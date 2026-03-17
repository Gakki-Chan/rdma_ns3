#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/pause-header.h"
#include "ns3/flow-id-tag.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "switch-node.h"
#include "qbb-net-device.h"
#include "ppp-header.h"
#include "ns3/int-header.h"
#include "ns3/simulator.h"
#include <cmath>
#include <sys/file.h>
#include <set>

namespace ns3 {

TypeId SwitchNode::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SwitchNode")
    .SetParent<Node> ()
    .AddConstructor<SwitchNode> ()
	.AddAttribute("EcnEnabled",
			"Enable ECN marking.",
			BooleanValue(false),
			MakeBooleanAccessor(&SwitchNode::m_ecnEnabled),
			MakeBooleanChecker())
	.AddAttribute("CcMode",
			"CC mode.",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ccMode),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("AckHighPrio",
			"Set high priority for ACK/NACK or not",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ackHighPrio),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("MaxRtt",
			"Max Rtt of the network",
			UintegerValue(9000),
			MakeUintegerAccessor(&SwitchNode::m_maxRtt),
			MakeUintegerChecker<uint32_t>())
  ;
  return tid;
}

SwitchNode::SwitchNode(){
	m_ecmpSeed = m_id;
	m_node_type = 1;
	m_mmu = CreateObject<SwitchMmu>();
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++)
			for (uint32_t k = 0; k < qCnt; k++)
				m_bytes[i][j][k] = 0;		// 从端口i去端口j，在队列k处等待的bytes
	for (uint32_t i = 0; i < pCnt; i++)
		m_txBytes[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_lastPktSize[i] = m_lastPktTs[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_u[i] = 0;
	
	//RDMA NPA init
	m_lastSignalEpoch = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < epochNum; j++)
			for (uint32_t k = 0; k < flowEntryNum; k++)
				m_flowTelemetryData[i][j][k].flowTuple = FiveTuple{0,0,0,0,0};
	for (uint32_t j = 0; j < epochNum; j++)
		for (uint32_t k = 0; k < pCnt; k++){
				m_portTelemetryData[j][k].enqQdepth = 0;
				m_portTelemetryData[j][k].pfcPausedPacketNum = 0;
				m_portTelemetryData[j][k].lastTimeStep = 0;
			}
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++){
			m_portToPortBytes[i][j] = 0;
			for(uint32_t k = 0; k < portToPortSlot; k++)
				m_portToPortBytesSlot[i][j][k] = 0;
		}
	for (uint32_t i = 0; i < pCnt; i++)
		m_lastPollingEpoch[i] = 0;
	for (uint32_t k = 0; k < flowEntryNum; k++)
		m_flowWeight[k] = 0;		
	m_nodeWeight.resize(20);
	for (uint32_t k = 0; k < 20; k++)
		m_nodeWeight[k] = 0;		
	
	m_slotIdx = 0;
	m_lastSignalEpoch = 0;
	
}

int SwitchNode::GetOutDev(Ptr<const Packet> p, CustomHeader &ch){	// 找到下一跳出口
	// look up entries
	auto entry = m_rtTable.find(ch.dip);	// 在路由表中，根据目的ip找到下一跳的出口vector

	// no matching entry
	if (entry == m_rtTable.end())		// 在路由表中，此目的ip没有对应的下一跳出口vector
		return -1;

	// entry found
	auto &nexthops = entry->second;		// 下一跳vector

	// pick one next hop based on hash 	基于hash找到下一跳
	union {	// union中各参数内存首地址相同
		uint8_t u8[4+4+2+2];		// [][][][] [][][][] [][][][]
		uint32_t u32[3];		// u32[2]   ch.dip   ch.sip
	} buf;
	buf.u32[0] = ch.sip;
	buf.u32[1] = ch.dip;
	if (ch.l3Prot == 0x6)
		buf.u32[2] = ch.tcp.sport | ((uint32_t)ch.tcp.dport << 16);
	else if (ch.l3Prot == 0x11)
		buf.u32[2] = ch.udp.sport | ((uint32_t)ch.udp.dport << 16);
	else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)
		buf.u32[2] = ch.ack.sport | ((uint32_t)ch.ack.dport << 16);

	uint32_t idx = EcmpHash(buf.u8, 12, m_ecmpSeed) % nexthops.size();	// 根据源和目的ip、port进行hash，找到vector中的一个数 
	return nexthops[idx];
}

int SwitchNode::GetOutDevToAnalysis(){
	auto entry = m_rtTable.find(m_analysis_addr.Get());
	
	if (entry == m_rtTable.end())		// 在路由表中，此目的ip没有对应的下一跳出口vector
		return -1;
		
	auto &nexthops = entry->second;
	/*
	uint32_t sport = 200, dport = 200;
	union {
		uint8_t u8[4+4+2+2];		// [][][][] [][][][] [][][][]
		uint32_t u32[3];		// u32[2]   ch.dip   ch.sip
	} buf;
	buf.u32[0] = GetObject<Ipv4>()->GetAddress(1, 0).GetLocal().Get();// sip
	buf.u32[1] = m_analysis_addr.Get();// dip
	buf.u32[2] = sport | (dport << 16);
	
	uint32_t idx = EcmpHash(buf.u8, 12, m_ecmpSeed) % nexthops.size();
	*/
	return nexthops[0];//TODO:error
}

void SwitchNode::CheckAndSendPfc(uint32_t inDev, uint32_t qIndex){ // 若需发送pause，就把向外发pause并把此队列设为pause。
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);	// 根据入口端口号，找到对应网卡
	if (m_mmu->CheckShouldPause(inDev, qIndex)){	// 若此队列需要Pause:
		device->SendPfc(qIndex, 0);			// 从此网卡的队列qIndex处向外广播，发送PFC Pause 包。0表示pause。
		m_mmu->SetPause(inDev, qIndex);			// 把此队列设置为pause状态。在src/point-to-point/model/switch-mmu.h文件中
	}
}
void SwitchNode::CheckAndSendResume(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldResume(inDev, qIndex)){	// 若此队列需要发pfc Resume包:
		device->SendPfc(qIndex, 1);
		m_mmu->SetResume(inDev, qIndex);		// 把此队列取消pause状态。
	}
}

void SwitchNode::SendSignalToAnalysis(){
	// Get idx
	int idx = GetOutDevToAnalysis();
	// Create and Send p to analysis server
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[idx]);// TODO
	device->SendAnalysis(0, 0, GetEpochIdx(), m_analysis_addr);
	
}

void SwitchNode::SendToDev(Ptr<Packet>p, CustomHeader &ch){ // 从接收队列中取出数据包并发送。根据数据包，更新下一跳端口的各类遥测数据和端口字节数据

	//RDMA NPA : signal packet parse 信号数据包解析.通常用于 通知 或 触发 拥塞、链路故障或某些事件,通知源设备降低发送速率等。
	if (ch.l3Prot == 0xFB){
		//ch.signal.pfcOff&&  == (m_analysis_addr.Get() >> 8) & 0xffff
		if(ch.signal.congestionPort != 0){
			UpdateFlowWeight();
			return;
		}
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();
		for (uint32_t idx = 0; idx < pCnt; idx++){
			if(m_portToPortBytes[inDev][idx] > rateThreshold ){ // 如果端inDev到端idx字节计数 > 速率阈值
				
				int fd_out = fileno(fp_telemetry);
				flock(fd_out, LOCK_EX);
				
				if(m_portTelemetryData[GetEpochIdx()][idx].pfcPausedPacketNum > 0){
					DynamicCast<QbbNetDevice>(m_devices[idx])-> SendSignal(0, 0, 0, 0, 0);
				}
				int epoch = GetEpochIdx();
				double timeInSeconds = Simulator::Now().GetSeconds();
				fprintf(fp_telemetry,"\n\nsignal\nepoch %d nowTime %fs\n", epoch, timeInSeconds);


				fprintf(fp_telemetry,"\n\nsignal\ntraffic meter form port %d to port %d\n", inDev, idx);
				fprintf(fp_telemetry, "portToPortBytes\n");
				fprintf(fp_telemetry, "%d\n", m_portToPortBytes[inDev][idx]);

				fprintf(fp_telemetry,"\n\nsignal\nport telemetry data for port %d\n", idx);
				fprintf(fp_telemetry, "enqQdepth pfcPausedPacketNum\n");
				fprintf(fp_telemetry, "%d ", m_portTelemetryData[epoch][idx].enqQdepth);
				fprintf(fp_telemetry, "%d\n", m_portTelemetryData[epoch][idx].pfcPausedPacketNum);

				fprintf(fp_telemetry,"\n\nsignal\nflow telemetry data for port %d\n", idx);
				//fprintf(fp_telemetry, "flowIdx srcIp dstIp srcPort dstPort protocol minSeq maxSeq packetFwdNum enqQdepth pfcPausedPacketNum\n");
				fprintf(fp_telemetry, "flowIdx srcIp dstIp srcPort dstPort protocol packetFwdNum totalFwdBytes enqQdepth pfcPausedPacketNum\n");
				for(uint32_t i = 0; i < flowEntryNum; i++){
					if(m_flowTelemetryData[idx][epoch][i].flowTuple.srcIp != 0){
						fprintf(fp_telemetry, "%d ", i);
						fprintf(fp_telemetry, "%08x ", m_flowTelemetryData[idx][epoch][i].flowTuple.srcIp);
						fprintf(fp_telemetry, "%08x ", m_flowTelemetryData[idx][epoch][i].flowTuple.dstIp);
						fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].flowTuple.srcPort);
						fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].flowTuple.dstPort);
						fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].flowTuple.protocol);
						//fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].minSeq);
						//fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].maxSeq);
						fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].packetFwdNum);
						fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].totalFwdBytes);
						fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].enqQdepth);
						fprintf(fp_telemetry, "%d\n", m_flowTelemetryData[idx][epoch][i].pfcPausedPacketNum);
						
						m_flowTelemetryData[idx][epoch][i].flowWeight = m_flowWeight[i];
						uint32_t tmpnid = (m_flowTelemetryData[idx][epoch][i].flowTuple.srcIp >> 8) & 0xffff;
						m_flowTelemetryData[idx][epoch][i].nodeWeight = m_nodeWeight[tmpnid];
						WriteFlowEntry(idx,epoch,i);
					}
				}
				fprintf(fp_telemetry, "0 0 0 0 0 0 0 0 0 0\n");
				
				fflush(fp_telemetry);
				flock(fd_out, LOCK_UN);
				
				SendSignalToAnalysis();// TODO:发Signal信号给分析器node
				
			}
		}
		return;	
	}
	//RDMA NPA : polling packet parse 轮询包分析。收到轮询数据包后，HW把交换机上的遥测数据轮询到分析器。主动查询状态或信息，周期性（按固定时间间隔）
	else if(ch.l3Prot == 0xFA){ // 如果是轮询包
		int fd_out = fileno(fp_telemetry);
		flock(fd_out, LOCK_EX);
	
		FlowIdTag t;
		p->PeekPacketTag(t);
		//uint32_t inDev = t.GetFlowId();
		int idx = GetOutDev(p, ch);	
		if(m_portTelemetryData[GetEpochIdx()][idx].pfcPausedPacketNum > 0){
			DynamicCast<QbbNetDevice>(m_devices[idx])-> SendSignal(0, 0, 0, 0, 0);
		}
		int epoch = GetEpochIdx();	// 当前时间窗口
		double timeInSeconds = Simulator::Now().GetSeconds();
		fprintf(fp_telemetry,"\n\npolling\nepoch %d nowTime %fs\n", epoch, timeInSeconds);
		
		fprintf(fp_telemetry,"\n\npolling\nflow telemetry data for port %d\n", idx);
		//fprintf(fp_telemetry, "flowIdx srcIp dstIp srcPort dstPort protocol minSeq maxSeq packetFwdNum enqQdepth pfcPausedPacketNum\n");
		fprintf(fp_telemetry, "flowIdx srcIp dstIp srcPort dstPort protocol packetFwdNum totalFwdBytes enqQdepth pfcPausedPacketNum\n");
		for(uint32_t i = 0; i < flowEntryNum; i++){	// 遍历流水平遥测数据的入口
			if(m_flowTelemetryData[idx][epoch][i].flowTuple.srcIp != 0){
				fprintf(fp_telemetry, "%d ", i);
				fprintf(fp_telemetry, "%08x ", m_flowTelemetryData[idx][epoch][i].flowTuple.srcIp);
				fprintf(fp_telemetry, "%08x ", m_flowTelemetryData[idx][epoch][i].flowTuple.dstIp);
				fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].flowTuple.srcPort);
				fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].flowTuple.dstPort);
				fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].flowTuple.protocol);
				//fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].minSeq);
				//fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].maxSeq);
				fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].packetFwdNum);
				fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].totalFwdBytes);
				fprintf(fp_telemetry, "%d ", m_flowTelemetryData[idx][epoch][i].enqQdepth);
				fprintf(fp_telemetry, "%d\n", m_flowTelemetryData[idx][epoch][i].pfcPausedPacketNum);
				
				m_flowTelemetryData[idx][epoch][i].flowWeight = m_flowWeight[i];
				uint32_t tmpnid = (m_flowTelemetryData[idx][epoch][i].flowTuple.srcIp >> 8) & 0xffff;
				m_flowTelemetryData[idx][epoch][i].nodeWeight = m_nodeWeight[tmpnid];
				WriteFlowEntry(idx,epoch,i);
			}
		}
		fprintf(fp_telemetry, "0 0 0 0 0 0 0 0 0 0\n");
		
		fflush(fp_telemetry);
		flock(fd_out, LOCK_UN);
		
		SendSignalToAnalysis();
	}

	int idx = GetOutDev(p, ch);	// 根据目的ip等，返回下一跳出口的端口号
	if (idx >= 0){
	
		NS_ASSERT_MSG(m_devices[idx]->IsLinkUp(), "The routing table look up should return link that is up");

		// determine the qIndex 算出队列优先级
		uint32_t qIndex;
		if (ch.l3Prot == 0xFA || ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0; // 0 为最高优先级
		}else{
			qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
		}

		// admission control 准入控制
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();
		if (qIndex != 0){ //not highest priority 不是最高优先级
			if (m_mmu->CheckIngressAdmission(inDev, qIndex, p->GetSize()) && m_mmu->CheckEgressAdmission(idx, qIndex, p->GetSize())){	// Admission control
				m_mmu->UpdateIngressAdmission(inDev, qIndex, p->GetSize());	// 更新入口准入字节状态
				m_mmu->UpdateEgressAdmission(idx, qIndex, p->GetSize());	// 更新出口准入字节状态
			}else{
				return; // Drop
			}
			CheckAndSendPfc(inDev, qIndex);	//检查是否需pause。是则反压上游，并把此队列设为pause。
		}
		
		
		// RDMA NPA: traffic meter 流量统计。收到RoCE包时才进入
		if (!(ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || ch.l3Prot == 0xFB || ch.l3Prot == 0xFA || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC)))){
		
			
			if((Simulator::Now().GetTimeStep() / (epoch / portToPortSlot)) % portToPortSlot != m_slotIdx){ // 判断当前时隙索引是否与分配的时隙索引匹配
				m_slotIdx = (Simulator::Now().GetTimeStep() / (epoch / portToPortSlot)) % portToPortSlot;
				for(uint32_t inDev = 0; inDev < pCnt; inDev++){ // 在时隙m_slotIdx结束时，更新端口到端口的字节计数
					for(uint32_t outDev = 0; outDev < pCnt; outDev++){
						m_portToPortBytes[inDev][outDev] -= m_portToPortBytesSlot[inDev][outDev][m_slotIdx]; // 从总字节数中减去当前时隙的字节数。
						m_portToPortBytesSlot[inDev][outDev][m_slotIdx] = 0; // 将当前时隙的字节数清零
					}
				}
			}
			m_portToPortBytesSlot[inDev][idx][m_slotIdx] += p->GetSize(); // 从入口到下一跳出口的当前时隙字节数 + packege size
			m_portToPortBytes[inDev][idx] += p->GetSize(); // 从入口到下一跳出口的总字节数 + packege size

			int oldidx = idx;
			FiveTuple fiveTuple;
			if(ch.l3Prot == 0xFD || ch.l3Prot == 0xFC){
				CustomHeader oldch;
				oldch.sip=ch.dip, oldch.dip=ch.sip; 
				oldch.udp.sport = ch.udp.dport, oldch.udp.dport = ch.udp.sport;
				oldch.l3Prot=0x11;
				oldidx = GetOutDev(p,oldch);
				fiveTuple.srcIp = oldch.sip, 
				fiveTuple.dstIp = oldch.dip,
				fiveTuple.srcPort = oldch.udp.sport, 
				fiveTuple.dstPort = oldch.udp.dport,
				fiveTuple.protocol = (uint8_t)oldch.l3Prot;
			} else {
				fiveTuple.srcIp = ch.sip,
				fiveTuple.dstIp = ch.dip,
				fiveTuple.srcPort = ch.l3Prot == 0x06 ? ch.tcp.sport : ch.udp.sport,
				fiveTuple.dstPort = ch.l3Prot == 0x06 ? ch.tcp.dport : ch.udp.dport,
				fiveTuple.protocol = (uint8_t)ch.l3Prot;
			}
			uint32_t epochIdx = GetEpochIdx();	
			uint32_t flowIdx = FiveTupleHash(fiveTuple);			
			auto &entry = m_flowTelemetryData[oldidx][epochIdx][flowIdx];	
			bool newEntry = Simulator::Now().GetTimeStep() - entry.lastTimeStep > epoch * (epochNum - 1); 
			if (entry.flowTuple == fiveTuple && !newEntry){ // 无需新建条目，更新旧条目即可
				uint32_t seq = ch.l3Prot == 0x06 ? ch.tcp.seq : ch.udp.seq; 
				if(seq < entry.minSeq){
					entry.minSeq = seq;
				}
				if(seq > entry.maxSeq){
					entry.maxSeq = seq;
				}	
				if(ch.l3Prot == 0xFC){ 
					entry.ackCount++;
					entry.totalBwdBytes += p->GetSize();
				}
				else if(ch.l3Prot == 0xFD){ 
					entry.nackCount++;
					entry.totalBwdBytes += p->GetSize();
				} else{
					entry.packetFwdNum++; 
					entry.totalFwdBytes += p->GetSize();
				}
				entry.enqQdepth += m_mmu->ingress_queue_length[inDev][qIndex] - 1;
				entry.flowWeight = m_flowWeight[flowIdx];
				entry.nodeWeight = m_nodeWeight[(fiveTuple.srcIp >> 8) & 0xffff];
				if(DynamicCast<QbbNetDevice>(m_devices[idx])->GetEgressPaused(qIndex)){
					m_flowTelemetryData[idx][epochIdx][flowIdx].pfcPausedPacketNum++;
					//uint32_t pnum=m_flowTelemetryData[idx][epochIdx][flowIdx].pfcPausedPacketNum;
						
				}/*
				if(Simulator::Now().GetTimeStep() - entry.lastTimeStep > 500000){
					WriteFlowEntry(oldidx,epochIdx,flowIdx);
				}*/
				entry.lastTimeStep = Simulator::Now().GetTimeStep();
			} else{ // 需要新建条目
				entry.flowWeight = m_flowWeight[flowIdx];
				entry.nodeWeight = m_nodeWeight[(fiveTuple.srcIp >> 8) & 0xffff];
				entry.endTimeSeconds = Simulator::Now().GetSeconds();
				WriteFlowEntry(oldidx,epochIdx,flowIdx);//记录流表条目
				entry.flowTuple = fiveTuple;
				entry.minSeq = entry.maxSeq = ch.l3Prot == 0x06 ? ch.tcp.seq : ch.udp.seq;
				entry.ackCount = entry.nackCount = 0;
				entry.packetFwdNum = 0;
				entry.totalFwdBytes = entry.totalBwdBytes = 0;
				if(ch.l3Prot == 0xFC){ 
					entry.ackCount = 1;
					entry.totalBwdBytes = p->GetSize();
				}
				else if(ch.l3Prot == 0xFD){ 
					entry.nackCount = 1;
					entry.totalBwdBytes = p->GetSize();
				}else{ 
					entry.packetFwdNum = 1;
					entry.totalFwdBytes = p->GetSize();
				}
				entry.enqQdepth = m_mmu->ingress_queue_length[inDev][qIndex] - 1;
				entry.pfcPausedPacketNum = 0;
				if(DynamicCast<QbbNetDevice>(m_devices[idx])->GetEgressPaused(qIndex)){ // if is pause
					m_flowTelemetryData[idx][epochIdx][flowIdx].pfcPausedPacketNum++;
				}
				entry.lastTimeStep = Simulator::Now().GetTimeStep();
				entry.flowWeight = m_flowWeight[flowIdx];
				entry.nodeWeight = m_nodeWeight[(fiveTuple.srcIp >> 8) & 0xffff];
				entry.startTimeSeconds = Simulator::Now().GetSeconds();
				entry.endTimeSeconds = 0;
			}

			auto &portEntry = m_portTelemetryData[epochIdx][idx]; // epochNum 表示当前窗口的编号
			bool newPortEntry = Simulator::Now().GetTimeStep() - portEntry.lastTimeStep > epoch * (epochNum - 1); // (当前时间 - 上一次更新时间)更大，则需创建新条目
			if (!newPortEntry){ // 无需新建条目
				portEntry.enqQdepth += m_mmu->ingress_queue_length[inDev][qIndex] - 1;
				if(DynamicCast<QbbNetDevice>(m_devices[idx])->GetEgressPaused(qIndex)){
					portEntry.pfcPausedPacketNum++;
				}
				portEntry.lastTimeStep = Simulator::Now().GetTimeStep();
			} else{ // 需要新建条目
				portEntry.enqQdepth = m_mmu->ingress_queue_length[inDev][qIndex] - 1;
				portEntry.pfcPausedPacketNum = 0;
				portEntry.lastTimeStep = Simulator::Now().GetTimeStep();
			}
		}

		m_bytes[inDev][idx][qIndex] += p->GetSize();
		//if(qIndex == 65535) printf("pg=65535 is here,SwitchNode::SendToDev\n");
		m_devices[idx]->SwitchSend(qIndex, p, ch);
	}else
		return; // Drop

}

void SwitchNode::UpdateFlowWeight(){
	FILE* fin = fopen("mix/find_root_cal.txt", "r");
	flock(fileno(fin), LOCK_SH | LOCK_NB);
	
	uint64_t ftime;
	uint32_t fid, nid, fwt;
	int tmpnw[20];
	for(uint32_t i = 0; i < 20; i++) 
		tmpnw[i]=0;
	
	fscanf(fin, "%lu\n", &ftime);
	if(ftime != m_lastUpdateWeight){
		m_lastUpdateWeight = ftime;
		while(fscanf(fin, "%u %u %u\n", &fid, &nid, &fwt) != EOF){
			m_flowWeight[fid] = fwt;
			nid = (nid >> 8) & 0xffff;
			tmpnw[nid] += fwt;
		}
		for(uint32_t i = 0; i < 20; i++)
			if(tmpnw[i] != 0)
				m_nodeWeight[i] = tmpnw[i];
	}

	
	flock(fileno(fin), LOCK_UN);
	fclose(fin);
	return;
}

std::string uint32_to_ipv4(uint32_t ip){
    	// 分解四个字节
    	uint8_t b1 = (ip >> 24) & 0xFF;
    	uint8_t b2 = (ip >> 16) & 0xFF;
    	uint8_t b3 = (ip >> 8)  & 0xFF;
    	uint8_t b4 =  ip        & 0xFF;
    	// 格式化为字符串
    	char buffer[16];
    	snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d", b1, b2, b3, b4);
    	return std::string(buffer);
}

void SwitchNode::WriteFlowEntry(uint32_t idx,uint32_t epoch,uint32_t flowid){
	if(m_flowTelemetryData[idx][epoch][flowid].flowTuple.srcIp == 0)
		return;
	m_flowTelemetryData[idx][epoch][flowid].durationSeconds = Simulator::Now().GetSeconds() - m_flowTelemetryData[idx][epoch][flowid].startTimeSeconds;
	/**/
	std::string sip = uint32_to_ipv4(m_flowTelemetryData[idx][epoch][flowid].flowTuple.srcIp);	
	//fprintf(fp_flowdata, "%d,", flowid);
	fprintf(fp_flowdata, "%s,", sip.c_str());
	//fprintf(fp_flowdata, "%s,", dip.c_str());
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].flowTuple.srcPort);
	//fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].flowTuple.dstPort);
	//fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].flowTuple.protocol);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].minSeq);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].maxSeq);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].ackCount);
	//fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].nackCount);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].packetFwdNum);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].totalFwdBytes);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].totalBwdBytes);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].enqQdepth);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].pfcPausedPacketNum);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].flowWeight);
	fprintf(fp_flowdata, "%d,", m_flowTelemetryData[idx][epoch][flowid].nodeWeight);
	//fprintf(fp_flowdata, "%f,", m_flowTelemetryData[idx][epoch][flowid].startTimeSeconds);
	fprintf(fp_flowdata, "%f\n", m_flowTelemetryData[idx][epoch][flowid].durationSeconds);
	
}



uint32_t SwitchNode::EcmpHash(const uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  if (len > 3) {
    const uint32_t* key_x4 = (const uint32_t*) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h += (h << 2) + 0xe6546b64;
    } while (--i);
    key = (const uint8_t*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

uint32_t SwitchNode::FiveTupleHash(const FiveTuple &fiveTuple){
	return EcmpHash((const uint8_t*)&fiveTuple, sizeof(fiveTuple), flowHashSeed) % flowEntryNum;
}

uint32_t SwitchNode::GetEpochIdx(){
	return Simulator::Now().GetTimeStep() / epoch % epochNum;
}

void SwitchNode::SetEcmpSeed(uint32_t seed){
	m_ecmpSeed = seed;
}

void SwitchNode::AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx){ // 在IP路由表的dstAddr.ip项中，加入一个值intf_idx
	uint32_t dip = dstAddr.Get();
	m_rtTable[dip].push_back(intf_idx); // 在IP路由表中dip对应的向量m_rtTable[dip]中加入intf_idx
}

void SwitchNode::ClearTable(){
	m_rtTable.clear();
}

// This function can only be called in switch mode
bool SwitchNode::SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch){ // 根据数据包，更新遥测数据和端口数据
	//if(ch.udp.pg==65535) printf("ch.udp.pg=65535 is here, SwitchNode::SwitchReceiveFromDevice\n");
	SendToDev(packet, ch); // 从队列中取出数据包并发送。根据数据包，更新下一跳端口的各类遥测数据和端口字节数据 
	return true;
}

void SwitchNode::SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){ // 通知交换机，数据包p已出队
	FlowIdTag t;
	p->PeekPacketTag(t);
	if (qIndex != 0){ // 非最高优先级
		uint32_t inDev = t.GetFlowId();
		m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());		// p从入口队列出队，并更新字节计数和队列状态。
		m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p->GetSize());	// p从出口队列出队，并更新字节计数和队列状态。
		m_bytes[inDev][ifIndex][qIndex] -= p->GetSize();
		if (m_ecnEnabled){							// ECN 是一种网络拥塞控制机制，标记拥塞而不是丢包
			bool egressCongested = m_mmu->ShouldSendCN(ifIndex, qIndex);		// 检查出口队列是否拥塞。
			if (egressCongested){							// 如果出口队列拥塞，就用ECN标记拥塞
				PppHeader ppp;
				Ipv4Header h;
				p->RemoveHeader(ppp);							// 从 p 中移除 Point-to-Point 头
				p->RemoveHeader(h);							// 从 p 中移除 IPv4 头
				h.SetEcn((Ipv4Header::EcnType)0x03);					// 设置 IPv4 头的 ECN 字段为 0x03，表示网络中存在拥塞。
				p->AddHeader(h);							// 将修改后的 IPv4 头重新添加到数据包
				p->AddHeader(ppp);							// 将 PPP 头重新添加到数据包
			}
		}
		//CheckAndSendPfc(inDev, qIndex);
		CheckAndSendResume(inDev, qIndex);					// 尝试取消暂停状态，并发送pfc Resume包。
	}
	if (1){
		uint8_t* buf = p->GetBuffer();
		if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
			IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
			Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
			if (m_ccMode == 3){ // HPCC
				ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes[ifIndex], dev->GetQueue()->GetNBytesTotal(), dev->GetDataRate().GetBitRate());
			}else if (m_ccMode == 10){ // HPCC-PINT
				uint64_t t = Simulator::Now().GetTimeStep();
				uint64_t dt = t - m_lastPktTs[ifIndex];
				if (dt > m_maxRtt)
					dt = m_maxRtt;
				uint64_t B = dev->GetDataRate().GetBitRate() / 8; //Bps
				uint64_t qlen = dev->GetQueue()->GetNBytesTotal();
				double newU;

				/**************************
				 * approximate calc
				 *************************/
				int b = 20, m = 16, l = 20; // see log2apprx's paremeters
				int sft = logres_shift(b,l);
				double fct = 1<<sft; // (multiplication factor corresponding to sft)
				double log_T = log2(m_maxRtt)*fct; // log2(T)*fct
				double log_B = log2(B)*fct; // log2(B)*fct
				double log_1e9 = log2(1e9)*fct; // log2(1e9)*fct
				double qterm = 0;
				double byteTerm = 0;
				double uTerm = 0;
				if ((qlen >> 8) > 0){
					int log_dt = log2apprx(dt, b, m, l); // ~log2(dt)*fct
					int log_qlen = log2apprx(qlen >> 8, b, m, l); // ~log2(qlen / 256)*fct
					qterm = pow(2, (
								log_dt + log_qlen + log_1e9 - log_B - 2*log_T
								) / fct
							) * 256;
					// 2^((log2(dt)*fct+log2(qlen/256)*fct+log2(1e9)*fct-log2(B)*fct-2*log2(T)*fct)/fct)*256 ~= dt*qlen*1e9/(B*T^2)
				}
				if (m_lastPktSize[ifIndex] > 0){
					int byte = m_lastPktSize[ifIndex];
					int log_byte = log2apprx(byte, b, m, l);
					byteTerm = pow(2, (
								log_byte + log_1e9 - log_B - log_T
								)/fct
							);
					// 2^((log2(byte)*fct+log2(1e9)*fct-log2(B)*fct-log2(T)*fct)/fct) ~= byte*1e9 / (B*T)
				}
				if (m_maxRtt > dt && m_u[ifIndex] > 0){
					int log_T_dt = log2apprx(m_maxRtt - dt, b, m, l); // ~log2(T-dt)*fct
					int log_u = log2apprx(int(round(m_u[ifIndex] * 8192)), b, m, l); // ~log2(u*512)*fct
					uTerm = pow(2, (
								log_T_dt + log_u - log_T
								)/fct
							) / 8192;
					// 2^((log2(T-dt)*fct+log2(u*512)*fct-log2(T)*fct)/fct)/512 = (T-dt)*u/T
				}
				newU = qterm+byteTerm+uTerm;

				#if 0
				/**************************
				 * accurate calc
				 *************************/
				double weight_ewma = double(dt) / m_maxRtt;
				double u;
				if (m_lastPktSize[ifIndex] == 0)
					u = 0;
				else{
					double txRate = m_lastPktSize[ifIndex] / double(dt); // B/ns
					u = (qlen / m_maxRtt + txRate) * 1e9 / B;
				}
				newU = m_u[ifIndex] * (1 - weight_ewma) + u * weight_ewma;
				printf(" %lf\n", newU);
				#endif

				/************************
				 * update PINT header
				 ***********************/
				uint16_t power = Pint::encode_u(newU);
				if (power > ih->GetPower())
					ih->SetPower(power);

				m_u[ifIndex] = newU;
			}
		}
	}
	m_txBytes[ifIndex] += p->GetSize();
	m_lastPktSize[ifIndex] = p->GetSize();
	m_lastPktTs[ifIndex] = Simulator::Now().GetTimeStep();
}

int SwitchNode::logres_shift(int b, int l){
	static int data[] = {0,0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5};
	return l - data[b];
}

int SwitchNode::log2apprx(int x, int b, int m, int l){
	int x0 = x;
	int msb = int(log2(x)) + 1;
	if (msb > m){
		x = (x >> (msb - m) << (msb - m));
		#if 0
		x += + (1 << (msb - m - 1));
		#else
		int mask = (1 << (msb-m)) - 1;
		if ((x0 & mask) > (rand() & mask))
			x += 1<<(msb-m);
		#endif
	}
	return int(log2(x) * (1<<logres_shift(b, l)));
}

} /* namespace ns3 */
