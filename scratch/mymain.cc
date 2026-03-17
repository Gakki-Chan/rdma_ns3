/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation;
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
]
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#undef PGO_TRAINING
#define PATH_TO_PGO_CONFIG "path_to_pgo_config"

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <set>
#include <time.h> 
#include "ns3/core-module.h"
#include "ns3/qbb-helper.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/packet.h"
#include "ns3/error-model.h"
#include <ns3/rdma.h>
#include <ns3/rdma-client.h>
#include <ns3/rdma-client-helper.h>
#include <ns3/rdma-driver.h>
#include <ns3/switch-node.h>
#include <ns3/sim-setting.h>

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("GENERIC_SIMULATION");

uint32_t cc_mode = 1;
bool enable_qcn = true, use_dynamic_pfc_threshold = true;
uint32_t packet_payload_size = 1000, l2_chunk_size = 0, l2_ack_interval = 0;
double pause_time = 5, simulator_stop_time = 3.01;
std::string data_rate, link_delay, topology_file, flow_file, attacker_file, trace_file, trace_output_file;
std::string fct_output_file = "fct.txt";
std::string pfc_output_file = "pfc.txt";

double alpha_resume_interval = 55, rp_timer, ewma_gain = 1 / 16;
double rate_decrease_interval = 4;
uint32_t fast_recovery_times = 5;
std::string rate_ai, rate_hai, min_rate = "100Mb/s";
std::string dctcp_rate_ai = "1000Mb/s";

bool clamp_target_rate = false, l2_back_to_zero = false;
double error_rate_per_link = 0.0;
uint32_t has_win = 1;
uint32_t global_t = 1;
uint32_t mi_thresh = 5;
bool var_win = false, fast_react = true;
bool multi_rate = true;
bool sample_feedback = false;
double pint_log_base = 1.05;
double pint_prob = 1.0;
double u_target = 0.95;
uint32_t int_multi = 1;
bool rate_bound = true;

uint32_t ack_high_prio = 0;
uint64_t link_down_time = 0;
uint32_t link_down_A = 0, link_down_B = 0;

uint32_t enable_trace = 1;

uint32_t buffer_size = 16;

uint32_t qlen_dump_interval = 100000000, qlen_mon_interval = 100;
uint64_t qlen_mon_start = 2000000000, qlen_mon_end = 2100000000;
string qlen_mon_file;

unordered_map<uint64_t, uint32_t> rate2kmax, rate2kmin;
unordered_map<uint64_t, double> rate2pmax;

set<int> agent_nodes;
set<int> no_cc_nodes;
set<int> attack_nodes;

uint32_t attacker_num, attacker_dst;
double attacker_start_time, attacker_duration, attacker_interval;

/************************************************
 * Runtime varibles
 ***********************************************/
std::ifstream topof, flowf, tracef,  attackerf;

NodeContainer n; // 在 network/helper/node-container.h 中

uint64_t nic_rate;

uint64_t maxRtt, maxBdp;

struct Interface{
	uint32_t idx;
	bool up;
	uint64_t delay;
	uint64_t bw;

	Interface() : idx(0), up(false){}
};
map<Ptr<Node>, map<Ptr<Node>, Interface> > nbr2if;
// Mapping destination to next hop for each node: <node, <dest, <nexthop0, ...> > >
map<Ptr<Node>, map<Ptr<Node>, vector<Ptr<Node> > > > nextHop;
map<Ptr<Node>, map<Ptr<Node>, uint64_t> > pairDelay;
map<Ptr<Node>, map<Ptr<Node>, uint64_t> > pairTxDelay;
map<uint32_t, map<uint32_t, uint64_t> > pairBw;
map<Ptr<Node>, map<Ptr<Node>, uint64_t> > pairBdp;
map<uint32_t, map<uint32_t, uint64_t> > pairRtt;

std::vector<Ipv4Address> serverAddress;
uint32_t analysis_node;

// maintain port number for each host pair
std::unordered_map<uint32_t, unordered_map<uint32_t, uint16_t> > portNumder;

struct FlowInput{
	uint32_t src, dst, pg, maxPacketCount, port, dport;
	double start_time;
	uint32_t idx;
};
FlowInput flow_input = {0};
uint32_t flow_num;


void ReadFlowInput(){   // 从文件中读取一行流信息
	if (flow_input.idx < flow_num){
		flowf >> flow_input.src >> flow_input.dst >> flow_input.pg >> flow_input.dport >> flow_input.maxPacketCount >> flow_input.start_time;
		NS_ASSERT(n.Get(flow_input.src)->GetNodeType() == 0 && n.Get(flow_input.dst)->GetNodeType() == 0);
		printf(" %d", flow_input.src);		
	}
}

void ScheduleFlowInputs(){ // 按计划读取流信息
	while (flow_input.idx < flow_num){
		uint32_t port = portNumder[flow_input.src][flow_input.dst]++; 
		RdmaClientHelper clientHelper(flow_input.pg, serverAddress[flow_input.src], serverAddress[flow_input.dst], port, flow_input.dport, flow_input.maxPacketCount, has_win?(global_t==1?maxBdp:pairBdp[n.Get(flow_input.src)][n.Get(flow_input.dst)]):0, global_t==1?maxRtt:pairRtt[flow_input.src][flow_input.dst]);
		clientHelper.SetAttribute("DataRate", StringValue("10Gbps"));
	        ApplicationContainer appCon = clientHelper.Install(n.Get(flow_input.src)); 
		appCon.Start(Seconds(flow_input.start_time)); // no stop time
                appCon.Stop(Seconds(simulator_stop_time - 0.001));
		flow_input.idx++;
		ReadFlowInput(); 
	}
	flowf.close();
	
}

void ReadAttackerInput(){
        attackerf >> attacker_start_time >> attacker_duration >> attacker_interval;
        int node;
        for(uint32_t i = 0; i < attacker_num; i++){
                attackerf >> node;
                printf(" %d", node);
                attack_nodes.insert(node);
                no_cc_nodes.insert(node); // attackers have no cc
        }
        attackerf.close();
}
void ScheduleAttackerInputs(){
        
        for(set<int>::iterator node = attack_nodes.begin(); node!= attack_nodes.end(); node++){
                double curr_start = attacker_start_time;
                double curr_stop = attacker_start_time + attacker_duration;
                while(curr_start < simulator_stop_time - 0.01){
                        uint32_t port = portNumder[*node][attacker_dst]++; // get a new port number 
	                RdmaClientHelper clientHelper(3, serverAddress[*node], serverAddress[attacker_dst], port, 4791, 1000000, has_win?(global_t==1?maxBdp:pairBdp[n.Get(*node)][n.Get(attacker_dst)]):0, global_t==1?maxRtt:pairRtt[*node][attacker_dst]);
	                ApplicationContainer appCon = clientHelper.Install(n.Get(*node)); 
	                
	                appCon.Start(Seconds(curr_start)); 
	                if(curr_stop < simulator_stop_time - 0.001)
                                appCon.Stop(Seconds(curr_stop));
                        else    
                                appCon.Stop(Seconds(simulator_stop_time - 0.001));
                        curr_start += attacker_interval;
                        curr_stop = curr_start + attacker_duration;
                }
	        
        }
        fflush(stdout);
}

Ipv4Address node_id_to_ip(uint32_t id){ // 把 node id 转换为对应的 ip 地址
	return Ipv4Address(0x0b000001 + ((id / 256) * 0x00010000) + ((id % 256) * 0x00000100));
}

uint32_t ip_to_node_id(Ipv4Address ip){ // 把 ip 地址转换为对应的 node id
	return (ip.Get() >> 8) & 0xffff;
}

void qp_finish(FILE* fout, Ptr<RdmaQueuePair> q){ // 处理 RDMA 队列对（Queue Pair, QP）的结束操作。
	uint32_t sid = ip_to_node_id(q->sip), did = ip_to_node_id(q->dip);      // 算出源 node id 和目的 node id
	uint64_t base_rtt = pairRtt[sid][did], b = pairBw[sid][did];            // 算出源节点和目的节点之间的基础 rtt 和带宽
	// q->m_size 是队列对中传输的数据大小；packet_payload_size 是每个数据包的有效载荷大小。
	uint32_t total_bytes = q->m_size + ((q->m_size-1) / packet_payload_size + 1) * (CustomHeader::GetStaticWholeHeaderSize() - IntHeader::GetStaticSize()); // translate to the minimum bytes required (with header but no INT)
	uint64_t standalone_fct = base_rtt + total_bytes * 8000000000lu / b;    // 独立流完成时间，表示在没有其他流干扰的情况下，完成数据传输所需的时间。常数用于将字节转换为纳秒
	fprintf(fout, "%08x %08x %u %u %lu %lu %lu %lu\n", q->sip.Get(), q->dip.Get(), q->sport, q->dport, q->m_size, q->startTime.GetTimeStep(), (Simulator::Now() - q->startTime).GetTimeStep(), standalone_fct);
	fflush(fout);

	// remove rxQp from the receiver 删除目标节点的接收队列
	Ptr<Node> dstNode = n.Get(did);
	Ptr<RdmaDriver> rdma = dstNode->GetObject<RdmaDriver> ();
	rdma->m_rdma->DeleteRxQp(q->sip.Get(), q->m_pg, q->sport);
}

void get_pfc(FILE* fout, Ptr<QbbNetDevice> dev, uint32_t type){ // 把pfc包的相关信息写入输出文件
	fprintf(fout, "%lu %u %u %u %u\n", Simulator::Now().GetTimeStep(), dev->GetNode()->GetId(), dev->GetNode()->GetNodeType(), dev->GetIfIndex(), type);
}

struct QlenDistribution{ // 用于统计队列长度的分布情况。它的作用是记录队列长度在不同范围内的出现次数，并以千字节（KB）为单位进行统计。
	vector<uint32_t> cnt; // cnt[i] = 队列长度为 i KB 的次数

	void add(uint32_t qlen){ // 更新队列长度的统计信息。qlen 是当前的队列长度，单位是字节（Byte）
		uint32_t kb = qlen / 1000; // 队列长度从byte转换为KB
		if (cnt.size() < kb+1)     // 如果动态数组大小不够，就增加索引，直到cnt[kb]存在
			cnt.resize(kb+1);
		cnt[kb]++;
	}
};
map<uint32_t, map<uint32_t, QlenDistribution> > queue_result; // 存储每个交换机和每个端口的队列长度分布。外层 map 的键是交换机 ID；内层 map的键是端口 ID
void monitor_buffer(FILE* qlen_output, NodeContainer *n){ // 监控交换机的缓冲区（队列）状态，并将队列长度的分布情况记录到文件中。它定期收集交换机端口的队列长度数据，并写入文件
	for (uint32_t i = 0; i < n->GetN(); i++){                       // 更新所有交换机的队列长度分布，保存在 queue_result 中
		if (n->Get(i)->GetNodeType() == 1){ // is switch
			Ptr<SwitchNode> sw = DynamicCast<SwitchNode>(n->Get(i)); // 将节点动态转换为 SwitchNode 类型，以便访问交换机的特定属性和方法。
			if (queue_result.find(i) == queue_result.end())          // 如果 queue_result 中还没有当前交换机的条目，则初始化一个。
				queue_result[i];
			for (uint32_t j = 1; j < sw->GetNDevices(); j++){        // 遍历交换机的所有端口（从 1 开始，因为 0 通常是控制端口）。
				uint32_t size = 0;                                      // 计算端口 j 的总队列长度（端口所有队列的长度相加）
				for (uint32_t k = 0; k < SwitchMmu::qCnt; k++)
					size += sw->m_mmu->egress_bytes[j][k];                  // 端口 j 的第 k 个队列的字节数。
				queue_result[i][j].add(size);                           // 更新端口 j 的队列长度分布
			}
		}
	}
	if (Simulator::Now().GetTimeStep() % qlen_dump_interval == 0){  // 检查是否到达写入时间点。当前仿真时间步长是 qlen_dump_interval 的倍数，则写入。
		fprintf(qlen_output, "time: %lu\n", Simulator::Now().GetTimeStep());
		for (auto &it0 : queue_result)                                  // 遍历 queue_result ，并写入文件 qlen.txt
			for (auto &it1 : it0.second){
				fprintf(qlen_output, "%u %u", it0.first, it1.first);
				auto &dist = it1.second.cnt;
				for (uint32_t i = 0; i < dist.size(); i++)              // 遍历队列长度分布 dist，并将每个分布值写入文件
					fprintf(qlen_output, " %u", dist[i]);
				fprintf(qlen_output, "\n");
			}
		fflush(qlen_output);                                            // 确保数据立即写入文件，而不是缓存在内存中。
	}
	if (Simulator::Now().GetTimeStep() < qlen_mon_end)              // 检查是否继续监控。当前仿真时间是否小于监控结束时间 
		Simulator::Schedule(NanoSeconds(qlen_mon_interval), &monitor_buffer, qlen_output, n); //  计划在 qlen_mon_interval 时间后再次调用此函数，实现定期监控。
}

void CalculateRoute(Ptr<Node> host){ // 基于广度优先搜索(BFS)的路由算法。从给定的host节点出发，计算到其他节点的最短路径，并记录路径的延迟、传输延迟和带宽等信息。路径记在nextHop中。
	// queue for the BFS.
	vector<Ptr<Node> > q;                   // 用于 BFS 的队列，存储待访问的节点。
	// Distance from the host to each node.
	map<Ptr<Node>, int> dis;                // 记录从 host 到每个节点的跳数（距离）
	map<Ptr<Node>, uint64_t> delay;         // 记录从 host 到每个节点的总延迟
	map<Ptr<Node>, uint64_t> txDelay;       // 记录从 host 到每个节点的总传输延迟
	map<Ptr<Node>, uint64_t> bw;            // 记录从 host 到每个节点的路径上的最小带宽
	// init BFS. 初始化 host 到自身的距离、延迟、传输延迟和带宽
	q.push_back(host);
	dis[host] = 0;
	delay[host] = 0;
	txDelay[host] = 0;
	bw[host] = 0xfffffffffffffffflu;        // 带宽设为最大值
	// BFS.
	for (int i = 0; i < (int)q.size(); i++){// 开始BFS计算
		Ptr<Node> now = q[i];
		int d = dis[now];                       // 从起点 host 到当前节点 i 的跳数，记为 d
		for (auto it = nbr2if[now].begin(); it != nbr2if[now].end(); it++){ // 遍历当前节点的邻居。映射nbr2if[now] ，存储当前节点的邻居节点及其对应的链路信息。
			// skip down link
			if (!it->second.up)                     // 跳过失效链路。
				continue;
			Ptr<Node> next = it->first;             // 这个邻居，暂时叫他 next
			// If 'next' have not been visited.
			if (dis.find(next) == dis.end()){       // 如果邻居节点 next 未被访问过，则更新其信息
				dis[next] = d + 1;                      // 更新 host 到 next 的跳数
				delay[next] = delay[now] + it->second.delay;
				txDelay[next] = txDelay[now] + packet_payload_size * 1000000000lu * 8 / it->second.bw;
				bw[next] = std::min(bw[now], it->second.bw);
				// we only enqueue switch, because we do not want packets to go through host as middle point
				if (next->GetNodeType() == 1)           // 如果邻居节点是交换机，则将其加入 BFS 队列。
					q.push_back(next);
			}
			// if 'now' is on the shortest path from 'next' to 'host'.
			if (d + 1 == dis[next]){                // 如果当前节点 now 在从 next 到 host 的最短路径上：
			        if(now->GetId()!=analysis_node || host->GetId()==analysis_node) // analysis不能作为中转节点
				        nextHop[next][host].push_back(now);     // 则将 now 记录为 next 到 host 的下一跳节点。
			}
		}
	}
	// 更新全局路由信息。将计算得到的延迟、传输延迟和带宽信息更新到全局数据结构中：
	for (auto it : delay)
		pairDelay[it.first][host] = it.second;
	for (auto it : txDelay)
		pairTxDelay[it.first][host] = it.second;
	for (auto it : bw)
		pairBw[it.first->GetId()][host->GetId()] = it.second;
}

void CalculateRoutes(NodeContainer &n){ // 用路由算法，计算所有节点到其他节点的最短路径。即，求全局的下一跳信息。
	for (int i = 0; i < (int)n.GetN(); i++){ // 遍历每个节点
		Ptr<Node> node = n.Get(i);
		if (node->GetNodeType() == 0)           // 若当前节点是主机：
			CalculateRoute(node);                   // 则计算从 node 到其他节点的最短路径。路径记在nextHop[nowNode][destNode]中。
	}
}

void SetRoutingEntries(){ // 设置路由表条目。根据全局的下一跳信息（nextHop），为每个节点配置到目标节点的路由表条目。
	// For each node. 遍历 nextHop 中的所有节点
	for (auto i = nextHop.begin(); i != nextHop.end(); i++){ 
		Ptr<Node> node = i->first;      // 当前节点叫 node。
		//if(node->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal() == serverAddress[analysis_node])  continue;  
		auto &table = i->second;        // table 是 node 的路由表，存储了从 node 到各个目标节点的下一跳信息。
		for (auto j = table.begin(); j != table.end(); j++){ // 遍历 table 中的所有目标节点。
			// The destination node.
			Ptr<Node> dst = j->first;               // 目标节点叫 dst
			// The IP address of the dst.
			Ipv4Address dstAddr = dst->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal(); // 获取第 1 个网络接口的第 0 个 IP 地址
			// The next hops towards the dst.
			vector<Ptr<Node> > nexts = j->second;   // 获取从 node 到 dst 的所有下一跳节点 nexts。
			for (int k = 0; k < (int)nexts.size(); k++){
				Ptr<Node> next = nexts[k];
				uint32_t interface = nbr2if[node][next].idx; // 获取下一跳的接口索引 interface 。获取 node 到 next 的链路对应的接口索引 interface。
				if (node->GetNodeType() == 1)                // 如果 node 是交换机：
					DynamicCast<SwitchNode>(node)->AddTableEntry(dstAddr, interface); // 将目标 IP 地址和下一跳接口索引，添加到交换机的路由表中
				else{                                    // 如果 node 是主机：
				        Ptr<RdmaDriver> p_rdmadriver = node->GetObject<RdmaDriver>();
					p_rdmadriver->m_rdma->AddTableEntry(dstAddr, interface); // 将目标 IP 地址和下一跳接口索引，添加到主机的路由表中
				}
			}
		}
	}
}

// take down the link between a and b, and redo the routing
void TakeDownLink(NodeContainer n, Ptr<Node> a, Ptr<Node> b){ // 模拟网络中两个节点之间的链路失效（例如链路断开或故障）
	if (!nbr2if[a][b].up)                           // 如果链路已经处于失效状态
		return;
	// take down link between a and b
	nbr2if[a][b].up = nbr2if[b][a].up = false;      // 将 a 到 b 和 b 到 a 的链路状态标记为失效
	nextHop.clear();                                // 清除下一跳信息
	CalculateRoutes(n);                             // 重新计算全局下一跳信息
	// clear routing tables
	for (uint32_t i = 0; i < n.GetN(); i++){        // 遍历所有节点，并清除路由表
		if (n.Get(i)->GetNodeType() == 1)
			DynamicCast<SwitchNode>(n.Get(i))->ClearTable();
		else
			n.Get(i)->GetObject<RdmaDriver>()->m_rdma->ClearTable();
	}
	DynamicCast<QbbNetDevice>(a->GetDevice(nbr2if[a][b].idx))->TakeDown(); // 通知设备 a 链路失效
	DynamicCast<QbbNetDevice>(b->GetDevice(nbr2if[b][a].idx))->TakeDown(); // 通知设备 b 链路失效
	// reset routing table
	SetRoutingEntries();                            // 根据新的路由信息，重新设置路由表。

	// redistribute qp on each host
	for (uint32_t i = 0; i < n.GetN(); i++){
		if (n.Get(i)->GetNodeType() == 0)       // 遍历所有主机节点
			n.Get(i)->GetObject<RdmaDriver>()->m_rdma->RedistributeQp(); // 重新分配队列对（QP），以适应新的网络拓扑------------------------------------
	}
}

uint64_t get_nic_rate(NodeContainer &n){
	for (uint32_t i = 0; i < n.GetN(); i++)
		if (n.Get(i)->GetNodeType() == 0)
			return DynamicCast<QbbNetDevice>(n.Get(i)->GetDevice(1))->GetDataRate().GetBitRate();
	return 0;
}

int main(int argc, char *argv[])
{
        
        CommandLine cmd(__FILE__);
        cmd.Parse(argc, argv);        
        
	clock_t begint, endt;
	begint = clock();
	if (argc > 1)
	{
		//Read the configuration file
		std::ifstream conf;
		conf.open(argv[1]);
		while (!conf.eof())
		{
			std::string key;
			conf >> key;

			//std::cout << conf.cur << "\n";

			if (key.compare("ENABLE_QCN") == 0)
			{
				uint32_t v;
				conf >> v;
				enable_qcn = v;
				if (enable_qcn)
					std::cout << "ENABLE_QCN\t\t\t" << "Yes" << "\n";
				else
					std::cout << "ENABLE_QCN\t\t\t" << "No" << "\n";
			}
			else if (key.compare("USE_DYNAMIC_PFC_THRESHOLD") == 0)
			{
				uint32_t v;
				conf >> v;
				use_dynamic_pfc_threshold = v;
				if (use_dynamic_pfc_threshold)
					std::cout << "USE_DYNAMIC_PFC_THRESHOLD\t" << "Yes" << "\n";
				else
					std::cout << "USE_DYNAMIC_PFC_THRESHOLD\t" << "No" << "\n";
			}
			else if (key.compare("CLAMP_TARGET_RATE") == 0)
			{
				uint32_t v;
				conf >> v;
				clamp_target_rate = v;
				if (clamp_target_rate)
					std::cout << "CLAMP_TARGET_RATE\t\t" << "Yes" << "\n";
				else
					std::cout << "CLAMP_TARGET_RATE\t\t" << "No" << "\n";
			}
			else if (key.compare("PAUSE_TIME") == 0)
			{
				double v;
				conf >> v;
				pause_time = v;
				std::cout << "PAUSE_TIME\t\t\t" << pause_time << "\n";
			}
			else if (key.compare("DATA_RATE") == 0)
			{
				std::string v;
				conf >> v;
				data_rate = v;
				std::cout << "DATA_RATE\t\t\t" << data_rate << "\n";
			}
			else if (key.compare("LINK_DELAY") == 0)
			{
				std::string v;
				conf >> v;
				link_delay = v;
				std::cout << "LINK_DELAY\t\t\t" << link_delay << "\n";
			}
			else if (key.compare("PACKET_PAYLOAD_SIZE") == 0)
			{
				uint32_t v;
				conf >> v;
				packet_payload_size = v;
				std::cout << "PACKET_PAYLOAD_SIZE\t\t" << packet_payload_size << "\n";
			}
			else if (key.compare("L2_CHUNK_SIZE") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_chunk_size = v;
				std::cout << "L2_CHUNK_SIZE\t\t\t" << l2_chunk_size << "\n";
			}
			else if (key.compare("L2_ACK_INTERVAL") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_ack_interval = v;
				std::cout << "L2_ACK_INTERVAL\t\t\t" << l2_ack_interval << "\n";
			}
			else if (key.compare("L2_BACK_TO_ZERO") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_back_to_zero = v;
				if (l2_back_to_zero)
					std::cout << "L2_BACK_TO_ZERO\t\t\t" << "Yes" << "\n";
				else
					std::cout << "L2_BACK_TO_ZERO\t\t\t" << "No" << "\n";
			}
			else if (key.compare("TOPOLOGY_FILE") == 0)
			{
				std::string v;
				conf >> v;
				topology_file = v;
				std::cout << "TOPOLOGY_FILE\t\t\t" << topology_file << "\n";
			}
			else if (key.compare("FLOW_FILE") == 0)
			{
				std::string v;
				conf >> v;
				flow_file = v;
				std::cout << "FLOW_FILE\t\t\t" << flow_file << "\n";
			}
			else if (key.compare("ATTACKER_FILE") == 0)
			{
				std::string v;
				conf >> v;
				attacker_file = v;
				std::cout << "ATTACKER_FILE\t\t\t" << attacker_file << "\n";
			}
			else if (key.compare("TRACE_FILE") == 0)
			{
				std::string v;
				conf >> v;
				trace_file = v;
				std::cout << "TRACE_FILE\t\t\t" << trace_file << "\n";
			}
			else if (key.compare("TRACE_OUTPUT_FILE") == 0)
			{
				std::string v;
				conf >> v;
				trace_output_file = v;
				if (argc > 2)
				{
					trace_output_file = trace_output_file + std::string(argv[2]);
				}
				std::cout << "TRACE_OUTPUT_FILE\t\t" << trace_output_file << "\n";
			}
			else if (key.compare("SIMULATOR_STOP_TIME") == 0)
			{
				double v;
				conf >> v;
				simulator_stop_time = v;
				std::cout << "SIMULATOR_STOP_TIME\t\t" << simulator_stop_time << "\n";
			}
			else if (key.compare("ALPHA_RESUME_INTERVAL") == 0)
			{
				double v;
				conf >> v;
				alpha_resume_interval = v;
				std::cout << "ALPHA_RESUME_INTERVAL\t\t" << alpha_resume_interval << "\n";
			}
			else if (key.compare("RP_TIMER") == 0)
			{
				double v;
				conf >> v;
				rp_timer = v;
				std::cout << "RP_TIMER\t\t\t" << rp_timer << "\n";
			}
			else if (key.compare("EWMA_GAIN") == 0)
			{
				double v;
				conf >> v;
				ewma_gain = v;
				std::cout << "EWMA_GAIN\t\t\t" << ewma_gain << "\n";
			}
			else if (key.compare("FAST_RECOVERY_TIMES") == 0)
			{
				uint32_t v;
				conf >> v;
				fast_recovery_times = v;
				std::cout << "FAST_RECOVERY_TIMES\t\t" << fast_recovery_times << "\n";
			}
			else if (key.compare("RATE_AI") == 0)
			{
				std::string v;
				conf >> v;
				rate_ai = v;
				std::cout << "RATE_AI\t\t\t\t" << rate_ai << "\n";
			}
			else if (key.compare("RATE_HAI") == 0)
			{
				std::string v;
				conf >> v;
				rate_hai = v;
				std::cout << "RATE_HAI\t\t\t" << rate_hai << "\n";
			}
			else if (key.compare("ERROR_RATE_PER_LINK") == 0)
			{
				double v;
				conf >> v;
				error_rate_per_link = v;
				std::cout << "ERROR_RATE_PER_LINK\t\t" << error_rate_per_link << "\n";
			}
			else if (key.compare("CC_MODE") == 0){
				conf >> cc_mode;
				std::cout << "CC_MODE\t\t\t\t" << cc_mode << '\n';
			}else if (key.compare("RATE_DECREASE_INTERVAL") == 0){
				double v;
				conf >> v;
				rate_decrease_interval = v;
				std::cout << "RATE_DECREASE_INTERVAL\t\t" << rate_decrease_interval << "\n";
			}else if (key.compare("MIN_RATE") == 0){
				conf >> min_rate;
				std::cout << "MIN_RATE\t\t\t" << min_rate << "\n";
			}else if (key.compare("FCT_OUTPUT_FILE") == 0){
				conf >> fct_output_file;
				std::cout << "FCT_OUTPUT_FILE\t\t\t" << fct_output_file << '\n';
			}else if (key.compare("HAS_WIN") == 0){
				conf >> has_win;
				std::cout << "HAS_WIN\t\t\t\t" << has_win << "\n";
			}else if (key.compare("GLOBAL_T") == 0){
				conf >> global_t;
				std::cout << "GLOBAL_T\t\t\t" << global_t << '\n';
			}else if (key.compare("MI_THRESH") == 0){
				conf >> mi_thresh;
				std::cout << "MI_THRESH\t\t\t" << mi_thresh << '\n';
			}else if (key.compare("VAR_WIN") == 0){
				uint32_t v;
				conf >> v;
				var_win = v;
				std::cout << "VAR_WIN\t\t\t\t" << v << '\n';
			}else if (key.compare("FAST_REACT") == 0){
				uint32_t v;
				conf >> v;
				fast_react = v;
				std::cout << "FAST_REACT\t\t\t" << v << '\n';
			}else if (key.compare("U_TARGET") == 0){
				conf >> u_target;
				std::cout << "U_TARGET\t\t\t" << u_target << '\n';
			}else if (key.compare("INT_MULTI") == 0){
				conf >> int_multi;
				std::cout << "INT_MULTI\t\t\t" << int_multi << '\n';
			}else if (key.compare("RATE_BOUND") == 0){
				uint32_t v;
				conf >> v;
				rate_bound = v;
				std::cout << "RATE_BOUND\t\t\t" << rate_bound << '\n';
			}else if (key.compare("ACK_HIGH_PRIO") == 0){
				conf >> ack_high_prio;
				std::cout << "ACK_HIGH_PRIO\t\t\t" << ack_high_prio << '\n';
			}else if (key.compare("DCTCP_RATE_AI") == 0){
				conf >> dctcp_rate_ai;
				std::cout << "DCTCP_RATE_AI\t\t\t" << dctcp_rate_ai << "\n";
			}else if (key.compare("PFC_OUTPUT_FILE") == 0){
				conf >> pfc_output_file;
				std::cout << "PFC_OUTPUT_FILE\t\t\t" << pfc_output_file << '\n';
			}else if (key.compare("LINK_DOWN") == 0){
				conf >> link_down_time >> link_down_A >> link_down_B;
				std::cout << "LINK_DOWN\t\t\t" << link_down_time << ' '<< link_down_A << ' ' << link_down_B << '\n';
			}else if (key.compare("ENABLE_TRACE") == 0){
				conf >> enable_trace;
				std::cout << "ENABLE_TRACE\t\t\t" << enable_trace << '\n';
			}else if (key.compare("KMAX_MAP") == 0){
				int n_k ;
				conf >> n_k;
				std::cout << "KMAX_MAP\t\t\t";
				for (int i = 0; i < n_k; i++){
					uint64_t rate;
					uint32_t k;
					conf >> rate >> k;
					rate2kmax[rate] = k;
					std::cout << ' ' << rate << ' ' << k;
				}
				std::cout<<'\n';
			}else if (key.compare("KMIN_MAP") == 0){
				int n_k ;
				conf >> n_k;
				std::cout << "KMIN_MAP\t\t\t";
				for (int i = 0; i < n_k; i++){
					uint64_t rate;
					uint32_t k;
					conf >> rate >> k;
					rate2kmin[rate] = k;
					std::cout << ' ' << rate << ' ' << k;
				}
				std::cout<<'\n';
			}else if (key.compare("PMAX_MAP") == 0){
				int n_k ;
				conf >> n_k;
				std::cout << "PMAX_MAP\t\t\t";
				for (int i = 0; i < n_k; i++){
					uint64_t rate;
					double p;
					conf >> rate >> p;
					rate2pmax[rate] = p;
					std::cout << ' ' << rate << ' ' << p;
				}
				std::cout<<'\n';
			}else if (key.compare("BUFFER_SIZE") == 0){
				conf >> buffer_size;
				std::cout << "BUFFER_SIZE\t\t\t" << buffer_size << '\n';
			}else if (key.compare("QLEN_MON_FILE") == 0){
				conf >> qlen_mon_file;
				std::cout << "QLEN_MON_FILE\t\t\t" << qlen_mon_file << '\n';
			}else if (key.compare("QLEN_MON_START") == 0){
				conf >> qlen_mon_start;
				std::cout << "QLEN_MON_START\t\t\t" << qlen_mon_start << '\n';
			}else if (key.compare("QLEN_MON_END") == 0){
				conf >> qlen_mon_end;
				std::cout << "QLEN_MON_END\t\t\t" << qlen_mon_end << '\n';
			}else if (key.compare("MULTI_RATE") == 0){
				int v;
				conf >> v;
				multi_rate = v;
				std::cout << "MULTI_RATE\t\t\t" << multi_rate << '\n';
			}else if (key.compare("SAMPLE_FEEDBACK") == 0){
				int v;
				conf >> v;
				sample_feedback = v;
				std::cout << "SAMPLE_FEEDBACK\t\t\t" << sample_feedback << '\n';
			}else if(key.compare("PINT_LOG_BASE") == 0){
				conf >> pint_log_base;
				std::cout << "PINT_LOG_BASE\t\t\t" << pint_log_base << '\n';
			}else if (key.compare("PINT_PROB") == 0){
				conf >> pint_prob;
				std::cout << "PINT_PROB\t\t\t" << pint_prob << '\n';
			}else if (key.compare("AGENT_NODE") == 0){
				int n_k ;
				conf >> n_k;
				std::cout << "AGENT_NODE\t\t\t";
				for (int i = 0; i < n_k; i++){
					int node;
					conf >> node;
					agent_nodes.insert(node);
					std::cout << ' ' << node;
				}
				std::cout<<'\n';
			}else if (key.compare("NO_CC_NODE") == 0){
				int n_k ;
				conf >> n_k;
				std::cout << "NO_CC_NODE\t\t\t";
				for (int i = 0; i < n_k; i++){
					int node;
					conf >> node;
					no_cc_nodes.insert(node);
					std::cout << ' ' << node;
				}
				std::cout<<'\n';
			}
			fflush(stdout); // // 确保数据立即写入stdout，而不是缓存在内存中。
		}
		conf.close();
	}
	else
	{
		std::cout << "Error: require a config file\n";
		fflush(stdout); // // 确保数据立即写入stdout，而不是缓存在内存中。
		return 1;
	}


	bool dynamicth = use_dynamic_pfc_threshold;

	Config::SetDefault("ns3::QbbNetDevice::PauseTime", UintegerValue(pause_time));
	Config::SetDefault("ns3::QbbNetDevice::QcnEnabled", BooleanValue(enable_qcn));
	Config::SetDefault("ns3::QbbNetDevice::DynamicThreshold", BooleanValue(dynamicth));

	// set int_multi
	IntHop::multi = int_multi;
	// IntHeader::mode
	if (cc_mode == 7) // timely, use ts
		IntHeader::mode = IntHeader::TS;
	else if (cc_mode == 3) // hpcc, use int
		IntHeader::mode = IntHeader::NORMAL;
	else if (cc_mode == 10) // hpcc-pint
		IntHeader::mode = IntHeader::PINT;
	else // others, no extra header
		// IntHeader::mode = IntHeader::NONE;
		IntHeader::mode = IntHeader::TS;//RDMA NPA

	// Set Pint,PINT可能是一个带内网络遥测框架，允许每个数据包的信息量开销限低至1位，在P4中实现
	if (cc_mode == 10){
		Pint::set_log_base(pint_log_base);
		IntHeader::pint_bytes = Pint::get_n_bytes();
		printf("PINT bits: %d bytes: %d\n", Pint::get_n_bits(), Pint::get_n_bytes());
	}

	//SeedManager::SetSeed(time(NULL));

	topof.open(topology_file.c_str());
	flowf.open(flow_file.c_str());
	tracef.open(trace_file.c_str());
	attackerf.open(attacker_file.c_str());
	uint32_t node_num, switch_num, link_num, trace_num;
	topof >> node_num >> switch_num >> link_num;
	flowf >> flow_num;
	tracef >> trace_num;
	attackerf >> attacker_num >> attacker_dst;


	//n.Create(node_num);
	node_num++; // TODO:+1表示额外的分析服务器，类型是Node
	analysis_node = node_num-1;
	std::vector<uint32_t> node_type(node_num, 0); 
	for (uint32_t i = 0; i < switch_num; i++)
	{
		uint32_t sid;
		topof >> sid;
		node_type[sid] = 1;
	}
	for (uint32_t i = 0; i < node_num; i++){ 
		if (node_type[i] == 0)
			n.Add(CreateObject<Node>()); // 函数在 network/helper/node-container.h 中
		else{
			Ptr<SwitchNode> sw = CreateObject<SwitchNode>();
			n.Add(sw);
			sw->SetAttribute("EcnEnabled", BooleanValue(enable_qcn));
		}
	}


	NS_LOG_INFO("Create nodes.");
        // 安装协议栈
	InternetStackHelper internet;
	internet.Install(n);

	//
	// Assign IP to each server
	//
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() == 0){ // is server
			serverAddress.resize(i + 1);
			serverAddress[i] = node_id_to_ip(i);
		}
	}

	NS_LOG_INFO("Create channels.");

	//
	// Explicitly create the channels required by the topology.
	//

	Ptr<RateErrorModel> rem = CreateObject<RateErrorModel>();
	Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
	rem->SetRandomVariable(uv);
	uv->SetStream(50);
	rem->SetAttribute("ErrorRate", DoubleValue(error_rate_per_link));
	rem->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));

	FILE *pfc_file = fopen(pfc_output_file.c_str(), "w");

	QbbHelper qbb;          // 用于创建和管理 QbbNetDevice 和 QbbChannel 的帮助类。
	Ipv4AddressHelper ipv4; // 用于分配和管理 IPv4 地址。
	for (uint32_t i = 0; i < link_num; i++) // 读取topo文件中链路信息，为每对节点创建网络设备（QbbNetDevice）和信道（QbbChannel），并设置相关的链路
	{
		uint32_t src, dst;
		std::string data_rate, link_delay;
		double error_rate;
		topof >> src >> dst >> data_rate >> link_delay >> error_rate;

		Ptr<Node> snode = n.Get(src), dnode = n.Get(dst);               // 根据节点索引 src 和 dst，从节点容器 n 中获取源节点 snode 和目标节点 dnode。

		qbb.SetDeviceAttribute("DataRate", StringValue(data_rate));     // 设置链路的数据速率。
		qbb.SetChannelAttribute("Delay", StringValue(link_delay));      // 设置链路的延迟。

		if (error_rate > 0) // 如果错误率 error_rate 大于 0，则创建一个错误模型，并将其附加到网络设备上
		{
			Ptr<RateErrorModel> rem = CreateObject<RateErrorModel>();       // 错误模型，用于模拟链路中的随机丢包。
			Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
			rem->SetRandomVariable(uv);
			uv->SetStream(50);
			rem->SetAttribute("ErrorRate", DoubleValue(error_rate));
			rem->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
			qbb.SetDeviceAttribute("ReceiveErrorModel", PointerValue(rem)); // 将错误模型附加到网络设备上
		}
		else
		{
			qbb.SetDeviceAttribute("ReceiveErrorModel", PointerValue(rem)); // 将错误模型附加到网络设备上
		}
		
		fflush(stdout); // 确保数据立即写入stdout，而不是缓存在内存中。

		// Assigne server IP
		// Note: this should be before the automatic assignment below (ipv4.Assign(d)),
		// because we want our IP to be the primary IP (first in the IP address list),
		// so that the global routing is based on our IP
		NetDeviceContainer d = qbb.Install(snode, dnode);               // 在 snode 和 dnode 之间安装网络设备和信道，并返回设备容器 d
		if (snode->GetNodeType() == 0){                                 // 如果源节点是 host，则为其分配预定义的 IP 地址。
			Ptr<Ipv4> ipv4 = snode->GetObject<Ipv4>();
			uint32_t in = ipv4->AddInterface(d.Get(0));                           // 在ipv4-l3-click-protocol.cc中
			ipv4->AddAddress(in, Ipv4InterfaceAddress(serverAddress[src], Ipv4Mask(0xff000000))); // 原来参数是 1 而非 in
		} // 确保手动分配的IP成为接口的主IP地址（即IP地址列表中的第一个），不会被自动分配的IP覆盖（ipv4.Assign()）
		if (dnode->GetNodeType() == 0){                                 // 如果目的节点是 host，则为其分配预定义的 IP 地址。
			Ptr<Ipv4> ipv4 = dnode->GetObject<Ipv4>();
			uint32_t in = ipv4->AddInterface(d.Get(1));
			ipv4->AddAddress(in, Ipv4InterfaceAddress(serverAddress[dst], Ipv4Mask(0xff000000))); // 原来参数是 1 而非 in
		}

		// used to create a graph of the topology 将链路的索引、状态、延迟和带宽等信息记录到 nbr2if 中。
		nbr2if[snode][dnode].idx = DynamicCast<QbbNetDevice>(d.Get(0))->GetIfIndex();
		nbr2if[snode][dnode].up = true;
		nbr2if[snode][dnode].delay = DynamicCast<QbbChannel>(DynamicCast<QbbNetDevice>(d.Get(0))->GetChannel())->GetDelay().GetTimeStep();
		nbr2if[snode][dnode].bw = DynamicCast<QbbNetDevice>(d.Get(0))->GetDataRate().GetBitRate();
		nbr2if[dnode][snode].idx = DynamicCast<QbbNetDevice>(d.Get(1))->GetIfIndex();
		nbr2if[dnode][snode].up = true;
		nbr2if[dnode][snode].delay = DynamicCast<QbbChannel>(DynamicCast<QbbNetDevice>(d.Get(1))->GetChannel())->GetDelay().GetTimeStep();
		nbr2if[dnode][snode].bw = DynamicCast<QbbNetDevice>(d.Get(1))->GetDataRate().GetBitRate();

		// This is just to set up the connectivity between nodes. The IP addresses are useless 为链路分配临时的 IP 地址，用于建立节点之间的连通性。
		char ipstring[16];
		sprintf(ipstring, "10.%d.%d.0", i / 254 + 1, i % 254 + 1);
		ipv4.SetBase(ipstring, "255.255.255.0");
		ipv4.Assign(d);

		// setup PFC trace 为每个网络设备设置 PFC 跟踪，用于记录 PFC 事件到文件中
		DynamicCast<QbbNetDevice>(d.Get(0))->TraceConnectWithoutContext("QbbPfc", MakeBoundCallback (&get_pfc, pfc_file, DynamicCast<QbbNetDevice>(d.Get(0)))); // pfc.txt
		DynamicCast<QbbNetDevice>(d.Get(1))->TraceConnectWithoutContext("QbbPfc", MakeBoundCallback (&get_pfc, pfc_file, DynamicCast<QbbNetDevice>(d.Get(1)))); // pfc.txt
	}
	
	// TODO:在所有交换机和分析服务器n[analysis_node]间，建立链路
	Ipv4InterfaceContainer interfaces;
	for (uint32_t i = 0; i < node_num; i++){
                Ptr<Node> snode = n.Get(i), dnode = n.Get(analysis_node);
	        if (snode->GetNodeType() == 1){ // 如果是switch，就为它和分析器建立链路
	                uint32_t src = i, dst = analysis_node;
                        // 设置点到点链路 
		        qbb.SetDeviceAttribute("DataRate", StringValue("100Gbps"));    
		        qbb.SetChannelAttribute("Delay", StringValue("0.001ms"));     
		        
		        fflush(stdout);
		        
                        // 安装网络设备
		        NetDeviceContainer d = qbb.Install(snode, dnode);
		        if (snode->GetNodeType() == 0){                                 
			        Ptr<Ipv4> ipv4 = snode->GetObject<Ipv4>();
			        uint32_t in = ipv4->AddInterface(d.Get(0));                           
			        ipv4->AddAddress(in, Ipv4InterfaceAddress(serverAddress[src], Ipv4Mask(0xff000000)));
		        }if (dnode->GetNodeType() == 0){                                 
			        Ptr<Ipv4> ipv4 = dnode->GetObject<Ipv4>();
			        uint32_t in = ipv4->AddInterface(d.Get(1));
			        ipv4->AddAddress(in, Ipv4InterfaceAddress(serverAddress[dst], Ipv4Mask(0xff000000)));
		        }
		        // used to create a graph of the topology
		        nbr2if[snode][dnode].idx = DynamicCast<QbbNetDevice>(d.Get(0))->GetIfIndex();
		        nbr2if[snode][dnode].up = true;
		        nbr2if[snode][dnode].delay = DynamicCast<QbbChannel>(DynamicCast<QbbNetDevice>(d.Get(0))->GetChannel())->GetDelay().GetTimeStep();
		        nbr2if[snode][dnode].bw = DynamicCast<QbbNetDevice>(d.Get(0))->GetDataRate().GetBitRate();
		        nbr2if[dnode][snode].idx = DynamicCast<QbbNetDevice>(d.Get(1))->GetIfIndex();
		        nbr2if[dnode][snode].up = true;
		        nbr2if[dnode][snode].delay = DynamicCast<QbbChannel>(DynamicCast<QbbNetDevice>(d.Get(1))->GetChannel())->GetDelay().GetTimeStep();
		        nbr2if[dnode][snode].bw = DynamicCast<QbbNetDevice>(d.Get(1))->GetDataRate().GetBitRate();
		
		        // 分配 IPv4 地址，用于建立节点之间的连通性。
		        char ipstring[16];
		        sprintf(ipstring, "10.%d.%d.0", (i+link_num) / 254 + 1, (i+link_num) % 254 + 1);
		        ipv4.SetBase(ipstring, "255.255.255.0");
		        interfaces = ipv4.Assign(d);
		        
	        }
	}
	
	nic_rate = get_nic_rate(n);

	// config switch
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() == 1){ // is switch
			Ptr<SwitchNode> sw = DynamicCast<SwitchNode>(n.Get(i));
			sw->m_analysis_addr = serverAddress[analysis_node];// TODO
			uint32_t shift = 3; // by default 1/8
			for (uint32_t j = 1; j < sw->GetNDevices(); j++){
			        Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(sw->GetDevice(j));
			        if(dev == nullptr) continue; // 如果是p2p，就跳过
				// set ecn
				uint64_t rate = dev->GetDataRate().GetBitRate();
				NS_ASSERT_MSG(rate2kmin.find(rate) != rate2kmin.end(), "must set kmin for each link speed"); // 若没设kmin，则输出并终止
				NS_ASSERT_MSG(rate2kmax.find(rate) != rate2kmax.end(), "must set kmax for each link speed");
				NS_ASSERT_MSG(rate2pmax.find(rate) != rate2pmax.end(), "must set pmax for each link speed");
				sw->m_mmu->ConfigEcn(j, rate2kmin[rate], rate2kmax[rate], rate2pmax[rate]);
				// set pfc
				uint64_t delay = DynamicCast<QbbChannel>(dev->GetChannel())->GetDelay().GetTimeStep();
				uint32_t headroom = rate * delay / 8 / 1000000000 * 3;
				sw->m_mmu->ConfigHdrm(j, headroom);

				// set pfc alpha, proportional to link bw
				sw->m_mmu->pfc_a_shift[j] = shift;
				while (rate > nic_rate && sw->m_mmu->pfc_a_shift[j] > 0){
					sw->m_mmu->pfc_a_shift[j]--;
					rate /= 2;
				}
			}
			sw->m_mmu->ConfigNPort(sw->GetNDevices()-1);
			sw->m_mmu->ConfigBufferSize(buffer_size * 1024);
			sw->m_mmu->node_id = sw->GetId();

			//RDMA NPA detect temp
			char telemetry_path[100];
			sprintf(telemetry_path, "mix/telemetry_%d.txt", i);     
			sw->fp_telemetry = fopen(telemetry_path, "w");
			/**/
			char flowdata_path[100];
			sprintf(flowdata_path, "mix/teleflowdata_%d.txt", i);     
			sw->fp_flowdata = fopen(flowdata_path, "w");
			
			//sw->SetAttribute("AckHighPrio",UintegerValue(1));
                        
		}
	}

	#if ENABLE_QP
	FILE *fct_output = fopen(fct_output_file.c_str(), "w");
	//
	// install RDMA driver
	//
	for (uint32_t i = 0; i < node_num; i++){
		// TODO:若节点dst是attacker，那么设置dst不进行拥塞控制
		if (n.Get(i)->GetNodeType() == 0){ // is host, not switch
			// create RdmaHw
			Ptr<RdmaHw> rdmaHw = CreateObject<RdmaHw>();
			rdmaHw->SetAttribute("ClampTargetRate", BooleanValue(clamp_target_rate));
			rdmaHw->SetAttribute("AlphaResumInterval", DoubleValue(alpha_resume_interval));
			rdmaHw->SetAttribute("RPTimer", DoubleValue(rp_timer));
			rdmaHw->SetAttribute("FastRecoveryTimes", UintegerValue(fast_recovery_times));
			rdmaHw->SetAttribute("EwmaGain", DoubleValue(ewma_gain));
			rdmaHw->SetAttribute("RateAI", DataRateValue(DataRate(rate_ai)));
			rdmaHw->SetAttribute("RateHAI", DataRateValue(DataRate(rate_hai)));
			rdmaHw->SetAttribute("L2BackToZero", BooleanValue(l2_back_to_zero));
			rdmaHw->SetAttribute("L2ChunkSize", UintegerValue(l2_chunk_size));
			rdmaHw->SetAttribute("L2AckInterval", UintegerValue(l2_ack_interval));
			rdmaHw->SetAttribute("CcMode", UintegerValue(cc_mode));
			rdmaHw->SetAttribute("RateDecreaseInterval", DoubleValue(rate_decrease_interval));
			rdmaHw->SetAttribute("MinRate", DataRateValue(DataRate(min_rate)));
			rdmaHw->SetAttribute("Mtu", UintegerValue(packet_payload_size));
			rdmaHw->SetAttribute("MiThresh", UintegerValue(mi_thresh));
			rdmaHw->SetAttribute("VarWin", BooleanValue(var_win));
			rdmaHw->SetAttribute("FastReact", BooleanValue(fast_react));
			rdmaHw->SetAttribute("MultiRate", BooleanValue(multi_rate));
			rdmaHw->SetAttribute("SampleFeedback", BooleanValue(sample_feedback));
			rdmaHw->SetAttribute("TargetUtil", DoubleValue(u_target));
			rdmaHw->SetAttribute("RateBound", BooleanValue(rate_bound));
			rdmaHw->SetAttribute("DctcpRateAI", DataRateValue(DataRate(dctcp_rate_ai)));
			rdmaHw->SetPintSmplThresh(pint_prob);
			
			char monitor_path[100];
			sprintf(monitor_path, "mixmonitor/agent_%d.txt", i);
			rdmaHw->fp_flow_monitor = fopen(monitor_path, "w");
                        
			// RDMA NPA
			if(agent_nodes.find(i) != agent_nodes.end()) {
				rdmaHw->m_agent_flag = true;
			}else 
				rdmaHw->m_agent_flag = false;
			/* Is Attacker */
			if(false/*i==5 || i==6 || i==7 || i==8*/)
			        rdmaHw->SetAttribute("Mtu", UintegerValue(500));
			if(/*i==1 || i==2 || i==5*/false) {//输出记录流速数据的文件
			        rdmaHw->m_monitor_flag = true;
			}	                                      
			// Set analysis node. 
			if(i == analysis_node){
			        rdmaHw->m_analysis_flag = true;
			        rdmaHw->nextHop = &nextHop;
			        rdmaHw->calfout_path = "mix/find_root_cal.txt";
			}else{
			        rdmaHw->m_analysis_flag = false;
			}
			if(no_cc_nodes.find(i) != no_cc_nodes.end())
				rdmaHw->SetAttribute("CcMode", UintegerValue(0));
			// create and install RdmaDriver
			Ptr<RdmaDriver> rdma = CreateObject<RdmaDriver>();
			Ptr<Node> node = n.Get(i);      
			rdma->SetNode(node);            // 把节点 node[i] 安装到RDMA驱动中
			rdma->SetRdmaHw(rdmaHw);        // 把   rdmaHw 网卡安装到RDMA驱动中
			node->AggregateObject (rdma);   // 函数在 core/model/object.h 中，将rdma驱动构件（各种协议）聚合到节点 node[i] 中
			rdma->Init();                   // 函数在 point-to-point/model/rdma-driver.h 中，根据已安装的 rdmaHw 网卡进行初始化
			rdma->TraceConnectWithoutContext("QpComplete", MakeBoundCallback (qp_finish, fct_output)); // 追踪绑定参数的回调qp_finish，但是不携带上下文信息；fct.txt
			// qp_finish 函数处理 RDMA 队列对（Queue Pair, QP）的结束操作。
			fflush(stdout);
		}
	}
	#endif

	// set ACK priority on hosts
	if (ack_high_prio)
		RdmaEgressQueue::ack_q_idx = 0;
	else
		RdmaEgressQueue::ack_q_idx = 3;

	// setup routing
	CalculateRoutes(n);     // 计算全局下一跳信息
	SetRoutingEntries();    // 根据下一跳信息，计算路由表条目

	//
	// get BDP and delay
	//
	maxRtt = maxBdp = 0;
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() != 0)
			continue;
		for (uint32_t j = 0; j < node_num; j++){
			if (n.Get(j)->GetNodeType() != 0)
				continue;
			uint64_t delay = pairDelay[n.Get(i)][n.Get(j)];
			uint64_t txDelay = pairTxDelay[n.Get(i)][n.Get(j)];
			uint64_t rtt = delay * 2 + txDelay;
			uint64_t bw = pairBw[i][j];
			uint64_t bdp = rtt * bw / 1000000000/8; 
			pairBdp[n.Get(i)][n.Get(j)] = bdp;
			pairRtt[i][j] = rtt;
			if (bdp > maxBdp)
				maxBdp = bdp;
			if (rtt > maxRtt)
				maxRtt = rtt;
		}
	}
	printf("maxRtt=%lu maxBdp=%lu\n", maxRtt, maxBdp);

	//
	// setup switch CC
	//
	for (uint32_t i = 0; i < node_num; i++){
		if (n.Get(i)->GetNodeType() == 1){ // switch
			Ptr<SwitchNode> sw = DynamicCast<SwitchNode>(n.Get(i));
			sw->SetAttribute("CcMode", UintegerValue(cc_mode)); // 为交换机设置拥塞控制模式
			sw->SetAttribute("MaxRtt", UintegerValue(maxRtt));
		}
	}

	//
	// add trace
	//

	NodeContainer trace_nodes; // 函数在  network/helper/node-container.h 中
	for (uint32_t i = 0; i < trace_num; i++)
	{
		uint32_t nid;
		tracef >> nid;
		if (nid >= n.GetN()){
			continue;
		}
		trace_nodes = NodeContainer(trace_nodes, n.Get(nid));
	}

	FILE *trace_output = fopen(trace_output_file.c_str(), "w");
	if (enable_trace){
		//qbb.EnableTracing(trace_output, trace_nodes);           // QbbHelper类，在trace_output文件中输出跟踪信息
                //qbb.EnablePcapAll("mixpcap/mypcap");
        }
	// dump link speed to trace file
	{
		SimSetting sim_setting;
		for (auto i: nbr2if){
			for (auto j : i.second){
				uint16_t node = i.first->GetId();
				uint8_t intf = j.second.idx;
				uint64_t bps = DynamicCast<QbbNetDevice>(i.first->GetDevice(j.second.idx))->GetDataRate().GetBitRate(); // bps = Bit每Per秒Second
				sim_setting.port_speed[node][intf] = bps;
			}
		}
		sim_setting.win = maxBdp;
		sim_setting.Serialize(trace_output);
	}

	Ipv4GlobalRoutingHelper::PopulateRoutingTables();

	NS_LOG_INFO("Create Applications.");

	Time interPacketInterval = Seconds(0.0000005 / 2);

	// maintain port number for each host
	for (uint32_t i = 0; i < node_num; i++){ // 遍历从 host 到 host 的端口数量
		if (n.Get(i)->GetNodeType() == 0) 
			for (uint32_t j = 0; j < node_num; j++){
				if (n.Get(j)->GetNodeType() == 0)
					portNumder[i][j] = 10000; // each host pair use port number from 10000
			}
	}

	flow_input.idx = 0;
	if (flow_num > 0){
	        printf("\nNormal Flow Node:");
		ReadFlowInput();
		ScheduleFlowInputs();
		printf("\n");
	}else
                printf("\nNo Normal Node.\n");
	if(attacker_num > 0){
	        printf("\nAttacker Node:");
	        ReadAttackerInput();
	        ScheduleAttackerInputs();
	        printf("\n");
        }else
                printf("\nNo Attacker.\n");
	topof.close();
	tracef.close();
	

	// schedule link down
	if (link_down_time > 0){
		Simulator::Schedule(Seconds(2) + MicroSeconds(link_down_time), &TakeDownLink, n, n.Get(link_down_A), n.Get(link_down_B));
	}

	// schedule buffer monitor
	FILE* qlen_output = fopen(qlen_mon_file.c_str(), "w");
	Simulator::Schedule(NanoSeconds(qlen_mon_start), &monitor_buffer, qlen_output, &n); // 计划在过了 qlen_mon_start 时间后再次调用monitor_buffer函数，实现定期监控。

	//
	// Now, do the actual simulation.
	//
	std::cout << "\nRunning Simulation.\n\n";
	fflush(stdout);
	NS_LOG_INFO("Run Simulation.");
	Simulator::Stop(Seconds(simulator_stop_time));
	Simulator::Run();
	Simulator::Destroy();
	NS_LOG_INFO("Done.");
	fclose(trace_output);

	endt = clock();
	std::cout << (double)(endt - begint) / CLOCKS_PER_SEC << "\n";

}
