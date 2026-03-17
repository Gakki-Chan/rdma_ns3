#include <iostream>
#include <fstream>
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/object-vector.h"
#include "ns3/uinteger.h"
#include "ns3/log.h"
#include "ns3/assert.h"
#include "ns3/global-value.h"
#include "ns3/boolean.h"
#include "ns3/simulator.h"
#include "ns3/random-variable.h"
#include "switch-mmu.h"

NS_LOG_COMPONENT_DEFINE("SwitchMmu");
namespace ns3 {
	TypeId SwitchMmu::GetTypeId(void){
		static TypeId tid = TypeId("ns3::SwitchMmu")
			.SetParent<Object>()
			.AddConstructor<SwitchMmu>();
		return tid;
	}

	SwitchMmu::SwitchMmu(void){
		buffer_size = 12 * 1024 * 1024;
		reserve = 4 * 1024;
		resume_offset = 3 * 1024;

		// headroom
		shared_used_bytes = 0;
		memset(hdrm_bytes, 0, sizeof(hdrm_bytes));
		memset(ingress_bytes, 0, sizeof(ingress_bytes));
		memset(paused, 0, sizeof(paused));
		memset(egress_bytes, 0, sizeof(egress_bytes));

		memset(ingress_queue_length, 0, sizeof(ingress_queue_length));
		memset(egress_queue_length, 0, sizeof(egress_queue_length));
	}
	bool SwitchMmu::CheckIngressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize){
		if (psize + hdrm_bytes[port][qIndex] > headroom[port] && psize + GetSharedUsed(port, qIndex) > GetPfcThreshold(port)){
			printf("%lu %u Drop: queue:%u,%u: Headroom full\n", Simulator::Now().GetTimeStep(), node_id, port, qIndex);
			for (uint32_t i = 1; i < 64; i++)
				printf("(%u,%u)", hdrm_bytes[i][3], ingress_bytes[i][3]);
			printf("\n");
			return false;
		}
		return true;
	}
	bool SwitchMmu::CheckEgressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize){
		return true;
	}
	void SwitchMmu::UpdateIngressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize){	// 更新入口准入字节计数，被switch-node.cc的SendToDev函数调用
		uint32_t new_bytes = ingress_bytes[port][qIndex] + psize;	// 此入口队列ingress_bytes放入packege后的新大小。psize=数据包的大小
		if (new_bytes <= reserve){	// 若此入口队列ingress_bytes新大小<=reserve，则：
			ingress_bytes[port][qIndex] += psize;	// 入口队列正常接收数据包
		}else {				// 若此入口队列ingress_bytes新大小>reserve，则：
			uint32_t thresh = GetPfcThreshold(port);	
			if (new_bytes - reserve > thresh){	// 若此入口队列超出reserve部分的大小 > 端口port的pfc阈值
				hdrm_bytes[port][qIndex] += psize;	// 数据包放到hdrm_bytes中。
			}else {					// 若此入口队列超出reserve部分的大小 <= 端口port的pfc阈值
				ingress_bytes[port][qIndex] += psize;	// 入口队列正常接收数据包
				shared_used_bytes += std::min(psize, new_bytes - reserve); // 更新共享缓冲区已使用字节数,并确保不会超出数据包的大小。ingress中超出reserve的部分。
			}
		}

		ingress_queue_length[port][qIndex]++;	// 入口队列长度 + 1
	}// PFC是在交换机入口发起的拥塞管理机制。无拥塞时，入口 buffer不需存储。当出口buffer达到一定阈值，入口 buffer开始积累。当入口 buffer达到阈值，入口开始主动迫使它的上级端口降速。
	void SwitchMmu::UpdateEgressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize){	// 更新出口准入字节计数，被switch-node.cc的SendToDev函数调用
		egress_bytes[port][qIndex] += psize;

		egress_queue_length[port][qIndex]++;
	}
	void SwitchMmu::RemoveFromIngressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize){ // 从入口端口的某队列中处理掉一个数据包，并更新相关的字节计数和队列状态。
		uint32_t from_hdrm = std::min(hdrm_bytes[port][qIndex], psize);	// 从hdrm_bytes中取出的字节数，并确保不会超出可用范围
		uint32_t from_shared = std::min(psize - from_hdrm, ingress_bytes[port][qIndex] > reserve ? ingress_bytes[port][qIndex] - reserve : 0); // 从共享区中取出的字节数
		hdrm_bytes[port][qIndex] -= from_hdrm;				// 更新hdrm字节数：减去已取出的字节数。
		ingress_bytes[port][qIndex] -= psize - from_hdrm;		// 更新入口字节数：减去数据包剩余需要取出的字节数。
		shared_used_bytes -= from_shared;				// 更新共享字节数：减去从共享区中取出的字节数。

		ingress_queue_length[port][qIndex]--;				// 减少队列长度，表示一个数据包已被处理。
	} // 共享缓冲区是：多个数据包可以共享同一块内存。当被复制或分片时，NS3不会立即分配新的内存，而是引用共享缓冲区中的数据，直到需要修改内容时才进行内存复制。
	void SwitchMmu::RemoveFromEgressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize){ // 从出口端口的某队列中处理掉一个数据包，并更新相关的字节计数和队列状态。
		egress_bytes[port][qIndex] -= psize; // 更新出口字节数，减去数据包字节数

		egress_queue_length[port][qIndex]--; // 减少队列长度，表示一个数据包已被处理。
	}
	bool SwitchMmu::CheckShouldPause(uint32_t port, uint32_t qIndex){ // 此队列不是暂停状态，且(超出pfc阈值的数据包>0)或(共享缓冲区>pfc阈值)，就发pause包
		return !paused[port][qIndex] && (hdrm_bytes[port][qIndex] > 0 || GetSharedUsed(port, qIndex) >= GetPfcThreshold(port));	
	}
	bool SwitchMmu::CheckShouldResume(uint32_t port, uint32_t qIndex){
		if (!paused[port][qIndex]) // 若此队列不是暂停状态，那么不用resume
			return false;
		uint32_t shared_used = GetSharedUsed(port, qIndex); // 若没有超出pfc阈值的包，且(未超过resume)或(超过resume的部分<=pfc阈值)，那么发送resume包
		return hdrm_bytes[port][qIndex] == 0 && (shared_used == 0 || shared_used + resume_offset <= GetPfcThreshold(port));
	}
	void SwitchMmu::SetPause(uint32_t port, uint32_t qIndex){	// 把端口port的队列qIndex设置为pause状态
		paused[port][qIndex] = true;
	}
	void SwitchMmu::SetResume(uint32_t port, uint32_t qIndex){	// 把端口port的队列qIndex设置为resume状态(取消pause状态)
		paused[port][qIndex] = false;
	}

	uint32_t SwitchMmu::GetPfcThreshold(uint32_t port){ // reserve左移2位，相当于乘以4
		// return (buffer_size - total_hdrm - total_rsrv - shared_used_bytes) >> pfc_a_shift[port];
		// TODO:?
		return reserve << 2;
	}
	uint32_t SwitchMmu::GetSharedUsed(uint32_t port, uint32_t qIndex){ // 返回入口队列中超出reserve部分的大小
		uint32_t used = ingress_bytes[port][qIndex];
		return used > reserve ? used - reserve : 0;
	}
	bool SwitchMmu::ShouldSendCN(uint32_t ifindex, uint32_t qIndex){
		if (qIndex == 0)
			return false;
		if (egress_bytes[ifindex][qIndex] > kmax[ifindex])
			return true;
		if (egress_bytes[ifindex][qIndex] > kmin[ifindex]){
			double p = pmax[ifindex] * double(egress_bytes[ifindex][qIndex] - kmin[ifindex]) / (kmax[ifindex] - kmin[ifindex]);
			if (UniformVariable(0, 1).GetValue() < p)
				return true;
		}
		return false;
	}
	void SwitchMmu::ConfigEcn(uint32_t port, uint32_t _kmin, uint32_t _kmax, double _pmax){
		kmin[port] = _kmin * 1000;
		kmax[port] = _kmax * 1000;
		pmax[port] = _pmax;
	}
	void SwitchMmu::ConfigHdrm(uint32_t port, uint32_t size){
		headroom[port] = size;
	}
	void SwitchMmu::ConfigNPort(uint32_t n_port){
		total_hdrm = 0;
		total_rsrv = 0;
		for (uint32_t i = 1; i <= n_port; i++){
			total_hdrm += headroom[i];
			total_rsrv += reserve;
		}
	}
	void SwitchMmu::ConfigBufferSize(uint32_t size){
		buffer_size = size;
	}
}
