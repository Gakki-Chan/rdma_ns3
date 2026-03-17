#ifndef SWITCH_MMU_H
#define SWITCH_MMU_H

#include <unordered_map>
#include <ns3/node.h>

namespace ns3 {

class Packet;

class SwitchMmu: public Object{
public:
	static const uint32_t pCnt = 257;	// Number of ports used
	static const uint32_t qCnt = 8;	// Number of queues/priorities used

	static TypeId GetTypeId (void);

	SwitchMmu(void);

	bool CheckIngressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize);
	bool CheckEgressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize);
	void UpdateIngressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize);	// 更新入口准入字节计数。根据当前队列的字节数和阈值，决定如何分配新到达数据包的字节数，并更新相关的队列状态
	void UpdateEgressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize);	// 更新出口准入字节计数。
	void RemoveFromIngressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize);// 从某入口队列中处理掉一个数据包，并更新相关的字节计数和队列状态。
	void RemoveFromEgressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize); // 从某出口队列中处理掉一个数据包，并更新相关的字节计数和队列状态。

	bool CheckShouldPause(uint32_t port, uint32_t qIndex);	// 检查端口port的队列qIndex处，根据pfc阈值， 决定是否要发暂停包
	bool CheckShouldResume(uint32_t port, uint32_t qIndex); // 检查端口port的队列qIndex处，根据resume值， 决定是否要发Resume包
	void SetPause(uint32_t port, uint32_t qIndex);		// 把端口port的队列qIndex设置为pause状态
	void SetResume(uint32_t port, uint32_t qIndex);  	// 把端口port的队列qIndex设置为resume状态(取消pause状态)
	//void GetPauseClasses(uint32_t port, uint32_t qIndex);
	//bool GetResumeClasses(uint32_t port, uint32_t qIndex);

	uint32_t GetPfcThreshold(uint32_t port);
	uint32_t GetSharedUsed(uint32_t port, uint32_t qIndex);

	bool ShouldSendCN(uint32_t ifindex, uint32_t qIndex);

	void ConfigEcn(uint32_t port, uint32_t _kmin, uint32_t _kmax, double _pmax);
	void ConfigHdrm(uint32_t port, uint32_t size);
	void ConfigNPort(uint32_t n_port);
	void ConfigBufferSize(uint32_t size);

	// config
	uint32_t node_id;
	uint32_t buffer_size;
	uint32_t pfc_a_shift[pCnt];
	uint32_t reserve;
	uint32_t headroom[pCnt];
	uint32_t resume_offset;
	uint32_t kmin[pCnt], kmax[pCnt];
	double pmax[pCnt];
	uint32_t total_hdrm;
	uint32_t total_rsrv;

	// runtime
	uint32_t shared_used_bytes;		// 可能是共享缓冲区中已使用的字节数。用于跟踪共享缓冲区的使用情况，确保缓冲区不会超出其容量。
	uint32_t hdrm_bytes[pCnt][qCnt];	// 可能是数据包中协议头部的字节数，包含控制信息（如源地址、目的地址、序列号等）
	uint32_t ingress_bytes[pCnt][qCnt];
	uint32_t paused[pCnt][qCnt];
	uint32_t egress_bytes[pCnt][qCnt];

	//RDMA NPA
	uint32_t ingress_queue_length[pCnt][qCnt];
	uint32_t egress_queue_length[pCnt][qCnt];
};

} /* namespace ns3 */

#endif /* SWITCH_MMU_H */

