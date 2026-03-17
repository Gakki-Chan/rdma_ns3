/*
 * Copyright (c) 2009 INRIA
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#include "seq-ts-header.h"

#include "ns3/assert.h"
#include "ns3/header.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("SeqTsHeader");

NS_OBJECT_ENSURE_REGISTERED(SeqTsHeader);

SeqTsHeader::SeqTsHeader()
    : m_seq(0),
      m_ts(Simulator::Now().GetTimeStep())
{
    NS_LOG_FUNCTION(this);
}

void
SeqTsHeader::SetSeq(uint32_t seq)
{
    NS_LOG_FUNCTION(this << seq);
    m_seq = seq;
}

uint32_t
SeqTsHeader::GetSeq() const
{
    NS_LOG_FUNCTION(this);
    return m_seq;
}

Time
SeqTsHeader::GetTs() const
{
    NS_LOG_FUNCTION(this);
    return TimeStep(m_ts);
}

void
SeqTsHeader::SetPG (uint16_t pg)
{
	m_pg = pg;
}
uint16_t
SeqTsHeader::GetPG (void) const
{
	return m_pg;
}

TypeId
SeqTsHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::SeqTsHeader")
                            .SetParent<Header>()
                            .SetGroupName("Applications")
                            .AddConstructor<SeqTsHeader>();
    return tid;
}

TypeId
SeqTsHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

void
SeqTsHeader::Print(std::ostream& os) const
{
    NS_LOG_FUNCTION(this << &os);
    os << "(seq=" << m_seq << " time=" << TimeStep(m_ts).As(Time::S) << ")";
}

uint32_t
SeqTsHeader::GetSerializedSize() const
{
    NS_LOG_FUNCTION(this);
    return GetHeaderSize();
}
uint32_t SeqTsHeader::GetHeaderSize(void){ // static
	return 12 + IntHeader::GetStaticSize();
}

void
SeqTsHeader::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION(this << &start);
    Buffer::Iterator i = start;
    if(isRdma){
    	i.WriteU8(0); 		// Opcode: 0 = SEND First
	i.WriteU8(0);
	i.WriteU16(0xffff);     // Partition Key
	i.WriteU16(0); 		// reserved = 8b. this 16b is reversed(8) + m_pg(8)
	i.WriteHtonU16(m_pg); 	// m_pg(24b) = 8b + 16b, 8b in reserved
	i.WriteHtonU32(m_seq);	// A(1b) + Reserves(7b) + PSNSep(24b) = 32b
    }else {
    	//i.WriteHtonU32(m_seq);
    	//i.WriteHtonU64(m_ts);
    	i.WriteU32 (0); // new add
        i.WriteHtonU32 (m_seq);
        i.WriteU16(0); // new
        i.WriteHtonU16 (m_pg);
    }
    
        // write IntHeader
        ih.Serialize(i);
}

uint32_t
SeqTsHeader::Deserialize(Buffer::Iterator start)
{
    NS_LOG_FUNCTION(this << &start);
    Buffer::Iterator i = start;
    //m_seq = i.ReadNtohU32();
    //m_ts = i.ReadNtohU64();
    /* 改 */
    if(isRdma){   
	i.ReadU16();
	i.ReadU32();
	m_pg = i.ReadNtohU16();
	m_seq = i.ReadNtohU32();
    } else {      
        /* 原 */
	i.ReadU32();
        m_seq = i.ReadNtohU32 ();
	i.ReadU16();
        m_pg =  i.ReadNtohU16 ();
        
    }
    // read IntHeader
    ih.Deserialize(i);
    return GetSerializedSize();
    
}

} // namespace ns3
