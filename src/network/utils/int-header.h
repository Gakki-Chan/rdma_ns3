#ifndef INT_HEADER_H
#define INT_HEADER_H

#include "ns3/buffer.h"
#include <stdint.h>
#include <cstdio>

namespace ns3 {

class IntHop{
public:
	static const uint32_t timeWidth = 24;
	static const uint32_t bytesWidth = 20;
	static const uint32_t qlenWidth = 17;
	static const uint64_t lineRateValues[8];
	union{
		struct {
			uint64_t lineRate: 64-timeWidth-bytesWidth-qlenWidth,
				time: timeWidth,
				bytes: bytesWidth,
				qlen: qlenWidth;
		} fields;
		uint32_t buf[2];
	};

	static const uint32_t byteUnit = 128;
	static const uint32_t qlenUnit = 80;
	static uint32_t multi;

	uint64_t GetLineRate(){
		return lineRateValues[fields.lineRate];
	}
	uint64_t GetBytes(){
		return (uint64_t)fields.bytes * byteUnit * multi;
	}
	uint32_t GetQlen(){
		return (uint32_t)fields.qlen * qlenUnit * multi;
	}
	uint64_t GetTime(){
		return fields.time;
	}
	void Set(uint64_t _time, uint64_t _bytes, uint32_t _qlen, uint64_t _rate){
		fields.time = _time;
		fields.bytes = _bytes / (byteUnit * multi);
		fields.qlen = _qlen / (qlenUnit * multi);
		switch (_rate){
			case 25000000000lu:
				fields.lineRate=0;break;
			case 50000000000lu:
				fields.lineRate=1;break;
			case 100000000000lu:
				fields.lineRate=2;break;
			case 200000000000lu:
				fields.lineRate=3;break;
			case 400000000000lu:
				fields.lineRate=4;break;
			default:
				printf("Error: IntHeader unknown rate: %lu\n", _rate);
				break;
		}
	}
	uint64_t GetBytesDelta(IntHop &b){
		if (fields.bytes >= b.fields.bytes)
			return (fields.bytes - b.fields.bytes) * byteUnit * multi;
		else
			return (fields.bytes + (1<<bytesWidth) - b.fields.bytes) * byteUnit * multi;
	}
	uint64_t GetTimeDelta(IntHop &b){
		if (fields.time >= b.fields.time)
			return fields.time - b.fields.time;
		else
			return fields.time + (1<<timeWidth) - b.fields.time;
	}
};

class IntHeader{
public:
	static const uint32_t maxHop = 5;
	enum Mode{
		NORMAL = 0,
		TS = 1,
		PINT = 2,
		NONE
	};
	static Mode mode;
	static int pint_bytes;

	// Note: the structure of IntHeader must have no internal padding, because we will directly transform the part of packet buffer to IntHeader*
	union{
		#pragma GCC diagnostic push
		#pragma GCC diagnostic ignored "-Wpedantic" // no warning
		struct {
			IntHop hop[maxHop];
			uint16_t nhop;
		}/*Hop*/;
		#pragma GCC diagnostic pop
		uint64_t ts;
		union {
			uint16_t power;
			struct{
				uint8_t power_lo8, power_hi8;
			}Power;
		}pint;
	};

	IntHeader();
	static uint32_t GetStaticSize();
	void PushHop(uint64_t time, uint64_t bytes, uint32_t qlen, uint64_t rate);
	void Serialize (Buffer::Iterator start) const;
	uint32_t Deserialize (Buffer::Iterator start);
	uint64_t GetTs(void);
	uint16_t GetPower(void);
	void SetPower(uint16_t);
};

}

#endif /* INT_HEADER_H */
