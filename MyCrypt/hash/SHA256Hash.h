#pragma once

#include <vector>
#include <stdint.h>
#include <queue>
#include <array>
#include <ostream>

#include "IHash.h"

using namespace std;

typedef array<uint8_t, 64> DataBlock;

class SHA256Hash :
	public IHash
{
public:
	SHA256Hash();

	virtual void init();
	virtual void processData(vector<uint8_t> & data);
	virtual vector<uint8_t> finalize();
	
private:
	static const uint32_t _H_1_INIT = 0x6a09e667;
	static const uint32_t _H_2_INIT = 0xbb67ae85;
	static const uint32_t _H_3_INIT = 0x3c6ef372;
	static const uint32_t _H_4_INIT = 0xa54ff53a;
	static const uint32_t _H_5_INIT = 0x510e527f;
	static const uint32_t _H_6_INIT = 0x9b05688c;
	static const uint32_t _H_7_INIT = 0x1f83d9ab;
	static const uint32_t _H_8_INIT = 0x5be0cd19;

	static const array<uint32_t, 64> _K;

	uint32_t _H1;
	uint32_t _H2;
	uint32_t _H3;
	uint32_t _H4;
	uint32_t _H5;
	uint32_t _H6;
	uint32_t _H7;
	uint32_t _H8;

	queue<uint8_t> _dataQueue;
	uint64_t _dataLength;

	void _compressBlock(DataBlock & dataBlock);

	inline uint32_t _SHA256_Ch(uint32_t x, uint32_t y, uint32_t z) const;
	inline uint32_t _SHA256_Maj(uint32_t x, uint32_t y, uint32_t z) const;
	inline uint32_t _SHA256_Sigma0(uint32_t x) const;
	inline uint32_t _SHA256_Sigma1(uint32_t x) const;
	inline uint32_t _SHA256_sigma0(uint32_t x) const;
	inline uint32_t _SHA256_sigma1(uint32_t x) const;

	inline uint32_t _R(uint32_t x, uint32_t n) const;
	inline uint32_t _S(uint32_t x, uint32_t n) const;

	inline uint32_t _UINT32fromAUINT8(array<uint8_t, 4> in) const;
	inline array<uint8_t, 8> _AUINT8fromUINT64(uint64_t in) const;
	inline array<uint8_t, 4> _AUINT8fromUINT32(uint32_t in) const;
};

