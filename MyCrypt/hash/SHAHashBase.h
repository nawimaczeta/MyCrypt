#pragma once
#include <vector>
#include <stdint.h>
#include <queue>
#include <array>

#include "IHash.h"

using namespace std;

typedef array<uint8_t, 64> DataBlock;

template<typename T>
class SHAHashBase :
	public IHash
{
public:
	SHAHashBase(array<T, 8> H_initValues, array<T, 64> K_values);
	virtual ~SHAHashBase() {};

	virtual void init() override;
	virtual void processData(vector<uint8_t> & data) override;
	virtual vector<uint8_t> finalize() override;

protected:
	const array<uint8_t, 8> _H_INIT;
	const array<T, 64> _K;

	array<T, 8> _H;

	queue<uint8_t> _dataQueue;
	uint64_t _dataLength;

	void _compressBlock(DataBlock & dataBlock);

	inline T _SHA256_Ch(T x, T y, T z) const;
	inline T _SHA256_Maj(T x, T y, T z) const;
	inline T _SHA256_Sigma0(T x) const;
	inline T _SHA256_Sigma1(T x) const;
	inline T _SHA256_sigma0(T x) const;
	inline T _SHA256_sigma1(T x) const;

	inline T _R(T x, T n) const;
	inline T _S(T x, T n) const;

	inline uint32_t _UINT32fromAUINT8(array<uint8_t, 4> in) const;
	inline array<uint8_t, 8> _AUINT8fromUINT64(uint64_t in) const;
	inline array<uint8_t, 4> _AUINT8fromUINT32(uint32_t in) const;
};
