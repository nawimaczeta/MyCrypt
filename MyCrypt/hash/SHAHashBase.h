#pragma once
#include <vector>
#include <stdint.h>
#include <queue>
#include <array>
#include <memory>

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
	const array<T, 8> _H_INIT;
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

const array<uint32_t, 64> SHA256_K_INIT{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const array<uint32_t, 8> SHA256_H_INIT{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

enum class HashAlgorythm {
	SHA256
};

struct HashFactory
{
	static unique_ptr<IHash> Get(enum class HashAlgorythm hashAlgorythm) {
		switch (hashAlgorythm) {
		case HashAlgorythm::SHA256:
			unique_ptr<IHash> res{ new SHAHashBase<uint32_t>(SHA256_H_INIT, SHA256_K_INIT) };
			return res;
			break;
		}

		return nullptr;
	}
};