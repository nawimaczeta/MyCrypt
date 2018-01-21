#include "hash/SHA256Hash.h"

const array<uint32_t, 64> SHA256Hash::_K {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA256Hash::SHA256Hash()
{
	init();
}

void SHA256Hash::init()
{
	_H1 = _H_1_INIT;
	_H2 = _H_2_INIT;
	_H3 = _H_3_INIT;
	_H4 = _H_4_INIT;
	_H5 = _H_5_INIT;
	_H6 = _H_6_INIT;
	_H7 = _H_7_INIT;
	_H8 = _H_8_INIT;

	// clear queue
	queue<uint8_t> empty;
	swap(_dataQueue, empty);

	_dataLength = 0;
}

void SHA256Hash::processData(vector<uint8_t>& data)
{
	_dataLength += data.size() * 8;	// in bytes

	for (auto & d : data) {
		_dataQueue.push(d);
	}

	while (_dataQueue.size() >= 64) {
		DataBlock db;
		for (int i = 0; i < 64; i++) {
			db.at(i) = _dataQueue.front();
			_dataQueue.pop();
		}
		_compressBlock(db);
	}
}

vector<uint8_t> SHA256Hash::finalize()
{
	// append bit 1
	_dataQueue.push(0x80);

	if (_dataQueue.size() > 56) {
		while (_dataQueue.size() < 64) {
			_dataQueue.push(0);
		}
	}

	while ((_dataQueue.size() % 64) < 56) {
		_dataQueue.push(0);
	}

	auto length = _AUINT8fromUINT64(_dataLength);
	_dataQueue.push(length[0]);
	_dataQueue.push(length[1]);
	_dataQueue.push(length[2]);
	_dataQueue.push(length[3]);
	_dataQueue.push(length[4]);
	_dataQueue.push(length[5]);
	_dataQueue.push(length[6]);
	_dataQueue.push(length[7]);

	while (_dataQueue.size() >= 64) {
		DataBlock db;
		for (int i = 0; i < 64; i++) {
			db.at(i) = _dataQueue.front();
			_dataQueue.pop();
		}
		_compressBlock(db);
	}

	auto AH1 = _AUINT8fromUINT32(_H1);
	auto AH2 = _AUINT8fromUINT32(_H2);
	auto AH3 = _AUINT8fromUINT32(_H3);
	auto AH4 = _AUINT8fromUINT32(_H4);
	auto AH5 = _AUINT8fromUINT32(_H5);
	auto AH6 = _AUINT8fromUINT32(_H6);
	auto AH7 = _AUINT8fromUINT32(_H7);
	auto AH8 = _AUINT8fromUINT32(_H8);

	vector<uint8_t> res;
	copy(begin(AH1), end(AH1), back_inserter(res));
	copy(begin(AH2), end(AH2), back_inserter(res));
	copy(begin(AH3), end(AH3), back_inserter(res));
	copy(begin(AH4), end(AH4), back_inserter(res));
	copy(begin(AH5), end(AH5), back_inserter(res));
	copy(begin(AH6), end(AH6), back_inserter(res));
	copy(begin(AH7), end(AH7), back_inserter(res));
	copy(begin(AH8), end(AH8), back_inserter(res));

	return res;
}

void SHA256Hash::_compressBlock(DataBlock & dataBlock)
{
	uint32_t a = _H1;
	uint32_t b = _H2;
	uint32_t c = _H3;
	uint32_t d = _H4;
	uint32_t e = _H5;
	uint32_t f = _H6;
	uint32_t g = _H7;
	uint32_t h = _H8;

	array<uint32_t, 64> W;
	for (int i = 0; i < 16; i++) {
		array<uint8_t, 4> a{dataBlock[4 * i], dataBlock[4 * i + 1], dataBlock[4 * i + 2], dataBlock[4 * i + 3]};
		W[i] = _UINT32fromAUINT8(a);
	}

	for (int i = 16; i < 64; i++) {
		W[i] = _SHA256_sigma1(W[i - 2]) + W[i - 7] + _SHA256_sigma0(W[i - 15]) + W[i - 16];
	}

	for (int j = 0; j < 64; j++) {
		uint32_t T1 = h + _SHA256_Sigma1(e) + _SHA256_Ch(e, f, g) + _K[j] + W[j];
		uint32_t T2 = _SHA256_Sigma0(a) + _SHA256_Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	_H1 += a;
	_H2 += b;
	_H3 += c;
	_H4 += d;
	_H5 += e;
	_H6 += f;
	_H7 += g;
	_H8 += h;
}

inline uint32_t SHA256Hash::_SHA256_Ch(uint32_t x, uint32_t y, uint32_t z) const
{
	return (x & y) ^ (~x & z);
}

inline uint32_t SHA256Hash::_SHA256_Maj(uint32_t x, uint32_t y, uint32_t z) const
{
	return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t SHA256Hash::_SHA256_Sigma0(uint32_t x) const
{
	return _S(x, 2) ^ _S(x, 13) ^ _S(x, 22);
}

inline uint32_t SHA256Hash::_SHA256_Sigma1(uint32_t x) const
{
	return _S(x, 6) ^ _S(x, 11) ^ _S(x, 25);
}

inline uint32_t SHA256Hash::_SHA256_sigma0(uint32_t x) const
{
	return _S(x, 7) ^ _S(x, 18) ^ _R(x, 3);
}

inline uint32_t SHA256Hash::_SHA256_sigma1(uint32_t x) const
{
	return _S(x, 17) ^ _S(x, 19) ^ _R(x, 10);
}

inline uint32_t SHA256Hash::_R(uint32_t x, uint32_t n) const
{
	return x >> n;
}

inline uint32_t SHA256Hash::_S(uint32_t x, uint32_t n) const
{
	return x >> n | x << (32 - n);
}

inline uint32_t SHA256Hash::_UINT32fromAUINT8(array<uint8_t, 4> in) const
{
	return (uint32_t)(in[0] << 24) | 
		(uint32_t)(in[1] << 16) | 
		(uint32_t)(in[2] << 8) | 
		(uint32_t)in[3];
}

inline array<uint8_t, 8> SHA256Hash::_AUINT8fromUINT64(uint64_t in) const
{
	union {
		uint64_t u64;
		uint8_t au8[8];
	} u;

	u.u64 = in;
	array<uint8_t, 8> out{
		u.au8[7], u.au8[6], u.au8[5], u.au8[4],
		u.au8[3], u.au8[2], u.au8[1], u.au8[0]
	};
	return out;
}

inline array<uint8_t, 4> SHA256Hash::_AUINT8fromUINT32(uint32_t in) const 
{
	union {
		uint64_t u32;
		uint8_t au8[4];
	} u;

	u.u32 = in;
	array<uint8_t, 4> out{
		u.au8[3], u.au8[2], u.au8[1], u.au8[0]
	};
	return out;
}
