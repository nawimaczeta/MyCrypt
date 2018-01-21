#include "SHAHashBase.h"

#include <algorithm>

template<typename T>
SHAHashBase<T>::SHAHashBase(array<T, 8> H_initValues, array<T, 64> K_values) :
	_H_INIT{ H_initValues },
	_K{ K_values }
{
}

template<typename T>
void SHAHashBase<T>::init()
{
	copy(begin(_H_INIT), end(_H_INIT), begin(_H));

	// clear queue
	queue<uint8_t> empty;
	swap(_dataQueue, empty);

	_dataLength = 0;
}

template<typename T>
void SHAHashBase<T>::processData(vector<uint8_t>& data)
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

template<typename T>
vector<uint8_t> SHAHashBase<T>::finalize()
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
}

template<typename T>
void SHAHashBase<T>::_compressBlock(DataBlock & dataBlock)
{
	uint32_t a = _H[0];
	uint32_t b = _H[1];
	uint32_t c = _H[2];
	uint32_t d = _H[3];
	uint32_t e = _H[4];
	uint32_t f = _H[5];
	uint32_t g = _H[6];
	uint32_t h = _H[7];

	array<T, 64> W;
	for (int i = 0; i < 16; i++) {
		array<uint8_t, 4> a{ dataBlock[4 * i], dataBlock[4 * i + 1], dataBlock[4 * i + 2], dataBlock[4 * i + 3] };
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

	_H[0] += a;
	_H[1] += b;
	_H[2] += c;
	_H[3] += d;
	_H[4] += e;
	_H[5] += f;
	_H[6] += g;
	_H[7] += h;
}

template<typename T>
inline T SHAHashBase<T>::_SHA256_Ch(T x, T y, T z) const
{
	return (x & y) ^ (~x & z);
}

template<typename T>
inline T SHAHashBase<T>::_SHA256_Maj(T x, T y, T z) const
{
	return (x & y) ^ (x & z) ^ (y & z);
}

template<typename T>
inline T SHAHashBase<T>::_SHA256_Sigma0(T x) const
{
	return _S(x, 2) ^ _S(x, 13) ^ _S(x, 22);
}

template<typename T>
inline T SHAHashBase<T>::_SHA256_Sigma1(T x) const
{
	return _S(x, 6) ^ _S(x, 11) ^ _S(x, 25);
}

template<typename T>
inline T SHAHashBase<T>::_SHA256_sigma0(T x) const
{
	return _S(x, 7) ^ _S(x, 18) ^ _R(x, 3);
}

template<typename T>
inline T SHAHashBase<T>::_SHA256_sigma1(T x) const
{
	return _S(x, 17) ^ _S(x, 19) ^ _R(x, 10);
}

template<typename T>
inline T SHAHashBase<T>::_R(T x, T n) const
{
	return x >> n;
}

template<typename T>
inline T SHAHashBase<T>::_S(T x, T n) const
{
	return x >> n | x << (32 - n);
}

template<typename T>
inline array<uint8_t, 8> SHAHashBase<T>::_AUINT8fromUINT64(uint64_t in) const
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

template<typename T>
inline uint32_t SHAHashBase<T>::_UINT32fromAUINT8(array<uint8_t, 4> in) const
{
	return (uint32_t)(in[0] << 24) |
		(uint32_t)(in[1] << 16) |
		(uint32_t)(in[2] << 8) |
		(uint32_t)in[3];
}

template<typename T>
inline array<uint8_t, 4> SHAHashBase<T>::_AUINT8fromUINT32(uint32_t in) const
{
	union {
		uint64_t u32;
		uint8_t au8[4];
	};

	u.u32 = in;
	array<uint8_t, 4> out{
		u.au8[3], u.au8[2], u.au8[1], u.au8[0]
	};
	return out;
}
