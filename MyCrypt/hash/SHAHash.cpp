#include "SHAHash.h"

#include <algorithm>

template<typename T>
SHAHash<T>::SHAHash(const array<T, 8> & H_initValues, const vector<T> & K_values, uint32_t hashSizeWords,
	uint32_t numOfAlgorithmRuns, uint32_t wordSize) :
	_H_INIT{ H_initValues },
	_K{ K_values },
	_hashSizeWords{ hashSizeWords },
	_numOfAlgorithmRuns{ numOfAlgorithmRuns },
	_wordSize{ wordSize } 
{ 
	init();
}

template<typename T>
void SHAHash<T>::init()
{
	copy(begin(_H_INIT), end(_H_INIT), begin(_H));

	// clear queue
	queue<uint8_t> empty;
	swap(_dataQueue, empty);

	_dataLength = 0;
}

template<typename T>
void SHAHash<T>::processData(vector<uint8_t>& data)
{
	_dataLength += data.size() * 8;	// in bytes

	for (auto & d : data) {
		_dataQueue.push(d);
	}

	while (_dataQueue.size() >= _wordSize) {
		DataBlock db;
		for (uint32_t i = 0; i < _wordSize; i++) {
			db.push_back(_dataQueue.front());
			_dataQueue.pop();
		}
		_compressBlock(db);
	}
}

template<typename T>
vector<uint8_t> SHAHash<T>::finalize()
{
	// append bit 1
	_dataQueue.push(0x80);

	if (_dataQueue.size() > (_wordSize - 8)) {
		while (_dataQueue.size() < _wordSize) {
			_dataQueue.push(0);
		}
	}

	while ((_dataQueue.size() % _wordSize) < (_wordSize - 8)) {
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

	while (_dataQueue.size() >= _wordSize) {
		DataBlock db;
		for (uint32_t i = 0; i < _wordSize; i++) {
			db.push_back(_dataQueue.front());
			_dataQueue.pop();
		}
		_compressBlock(db);
	}

	vector<uint8_t> res;
	for (uint32_t i = 0; i < _hashSizeWords; i++) {
		auto ah = _BytesFromWord(_H[i]);
		copy(begin(ah), end(ah), back_inserter(res));
	}

	return res;
}

template<typename T>
void SHAHash<T>::_compressBlock(DataBlock & dataBlock)
{
	T a = _H[0];
	T b = _H[1];
	T c = _H[2];
	T d = _H[3];
	T e = _H[4];
	T f = _H[5];
	T g = _H[6];
	T h = _H[7];

	//array<T, 64> W;
	vector<T> W;
	for (uint32_t i = 0; i < 16; i++) {
		vector<uint8_t> v;
		uint32_t NumOfBytes = sizeof(T);
		copy_n(begin(dataBlock) + i * NumOfBytes, NumOfBytes, back_inserter(v));
		W.push_back(_WordFromBytes(v));
	}

	for (uint32_t i = 16; i < _numOfAlgorithmRuns; i++) {
		W.push_back(_SHA256_sigma1(W[i - 2]) + W[i - 7] + _SHA256_sigma0(W[i - 15]) + W[i - 16]);
	}

	for (uint32_t j = 0; j < _numOfAlgorithmRuns; j++) {
		T T1 = h + _SHA256_Sigma1(e) + _SHA256_Ch(e, f, g) + _K[j] + W[j];
		T T2 = _SHA256_Sigma0(a) + _SHA256_Maj(a, b, c);
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
inline T SHAHash<T>::_SHA256_Ch(T x, T y, T z) const
{
	return (x & y) ^ (~x & z);
}

template<typename T>
inline T SHAHash<T>::_SHA256_Maj(T x, T y, T z) const
{
	return (x & y) ^ (x & z) ^ (y & z);
}

template<typename T>
inline T SHAHash<T>::_SHA256_Sigma0(T x) const
{
	return _S(x, 2) ^ _S(x, 13) ^ _S(x, 22);
}

template<typename T>
inline T SHAHash<T>::_SHA256_Sigma1(T x) const
{
	return _S(x, 6) ^ _S(x, 11) ^ _S(x, 25);
}

template<typename T>
inline T SHAHash<T>::_SHA256_sigma0(T x) const
{
	return _S(x, 7) ^ _S(x, 18) ^ _R(x, 3);
}

template<typename T>
inline T SHAHash<T>::_SHA256_sigma1(T x) const
{
	return _S(x, 17) ^ _S(x, 19) ^ _R(x, 10);
}

template<typename T>
inline T SHAHash<T>::_R(T x, T n) const
{
	return x >> n;
}

template<typename T>
inline T SHAHash<T>::_S(T x, T n) const
{
	return x >> n | x << (32 - n);
}

template<typename T>
inline array<uint8_t, 8> SHAHash<T>::_AUINT8fromUINT64(uint64_t in) const
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
inline T SHAHash<T>::_WordFromBytes(vector<uint8_t> in) const
{
	reverse(begin(in), end(in));
	T res = *reinterpret_cast<T *>(in.data());
	//uint32_t counter = 0;
	//T res = 0;
	//for (uint32_t i = 0; i < in.size(); i++) {
	//	uint32_t f = ((7 - i) * 8);
	//	res |= in[i] << f;
	//}
	//for_each(rbegin(in), rend(in), 
	//	[&counter, &res](auto v) { 
	//	res |= v << (counter++ * 8); 
	//});
	return res;
}

template<typename T>
inline vector<uint8_t> SHAHash<T>::_BytesFromWord(T in) const
{
	vector<uint8_t> res(sizeof(T));
	uint8_t *ptr = reinterpret_cast<uint8_t *>(&in);
	for_each(rbegin(res), rend(res), [&ptr](auto & byte) { byte = *(ptr++); });
	return res;
}

template class SHAHash<uint32_t>;
template class SHAHash<uint64_t>;
