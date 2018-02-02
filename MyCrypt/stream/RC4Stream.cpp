#include "RC4Stream.h"

void RC4Stream::setKey(Bytes & key)
{
	uint8_t j;
	uint32_t keySize = key.size();

	iota(begin(_S), end(_S), 0);

	j = 0;
	for (uint32_t i = 0; i < 256; i++) {
		j += _S[i] + key[i % keySize];
		swap(_S[i], _S[j]);
	}

	_i = 0;
	_j = 0;
}

void RC4Stream::setIV(Bytes & IV) {
	// Not needed by RC4
}

void RC4Stream::processBuffer(Bytes & buffer) {
	processBuffer(buffer, buffer);
}

void RC4Stream::processBuffer(const Bytes & input, Bytes & output)
{
	auto io = begin(output);

	for (auto & b : input) {
		_i++;
		_j += _S[_i];
		swap(_S[_i], _S[_j]);
		uint8_t K = _S[(_S[_i] + _S[_j]) % 256];

		*io = b ^ K;
		io++;
	}
}
