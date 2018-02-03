#pragma once

#include <vector>

#include "ITestVector.h"

class RCF6229TestVector	
	: public ITestVector {
public:
	RCF6229TestVector(uint32_t inputSize, Bytes key, vector<uint32_t> offsets, vector<uint8_t> outputStream) :
		_inputSize{ inputSize }, _key{ key }, _offsets{ offsets }, _outputStream{ outputStream } {}

	virtual Bytes getKey() const {
		return _key;
	}

	virtual Bytes getInputData() const {
		Bytes res(_inputSize);
		return res;
	}

	virtual bool validateOutput(Bytes & output) {
		vector<uint8_t> vectorChunks;
		for (auto offset : _offsets) {
			copy_n(begin(output) + offset, CHUNK_SIZE, back_inserter(vectorChunks));
		}
		return equal(begin(_outputStream), end(_outputStream), begin(vectorChunks));
	}

private:
	static const uint32_t CHUNK_SIZE = 32;

	uint32_t _inputSize;
	Bytes _key;
	vector<uint32_t> _offsets;
	vector<uint8_t> _outputStream;
};