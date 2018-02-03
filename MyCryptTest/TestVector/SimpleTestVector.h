#pragma once

#include "ITestVector.h"

class SimpleTestVector :
	public ITestVector
{
public:
	SimpleTestVector() = delete;
	SimpleTestVector(Bytes key, Bytes inputVector, Bytes outputVector) :
		_key{ key }, _inputVector{ inputVector }, _outputVector{ outputVector } {}

	virtual Bytes getInputData() const {
		return _inputVector;
	}

	virtual Bytes getKey() const {
		return _key;
	}

	virtual bool validateOutput(Bytes & output) {
		return _outputVector == output;
	}

private:
	Bytes _key;
	Bytes _inputVector;
	Bytes _outputVector;
};

