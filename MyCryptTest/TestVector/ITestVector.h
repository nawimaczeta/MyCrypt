#pragma once

#include "MyCrypt.h"

class ITestVector {
public:
	~ITestVector() {}

	virtual Bytes getInputData() const  = 0;
	virtual Bytes getKey() const  = 0;
	virtual bool validateOutput(Bytes & output) = 0;
};
