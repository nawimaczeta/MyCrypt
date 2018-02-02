#pragma once

#include <vector>
#include <array>
#include <algorithm>
#include <numeric>
#include <stdint.h>

#include "MyCrypt.h"

class IStream {
public:
	virtual ~IStream() {}

	virtual void setKey(Bytes & key) = 0;
	virtual void setIV(Bytes & IV) = 0;
	virtual void processBuffer(Bytes & buffer) = 0;
	virtual void processBuffer(const Bytes & input, Bytes & output) = 0;
};
