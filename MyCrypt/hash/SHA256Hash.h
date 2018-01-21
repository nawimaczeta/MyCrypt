#pragma once

#include <vector>
#include <stdint.h>
#include <queue>
#include <array>
#include <ostream>

#include "SHAHashBase.h"

using namespace std;

class SHA256Hash :
	public SHAHashBase<uint32_t>
{
public:
	SHA256Hash();

	virtual void init() override {
		SHAHashBase::init();
	}

	virtual void processData(vector<uint8_t> & data) override {
		SHAHashBase::processData(data);
	}

	virtual vector<uint8_t> finalize() override {
		return SHAHashBase::finalize();
	}
	
private:
	static const array<uint32_t, 8> _H_INIT;
	static const array<uint32_t, 64> _K_INIT;
};

