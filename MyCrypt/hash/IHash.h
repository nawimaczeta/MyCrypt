#pragma once

#include <vector>
#include <stdint.h>

using namespace std;

class IHash
{
public:
	virtual void init() = 0;
	virtual void processData(vector<uint8_t> & data) = 0;
	virtual vector<uint8_t> finalize() = 0;

	vector<uint8_t> compute(vector<uint8_t> & data)
	{
		init();
		processData(data);
		return finalize();
	}

	vector<uint8_t> operator<<(vector<uint8_t> & in);
};

