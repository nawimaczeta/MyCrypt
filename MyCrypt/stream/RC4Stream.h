#pragma once

#include "IStream.h"

class RC4Stream :
	public IStream
{
public:
	virtual void setKey(Bytes & key) override;
	virtual void setIV(Bytes & IV) override;
	virtual void processBuffer(const Bytes & input, Bytes & output) override;

private:
	array<uint8_t, 256> _S;
	uint8_t _i, _j;
};

