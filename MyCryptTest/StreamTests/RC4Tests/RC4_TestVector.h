#pragma once

#include "MyCrypt.h"

struct RC4_TestVector {
	Bytes key;
	Bytes outputStream;
};