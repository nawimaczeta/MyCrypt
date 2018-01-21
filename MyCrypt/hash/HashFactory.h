#pragma once

#include <memory>

#include "IHash.h"
#include "SHA256Hash.h"

using namespace std;

enum class HashAlgorythm {
	SHA256
};

struct HashFactory
{
	static unique_ptr<IHash> Get(enum class HashAlgorythm hashAlgorythm) {
		switch (hashAlgorythm) {
		case HashAlgorythm::SHA256:
			unique_ptr<IHash> res{ new SHA256Hash };
			return res;
			break;
		}

		return nullptr;
	}
};
