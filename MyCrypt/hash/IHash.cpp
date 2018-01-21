#include "IHash.h"

vector<uint8_t> IHash::operator<<(vector<uint8_t>& in)
{
	processData(in);
	return in;
}
