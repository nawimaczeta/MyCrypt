// MyCrypt.cpp : Defines the entry point for the console application.
//

#include <memory>
#include <iostream>
#include <string>
#include <iomanip>

#include "stdafx.h"
//#include "hash/HashFactory.h"
#include "hash/SHAHashBase.h"

using namespace std;

int main()
{
	string s{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" };
	vector<uint8_t> in;
	copy(begin(s), end(s), back_inserter(in));

	cout << "Input data: \n" << s << "\n";
	cout << "HAsh:\n";

	auto hash1 = HashFactory::Get(HashAlgorythm::SHA256)->compute(in);

	for (auto h : hash1) {
		cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	}
	cout << endl;

	auto sha256 = HashFactory::Get(HashAlgorythm::SHA256);
	*sha256 << in;
	auto hash2 = sha256->finalize();

	for (auto h : hash2) {
		cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	}
	cout << endl;

	getchar();
	
    return 0;
}

