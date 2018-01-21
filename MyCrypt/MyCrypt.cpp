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

	auto hash256_1 = HashFactory::Get(HashAlgorythm::SHA256)->compute(in);
	auto hash224_1 = HashFactory::Get(HashAlgorythm::SHA224)->compute(in);

	for (auto h : hash256_1) {
		cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	}
	cout << endl;

	for (auto h : hash224_1) {
		cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	}
	cout << endl;
	
	auto sha256 = HashFactory::Get(HashAlgorythm::SHA256);
	auto sha224 = HashFactory::Get(HashAlgorythm::SHA224);

	*sha256 << in;
	*sha224 << in;
	auto hash256_2 = sha256->finalize();
	auto hash224_2 = sha224->finalize();

	for (auto h : hash256_2) {
		cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	}
	cout << endl;

	for (auto h : hash224_2) {
		cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	}
	cout << endl;

	getchar();
	
    return 0;
}

