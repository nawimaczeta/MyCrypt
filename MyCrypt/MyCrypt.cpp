// MyCrypt.cpp : Defines the entry point for the console application.
//

#include <memory>
#include <iostream>
#include <string>
#include <iomanip>

#include "stdafx.h"
#include "hash/SHAHash.h"
#include "stream/RC4Stream.h"

using namespace std;

int main()
{
	RC4Stream rc4;
	Bytes _key{ 0x01, 0x02, 0x03, 0x04, 0x05 };
	Bytes input(0x1000);
	rc4.setKey(_key);
	rc4.processBuffer(input);

	//RC4Stream rc4;
	//Bytes key{ 'K', 'e', 'y' };
	//Bytes input{ 'P', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't' };
	//rc4.setKey(key);
	//rc4.processBuffer(input);

	//RC4Stream rc4_2;
	//Bytes key_2{ 'W', 'i', 'k', 'i' };
	//Bytes input_2{ 'p', 'e', 'd', 'i', 'a' };
	//rc4_2.setKey(key_2);
	//rc4_2.processBuffer(input_2);

	//RC4Stream rc4_3;
	//Bytes key_3{ 'K', 'e', 'y' };
	//Bytes input_3{ 'P', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't' };
	//Bytes output_3(input.size());
	//rc4_3.setKey(key_3);
	//rc4_3.processBuffer(input_3, output_3);

	////string s{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" };
	//string s{ "abc" };
	//vector<uint8_t> in;
	//copy(begin(s), end(s), back_inserter(in));

	//cout << "Input data: \n" << s << "\n";
	//cout << "HAsh:\n";

	//auto hash256_1 = HashFactory::Get(HashAlgorythm::SHA256)->compute(in);
	////auto hash224_1 = HashFactory::Get(HashAlgorythm::SHA224)->compute(in);
	//auto hash512_1 = HashFactory::Get(HashAlgorythm::SHA512)->compute(in);

	//cout << "SHA224 ";
	//for (auto h : hash256_1) {
	//	cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	//}
	//cout << endl;

	////cout << "SHA256 ";
	////for (auto h : hash224_1) {
	////	cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	////}
	//cout << endl;

	//cout << "SHA512 ";
	//for (auto h : hash512_1) {
	//	cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	//}
	//cout << endl;
	//
	//auto sha256 = HashFactory::Get(HashAlgorythm::SHA256);
	//auto sha224 = HashFactory::Get(HashAlgorythm::SHA224);

	//*sha256 << in;
	//*sha224 << in;
	//auto hash256_2 = sha256->finalize();
	//auto hash224_2 = sha224->finalize();

	//for (auto h : hash256_2) {
	//	cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	//}
	//cout << endl;

	//for (auto h : hash224_2) {
	//	cout << setw(2) << setfill('0') << hex << static_cast<int>(h);
	//}
	//cout << endl;

	getchar();
	
    return 0;
}

