// MyCryptTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "gtest/gtest.h"

int main(int argc, char *argv[])
{
	::testing::InitGoogleTest(&argc, argv);
	auto res = RUN_ALL_TESTS();
	getchar();
	return res;
}

