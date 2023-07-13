// Test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#include <Geek/Process/process.hpp>

bool  wxMemory(uint64_t raw_addr, char* addr, size_t size, void* arg)
{
	bool ret = false;
	uint64_t  key_offset = 0;
	//ooo//C1 50 F7 67 44 AC 4E 63 91 F9 AD 5E A6 5F C3 9A D0 C9 9A 53 2D E2 48 1E AD 6C 48 33 C8 11 E6 1B
#define FEATURE_LEN 60//, 0x01, 0x00, 0x00, 0x00
	unsigned char keyFeature[FEATURE_LEN] = {
		0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	DWORD j = 0, n = 0;
	int isDiff = 0;
	for (j = 0; j < size - FEATURE_LEN; j++)
	{
		isDiff = 0;
		for (n = 0; n < FEATURE_LEN; n++) {
			if (keyFeature[n] != addr[j + n]) {
				isDiff = 1;
				break;
			}
		}
		if (isDiff == 0)
		{
			printf("match....\n");
			memcpy(&n, &addr[j + FEATURE_LEN + 12], 4);
			if (n == 0x20) {
				//key_offset = (DWORD)MemInfo.BaseAddress + j + FEATURE_LEN + 8 - base;
				memcpy(&key_offset, &addr[j + FEATURE_LEN + 4], 8);
				printf("key_offset=%x\n", key_offset);
				ret = true;
				break;
			}
		}
	}
	return ret;
}

int main()
{
	Geek::Process process;
	process.Open(L"WeChat.exe");
	process.ScanMemoryBlocks(wxMemory, NULL, true);


    std::cout << "Hello World!\n";
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
