
#include <fstream>
#include <iostream>
#include <regex>
#include <vector>
#include <string>
#include <sstream>

#include <geek/utils/searcher.h>
#include <geek/utils/file.h>
#include <geek/process/process.h>

#include <geek/hook/inline_hook.h>
#include <geek/asm/assembler.h>

#include <geek/asm/disassembler.h>

using namespace geek;

const unsigned char hexData[240] = {
	0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
	0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00,
	0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
	0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
	0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
	0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x1D, 0x11, 0x45, 0x14, 0x59, 0xDC, 0xCE, 0xC8, 0x59, 0xDC, 0xCE, 0xC8, 0x59, 0xDC, 0xCE, 0xC8,
	0x49, 0x58, 0xCF, 0xC9, 0x5A, 0xDC, 0xCE, 0xC8, 0x49, 0x58, 0xCD, 0xC9, 0x5A, 0xDC, 0xCE, 0xC8,
	0x49, 0x58, 0xCA, 0xC9, 0x53, 0xDC, 0xCE, 0xC8, 0x49, 0x58, 0xCB, 0xC9, 0x4E, 0xDC, 0xCE, 0xC8,
	0x12, 0xA4, 0xCF, 0xC9, 0x5D, 0xDC, 0xCE, 0xC8, 0x59, 0xDC, 0xCF, 0xC8, 0x1C, 0xDC, 0xCE, 0xC8,
	0x12, 0x59, 0xCB, 0xC9, 0x58, 0xDC, 0xCE, 0xC8, 0x12, 0x59, 0x31, 0xC8, 0x58, 0xDC, 0xCE, 0xC8,
	0x12, 0x59, 0xCC, 0xC9, 0x58, 0xDC, 0xCE, 0xC8, 0x52, 0x69, 0x63, 0x68, 0x59, 0xDC, 0xCE, 0xC8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x08, 0x00
};

void Origin()
{
	int i = 0;
	i = 1;
	i = 2;
	i = 4;
	printf("Origin\n");
	printf("Origin\n");
	printf("Origin\n");
}

bool Hooked(InlineHook::HookContextX64* ctx)
{
	printf("Hooked\n");
	return true;
}

//#include <asmjit/asmjit.h>
//#include <iostream>
//
//using namespace asmjit;
//
//int main() {
//	// 创建 JitRuntime 运行时环境
//	JitRuntime runtime;
//
//	// 创建 CodeHolder 并初始化
//	CodeHolder code;
//	code.init(runtime.environment());
//
//	// 创建汇编器并绑定到 CodeHolder
//	x86::Assembler assembler(&code);
//
//	// 编写汇编代码：int add(int a, int b) { return a + b; }
//	assembler.mov(x86::eax, x86::ecx);   // 将第一个参数 (ecx) 移动到 eax
//	assembler.add(x86::eax, x86::edx);   // 将第二个参数 (edx) 加到 eax
//	assembler.ret();                     // 返回
//
//	// 定义函数指针类型
//	typedef int (*AddFunc)(int, int);
//	AddFunc addFunc;
//
//	// 将生成的代码映射到可执行内存，并获取函数指针
//	Error err = runtime.add(&addFunc, &code);
//	if (err) {
//		std::cerr << "Error: " << DebugUtils::errorAsString(err) << std::endl;
//		return 1;
//	}
//
//	// 调用生成的函数
//	int result = addFunc(5, 3);
//	std::cout << "Result of 5 + 3 = " << result << std::endl;  // 输出：Result of 5 + 3 = 8
//
//	// 释放 JIT 生成的函数
//	runtime.release(addFunc);
//
//	return 0;
//}


class MyClass
{
public:
	MyClass(
		int a1,
		int a2,
		int a3,
		int a4)
		: a1_(a1)
		, a2_(a2)
		, a3_(a3)
		, a4_(a4)
	{

	}


	~MyClass();

private:
	int a1_;
	int a2_;
	int a3_;
	int a4_;
};


int jjjbb = 0;

int main() {
	// auto a = Assembler(Arch::kX86);								// 实例化一个汇编器
	//
	// auto label = a.NewLabel();									// 分配一个标签
	//
	// a.mov(asm_reg::eax, 0x114514);
	// a.mov(asm_reg::eax, asm_reg::ebx);
	// a.lea(asm_reg::edx, asm_op::ptr_abs((intptr_t) & jjjbb));	// 取绝对地址
	// a.Bind(label);												// 绑定标签（可以像goto那样用）
	// a.mov(asm_reg::ecx, asm_op::ptr(0x3333));					// 取内存（相对当前指令）
	// a.sub(asm_reg::al, 123);
	// a.jmp(label);												// 跳到标签
	// a.push(asm_reg::ebp);
	// a.pop(asm_reg::edi);
	//
	// auto c = a.PackCode();					// 打包硬编码
	//
	// // 实例化一个反汇编器，设为64位
	// auto da = DisAssembler(DisAssembler::MachineMode::kLong64, DisAssembler::StackWidth::k64);
	// da.SetCodeData(c);						// 设置硬编码缓冲区
	// da.Config().runtime_address = 0x1000;	// 设置指令初始地址
	// // 遍历解析的指令
	// for (auto& inst : da.DecodeInstructions()) {
	// 	std::cout << inst.SimpleFormat() << std::endl;
	// }

	// auto m = geek::ThisProc().Modules().FindByModuleName(L"example.exe");
	//
	// hexData[0];
	//
	// auto res = geek::ThisProc().SearchSig("11 45 14", m.DllBase(), m.SizeOfImage());
	//
	// for (auto o : res)
	// {
	// 	printf("%llx - %llx\n", o, *reinterpret_cast<const uint64_t*>(o));
	// }

	Origin();
	InlineHook::InstallX64(&ThisProc(), (size_t)Origin, Hooked);
	Origin();
}

// auto dir = geek::File::GetAppDirectory();
// auto proc_opt = geek::Process::Open(L"C:\\Windows\\notepad.exe", PROCESS_ALL_ACCESS);
// if (!proc_opt.has_value())
// {
// 	auto opt = geek::Process::Create(L"C:\\Windows\\notepad.exe");
// 	if (!opt.has_value())
// 	{
// 		return -1;
// 	}
// 	proc_opt = { std::move(std::get<0>(opt.value())) };
// }
// auto proc = std::move(proc_opt.value());