#include <assert.h>
#include <geek/hook/inline_hook.h>

#include <unordered_map>

#include <geek/process/process.h>
#include <geek/asm/assembler.h>
#include "insn_len.h"


#define GET_CURRENT_ADDR { 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x8c, 0xc0, 0x05 }         // call next;    next: pop eax/rax;    add eax/rax, 5;


#define GET_KERNEL32_IMAGE_BASE { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x0C, 0x8B, 0x00, 0x8B, 0x00, 0x8B, 0x40, 0x18 }
/* 定位kernel32
mov eax, dword ptr fs : [30h]     ;指向PEB结构
mov eax, dword ptr[eax + 0Ch]     ;指向LDR Ptr32 _PEB_LDR_DATA
mov eax, dword ptr[eax + 0Ch]     ;指向InLoadOrderModuleList _LIST_ENTRY
mov eax, dword ptr[eax]         ;移动_LIST_ENTRY
mov eax, dword ptr[eax]         ;指向Kernel32
mov eax, dword ptr[eax + 18h]     ;指向DllBase基址
;ret
*/


namespace geek {
using namespace asm_reg;
namespace {
int64_t GetInstrOffset(uint64_t instr_addr, size_t instr_size, uint64_t dst_addr) {
	return dst_addr - instr_addr - instr_size;
}

// 生成跳转到指定地址的指令
uint64_t MakeJmp(Arch arch, std::vector<uint8_t>* buf, uint64_t cur_addr, uint64_t jmp_addr) {
	switch (arch) {
	case Arch::kX86: {
		if (buf->size() < 5) {
			buf->resize(5);
		}
		buf->operator[](0) = 0xe9;        // jmp
		*(uint32_t*)&buf->operator[](1) = GetInstrOffset(cur_addr, 5, jmp_addr);

		for (int i = 5; i < buf->size(); i++) {
			buf->operator[](i) = 0xcc;        // int 3
		}
		break;
	}
	case Arch::kX64: {
		if (buf->size() < 14) buf->resize(14);
		buf->operator[](0) = 0x68;        // push low_addr
		*(uint32_t*)&buf->operator[](1) = (uint64_t)jmp_addr & 0xffffffff;
		buf->operator[](5) = 0xc7;        // mov dword ptr ss:[rsp+4], high_addr
		buf->operator[](6) = 0x44;
		buf->operator[](7) = 0x24;
		buf->operator[](8) = 0x04;
		*(uint32_t*)&buf->operator[](9) = (uint64_t)jmp_addr >> 32;
		buf->operator[](13) = 0xc3;        // ret

		for (int i = 14; i < buf->size(); i++) {
			buf->operator[](i) = 0xcc;        // int 3
		}
		break;
	}
	}
	return buf->size();
}

// 生成构建栈帧的指令
// 会使用rdi寄存器
void MakeStackFrameStart(Assembler& a, uint8_t size)
{
	size_t i = 0;
	switch (a.GetArch()) {
	case Arch::kX86: {
		break;
	}
	case Arch::kX64: {
		// 构建栈帧
		a.sub(rsp, size);
		// 强制使栈16字节对齐
		a.mov(rdi, rsp);
		a.and_(rdi, 0x8);
		a.sub(rsp, rdi);
		break;
	}
	}
}

// 生成结束栈帧的指令
void MakeStackFrameEnd(Assembler& a, int8_t size)
{
	switch (a.GetArch()) {
	case Arch::kX86: {
		break;
	}
	case Arch::kX64: {
		a.add(rsp, rdi);
		a.add(rsp, size);
		break;
	}
	}
}

// 生成TlsSetValue的指令
// X86:会使用rax，要求value已经推到栈中
// X64:会使用rcx，rax，要求value放在rdx中，且已经构建好栈帧
void MakeTlsSetValue(Assembler& a, uint32_t tls_id)
{
	switch (a.GetArch()) {
	case Arch::kX86: {
		a.push(tls_id);
		a.mov(eax, TlsSetValue);
		a.call(rax);
		break;
	}
	case Arch::kX64: {
		a.mov(rcx, tls_id);
		a.mov(rax, TlsSetValue);
		a.call(rax);
		break;
	}
	}
}

// 生成TlsGetValue的指令
// 会使用rcx，rax，要求已经构建好栈帧
void MakeTlsGetValue(Assembler& a, uint32_t tls_id)
{
	switch (a.GetArch()) {
	case Arch::kX86: {
		a.push(tls_id);
		a.mov(eax, TlsGetValue);
		a.call(rax);
		break;
	}
	case Arch::kX64: {
		a.mov(rcx, tls_id);
		a.mov(rax, TlsGetValue);
		a.call(rax);
		break;
	}
	}
}
}

InlineHook::InlineHook(const Process* process) :
	process_{ process }
{
}

std::optional<InlineHook> InlineHook::InstallEx(
	const Process* proc,
	uint64_t hook_addr,
	uint64_t callback,
	Arch arch,
	size_t instr_size,
	bool save_volatile_register,
	uint64_t forward_page_size)
{
	InlineHook hook{ proc };

	hook.tls_id_ = TlsAlloc();
	if (hook.tls_id_ == TLS_OUT_OF_INDEXES) {
		return std::nullopt;
	}

	if (forward_page_size < 0x1000) {
		forward_page_size = 0x1000;
	}

	if (instr_size > 255) {
		return std::nullopt;
	}


	auto forward_page_res = hook.process_->AllocMemory(NULL, forward_page_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!forward_page_res) {
		return std::nullopt;
	}

	hook.forward_page_ = forward_page_res.value();

	// 处理转发页面指令
	std::vector<uint8_t> forward_page(forward_page_size, 0);
	auto forward_page_temp = forward_page.data();

	uint64_t forward_page_uint = (uint64_t)hook.forward_page_;

	std::vector<uint8_t> temp(64);
	if (!hook.process_->ReadMemory(hook_addr, temp.data(), 64)) {
		return std::nullopt;
	}

	if (instr_size == 0) {
		if (arch == Arch::kX86) {
			while (instr_size < 5) {
				instr_size += insn_len_x86_32(&temp[instr_size]);
			}
		} else {
			while (instr_size < 14) {
				instr_size += insn_len_x86_64(&temp[instr_size]);
			}
		}
	}

	// 保存原指令
	hook.old_instr_.resize(instr_size);
	if (!hook.process_->ReadMemory(hook_addr, hook.old_instr_.data(), instr_size)) {
		return std::nullopt;
	}

	if (arch == Arch::kX86) {
		// if (instr_size < 5) {
		// 	return std::nullopt;
		// }
		//
		// size_t i = 0;
		// uint32_t context_addr;
		//
		// // 可重入与线程安全的处理
		// {
		// 	// 保存原寄存器
		// 	forward_page_temp[i++] = 0x50;        // push eax
		// 	forward_page_temp[i++] = 0x51;        // push ecx
		// 	forward_page_temp[i++] = 0x52;        // push edx
		// 	forward_page_temp[i++] = 0x9c;        // pushfd
		//
		// 	// 获取TlsValue
		// 	i += MakeTlsGetValue(arch, &forward_page_temp[i], hook.tls_id_);
		//
		//
		// 	// 判断是否重入
		// 	// cmp eax, 0
		// 	forward_page_temp[i++] = 0x83;
		// 	forward_page_temp[i++] = 0xf8;
		// 	forward_page_temp[i++] = 0x00;
		// 	// je _next
		// 	forward_page_temp[i++] = 0x74;
		// 	forward_page_temp[i++] = 4 + hook.old_instr_.size() + 5;
		//
		// 	// 低1位为1，是重入，执行原指令并转回
		// 	forward_page_temp[i++] = 0x9d;        // popfd
		// 	forward_page_temp[i++] = 0x5a;        // pop rdx
		// 	forward_page_temp[i++] = 0x59;        // pop rcx
		// 	forward_page_temp[i++] = 0x58;        // pop rax
		//
		// 	memcpy(&forward_page_temp[i], hook.old_instr_.data(), hook.old_instr_.size());
		// 	i += hook.old_instr_.size();
		//
		// 	// 跳回原函数正常执行
		// 	std::vector<uint8_t> temp;
		// 	MakeJmp(arch, &temp, forward_page_uint + i, hook_addr + instr_size);
		// 	memcpy(&forward_page_temp[i], &temp[0], temp.size());
		// 	i += temp.size();
		//
		//
		// 	// _next:
		// 	// 设置为1
		// 	// call TlsSetValue
		// 	// push 1
		// 	forward_page_temp[i++] = 0x6a;
		// 	forward_page_temp[i++] = 0x01;
		// 	i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);
		//
		// 	forward_page_temp[i++] = 0x9d;        // popfq
		// 	forward_page_temp[i++] = 0x5a;        // pop rdx
		// 	forward_page_temp[i++] = 0x59;        // pop rcx
		// 	forward_page_temp[i++] = 0x58;        // pop rax
		// }
		//
		// // sub rsp, 400
		// forward_page_temp[i++] = 0x81;
		// forward_page_temp[i++] = 0xec;
		// *(uint32_t*)&forward_page_temp[i] = 0x400;
		// i += 4;
		//
		// // 构建context_addr
		// {
		// 	forward_page_temp[i++] = 0x50;        // push eax
		// 	forward_page_temp[i++] = 0x51;        // push ecx
		//
		// 	// lea ecx, [esp+0x8]
		// 	forward_page_temp[i++] = 0x8d;
		// 	forward_page_temp[i++] = 0x4c;
		// 	forward_page_temp[i++] = 0x24;
		// 	forward_page_temp[i++] = 0x8;
		//
		// 	// 压入原stack，跳过前面push的eax和ecx
		// 	// lea eax, [esp+0x400+0x8]
		// 	forward_page_temp[i++] = 0x8d;
		// 	forward_page_temp[i++] = 0x84;
		// 	forward_page_temp[i++] = 0x24;
		// 	*(uint32_t*)&forward_page_temp[i] = (uint32_t)0x400 + 8;
		// 	i += 4;
		//
		// 	// mov [ecx], eax
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x01;
		//
		// 	// 实际上是压入esp
		// 	// mov [ecx+4], eax
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x41;
		// 	forward_page_temp[i++] = 0x04;
		//
		//
		// 	// mov eax, hook_addr + instr_size
		// 	forward_page_temp[i++] = 0xb8;
		// 	*(uint32_t*)&forward_page_temp[i] = (uint32_t)hook_addr + instr_size;
		// 	i += 4;
		// 	// mov [ecx+0x8], eax
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x41;
		// 	forward_page_temp[i++] = 0x8;
		//
		// 	// mov eax, forward_page
		// 	forward_page_temp[i++] = 0xb8;
		// 	*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint;
		// 	i += 4;
		// 	// mov [ecx+0xc], rax
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x41;
		// 	forward_page_temp[i++] = 0xc;
		//
		// 	// mov eax, hook_addr
		// 	forward_page_temp[i++] = 0xb8;
		// 	*(uint32_t*)&forward_page_temp[i] = (uint32_t)hook_addr;
		// 	i += 4;
		// 	// mov [ecx+0x10], eax
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x41;
		// 	forward_page_temp[i++] = 0x10;
		//
		// 	// pop eax      // 这里其实是ecx
		// 	forward_page_temp[i++] = 0x58;
		// 	// mov [ecx+0x44], eax
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x41;
		// 	forward_page_temp[i++] = 0x44;
		//
		// 	// pop eax
		// 	forward_page_temp[i++] = 0x58;
		// 	// mov [ecx+0x40], eax
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x41;
		// 	forward_page_temp[i++] = 0x40;
		//
		// 	// mov [ecx+0x48], edx
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x51;
		// 	forward_page_temp[i++] = 0x48;
		//
		// 	// mov [ecx+0x4c], ebx
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x59;
		// 	forward_page_temp[i++] = 0x4c;
		//
		// 	// mov [ecx+0x50], esp
		// 	//forward_page_temp[i++] = 0x89;
		// 	//forward_page_temp[i++] = 0x61;
		// 	//forward_page_temp[i++] = 0x50;
		//
		// 	// mov [ecx+0x54], ebp
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x69;
		// 	forward_page_temp[i++] = 0x54;
		//
		// 	// mov [ecx+0x58], esi
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x71;
		// 	forward_page_temp[i++] = 0x58;
		//
		// 	// mov [ecx+0x5c], edi
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x79;
		// 	forward_page_temp[i++] = 0x5c;
		//
		// 	forward_page_temp[i++] = 0x9c;        // pushfd
		// 	forward_page_temp[i++] = 0x58;        // pop eax
		// 	// mov [ecx+0x60], eax
		// 	forward_page_temp[i++] = 0x89;
		// 	forward_page_temp[i++] = 0x41;
		// 	forward_page_temp[i++] = 0x60;
		//
		// }
  //           
		//
		// // ecx保存到非易失寄存器
		// // mov esi, ecx
		// forward_page_temp[i++] = 0x89;
		// forward_page_temp[i++] = 0xce;
		//
		// // 准备调用
		// // 传递参数
		// // 使用fastcall，参数已在ecx中
		//
		// forward_page_temp[i++] = 0xe8;        // call callback
		// *(uint32_t*)&forward_page_temp[i] = GetInstrOffset((forward_page_uint + i - 1), 5, callback);
		// i += 4;
		//
		// // mov ecx, esi     // 再次拿到context
		// forward_page_temp[i++] = 0x89;
		// forward_page_temp[i++] = 0xf1;
		//
		// // 先把callback返回值保存起来
		// // mov [ecx + 0x280 + 0], al
		// forward_page_temp[i++] = 0x88;
		// forward_page_temp[i++] = 0x81; 
		// *(uint32_t*)&forward_page_temp[i] = (uint32_t)0x280 + 0;
		// i += 4;
		//
		// // 将jmp_addr保存到tls中
		// // push [ecx+0x8]
		// forward_page_temp[i++] = 0xff;
		// forward_page_temp[i++] = 0x71;
		// forward_page_temp[i++] = 0x8;
		// i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);
		//
		// // 恢复上下文环境
		// // 除ecx和eax
		// {
		// 	// mov eax, [ecx + 0x60]
		// 	forward_page_temp[i++] = 0x8b;
		// 	forward_page_temp[i++] = 0x41;
		// 	forward_page_temp[i++] = 0x60;
		//
		// 	forward_page_temp[i++] = 0x50;        // push eax
		// 	forward_page_temp[i++] = 0x9d;        // popfd
		//
		// 	// mov edx, [ecx + 0x48]
		// 	forward_page_temp[i++] = 0x8b;
		// 	forward_page_temp[i++] = 0x51;
		// 	forward_page_temp[i++] = 0x48;
		//
		// 	// mov ebx, [ecx + 0x4c]
		// 	forward_page_temp[i++] = 0x8b;
		// 	forward_page_temp[i++] = 0x59;
		// 	forward_page_temp[i++] = 0x4c;
		//
		// 	// mov esp, [ecx + 0x50]
		// 	//forward_page_temp[i++] = 0x8b;
		// 	//forward_page_temp[i++] = 0x61;
		// 	//forward_page_temp[i++] = 0x50;
		//
		// 	// mov ebp, [ecx + 0x54]
		// 	forward_page_temp[i++] = 0x8b;
		// 	forward_page_temp[i++] = 0x69;
		// 	forward_page_temp[i++] = 0x54;
		//
		// 	// mov esi, [ecx + 0x58]
		// 	forward_page_temp[i++] = 0x8b;
		// 	forward_page_temp[i++] = 0x71;
		// 	forward_page_temp[i++] = 0x58;
		//
		// 	// mov edi, [ecx + 0x5c]
		// 	forward_page_temp[i++] = 0x8b;
		// 	forward_page_temp[i++] = 0x79;
		// 	forward_page_temp[i++] = 0x5c;
		// }
  //           
		//
		// // 在原指令执行前还原所有环境，包括压入的jmp_addr
		//
		// // 执行前设置hook回调中可能修改的esp
		// // mov esp, [ecx + 4]
		// forward_page_temp[i++] = 0x8b;
		// forward_page_temp[i++] = 0x61;
		// forward_page_temp[i++] = 0x04;
		//
  //           
		// // 拿到callback的返回值
		// // mov al, [ecx + 0x280 + 0]
		// forward_page_temp[i++] = 0x8a;
		// forward_page_temp[i++] = 0x81;
		// *(uint32_t*)&forward_page_temp[i] = (uint32_t)0x280 + 0;
		// i += 4;
		//
  //           
		// forward_page_temp[i++] = 0x9c;      // pushfd
		// // cmp al, 0
		// forward_page_temp[i++] = 0x3c;
		// forward_page_temp[i++] = 0x00;
		//
		// // 上面的恢复上下文还没有恢复eax和ecx，这里再恢复eax和ecx
		// // mov eax, [ecx + 0x44]        // 这里原ecx先保存到eax
		// forward_page_temp[i++] = 0x8b;
		// forward_page_temp[i++] = 0x81;
		// *(uint32_t*)&forward_page_temp[i] = 0x44;
		// i += 4;
		// // push eax     // 现在原ecx已经再栈上了
		// forward_page_temp[i++] = 0x50;
		//
		// // mov eax, [ecx + 0x40]
		// forward_page_temp[i++] = 0x8b;
		// forward_page_temp[i++] = 0x81;
		// *(uint32_t*)&forward_page_temp[i] = 0x40;
		// i += 4;
		//
		// // pop ecx      // 恢复原ecx
		// forward_page_temp[i++] = 0x59;
		//
		//
		// // je _skip_exec_old_insrt
		// forward_page_temp[i++] = 0x74;
		// forward_page_temp[i++] = 1 + hook.old_instr_.size() + 2;
		//
		// forward_page_temp[i++] = 0x9d;      // popfd
		// // 执行原指令
		// memcpy(&forward_page_temp[i], hook.old_instr_.data(), hook.old_instr_.size());
		// i += hook.old_instr_.size();
		// // jmp _next_exec_old_insrt
		// forward_page_temp[i++] = 0xeb;
		// forward_page_temp[i++] = 0x01;      // +1
		//
		// // _skip_exec_old_insrt:
		// forward_page_temp[i++] = 0x9d;      // popfd
		// // _next_exec_old_insrt:
  //           
		//
		// // push eax     // 预留一个栈位置，存放jmp_addr
		// forward_page_temp[i++] = 0x50;
		// forward_page_temp[i++] = 0x50;      // push eax
		// forward_page_temp[i++] = 0x51;      // push ecx
		//
		//
		//
		// // 恢复jmp_addr环境
		//
		// // 从Tls中获取jmp_addr
		// i += MakeTlsGetValue(arch, &forward_page_temp[i], hook.tls_id_);
		//
		//
		// // 刚刚预留的栈位置，放入jmp_addr，即下面ret返回的地址
		// // mov [esp+0x08], eax
		// forward_page_temp[i++] = 0x89;
		// forward_page_temp[i++] = 0x44;
		// forward_page_temp[i++] = 0x24;
		// forward_page_temp[i++] = 0x08;
		//
		// // 解锁
		// {
		// 	// 设置为0
		// 	// call TlsSetValue
		// 	// push 0
		// 	forward_page_temp[i++] = 0x6a;
		// 	forward_page_temp[i++] = 0x00;
		// 	i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);
		// }
		//
		// forward_page_temp[i++] = 0x59;      // pop ecx
		// forward_page_temp[i++] = 0x58;      // pop eax
		//
		// // 转回去继续执行
		// forward_page_temp[i++] = 0xc3;        // ret
	}
	else {
		if (instr_size < 14) {
			return std::nullopt;
		}
		auto a = Assembler(Arch::kX64);
		auto next_lab = a.NewLabel();

		// 保存原寄存器
		a.push(rax);
		a.push(rcx);
		a.push(rdx);
		a.push(rdi);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.pushfq();
		MakeStackFrameStart(a, 0x20);
		// 获取TlsValue
		MakeTlsGetValue(a, hook.tls_id_);
		// 判断是否重入
		a.cmp(rax, 0);
		a.je(next_lab);
		MakeStackFrameEnd(a, 0x20);
		a.popfq();
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.pop(rdi);
		a.pop(rdx);
		a.pop(rcx);
		a.pop(rax);

		// 跳回原函数正常执行
		for (size_t i_ = 0; i_ < hook.old_instr_.size(); ++i_)
			a.db(hook.old_instr_[i_]);

		a.jmp(hook_addr + instr_size);

		a.bind(next_lab);
		a.mov(rdx, 1);
		MakeTlsSetValue(a, hook.tls_id_);
		MakeStackFrameEnd(a, 0x20);

		a.popfq();
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.pop(rdi);
		a.pop(rdx);
		a.pop(rcx);
		a.pop(rax);

		a.sub(rsp, 0x400);

		a.push(rax);
		a.push(rcx);
		a.lea(rcx, ptr(rsp, 0x10));
		// 压入原stack，跳过前面push的rax和rcx
		a.lea(rax, ptr(rsp, 0x400 + 0x10));
		a.mov(ptr(rcx), rax);
		// 实际上是压入rsp
		a.mov(ptr(rcx, 8), rax);
		// 提前压入转回地址，以便HookCallback能够修改
		a.mov(rax, hook_addr + instr_size);
		a.mov(ptr(rcx, 0x10), rax);
		a.mov(rax, forward_page_uint);
		a.mov(ptr(rcx, 0x18), rax);
		a.mov(rax, hook_addr);
		a.mov(ptr(rcx, 0x20), rax);
		// 这里其实是rcx
		a.pop(rax);
		a.mov(ptr(rcx, 0x88), rax);
		a.pop(rax);
		a.mov(ptr(rcx, 0x80), rax);
		a.mov(ptr(rcx, 0x90), rdx);
		a.mov(ptr(rcx, 0x98), rbx);
		a.mov(ptr(rcx, 0xA8), rbp);
		a.mov(ptr(rcx, 0xB0), rsi);
		a.mov(ptr(rcx, 0xB8), rdi);
		a.mov(ptr(rcx, 0xC0), r8);
		a.mov(ptr(rcx, 0xC8), r9);
		a.mov(ptr(rcx, 0xD0), r10);
		a.mov(ptr(rcx, 0xD8), r11);
		a.mov(ptr(rcx, 0xE0), r12);
		a.mov(ptr(rcx, 0xE8), r13);
		a.mov(ptr(rcx, 0xF0), r14);
		a.mov(ptr(rcx, 0xF8), r15);
		a.pushfq();
		a.pop(rax);
		a.mov(ptr(rcx, 0x100), rax);

		// 遵循x64调用约定，为当前函数的使用提前分配栈空间
		MakeStackFrameStart(a, 0x20);

		// 参数即rcx，在保存上下文时已经设置了
		// 将context保存到非易失寄存器
		a.mov(rsi, rcx);
		// 调用
		a.mov(rax, callback);
		a.call(rax);
		// 再次拿到context
		a.mov(rcx, rsi);
		// 先保存callback的返回值
		a.mov(ptr(rcx, 0x280), al);
		// 将jmp_addr保存到tls中
		a.mov(rdx, ptr(rcx, 0x10));
		MakeTlsSetValue(a, hook.tls_id_);
		// 再次拿到context
		a.mov(rcx, rsi);

		MakeStackFrameEnd(a, 0x20);

		// 恢复上下文环境
		// 除rcx和rax
		a.mov(rax, ptr(rcx, 0x100));
		a.push(rax);
		a.popfq();
		a.mov(rdx, ptr(rcx, 0x90));
		a.mov(rbx, ptr(rcx, 0x98));
		a.mov(rbp, ptr(rcx, 0xA8));
		a.mov(rsi, ptr(rcx, 0xB0));
		a.mov(rdi, ptr(rcx, 0xB8));
		a.mov(r8, ptr(rcx, 0xC0));
		a.mov(r9, ptr(rcx, 0xC8));
		a.mov(r10, ptr(rcx, 0xD0));
		a.mov(r11, ptr(rcx, 0xD8));
		a.mov(r12, ptr(rcx, 0xE0));
		a.mov(r13, ptr(rcx, 0xE8));
		a.mov(r14, ptr(rcx, 0xF0));
		a.mov(r15, ptr(rcx, 0xF8));

		// 在原指令执行前还原所有环境，包括保存的jmp_addr
		// 执行前设置hook回调中可能修改的rsp
		a.mov(rax, ptr(rcx, 8));
		a.mov(rsp, rax);

		// 准备执行原指令
		// 拿到callback的返回值
		a.mov(al, ptr(rcx, 0x280));
		a.pushfq();
		a.cmp(al, 0);

		// 上面的恢复上下文环境还没有恢复rax和rcx，这里再恢复rax和rcx
		a.mov(rax, ptr(rcx, 0x88));		// 原rcx先保存到rax
		a.push(rax);					// 现在原rcx已经在栈上了
		a.mov(rax, ptr(rcx, 0x80));
		a.pop(rcx);						// 恢复原rcx

		auto skip_exec_old_insrt_lab = a.NewLabel();
		auto next_exec_old_insrt_lab = a.NewLabel();

		a.je(skip_exec_old_insrt_lab);
		a.popfq();
		// 执行原指令
		for (size_t i_ = 0; i_ < hook.old_instr_.size(); ++i_)
			a.db(hook.old_instr_[i_]);
		a.jmp(next_exec_old_insrt_lab);

		a.bind(skip_exec_old_insrt_lab);

		a.popfq();

		a.bind(next_exec_old_insrt_lab);

		a.push(rax);					// 预留一个栈位置，存放jmp_addr
		a.push(rax);
		a.push(rcx);
		a.push(rdx);
		a.push(rdi);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);

		MakeStackFrameStart(a, 0x20);

		// 恢复jmp_addr环境
		// 从Tls中获取jmp_addr
		MakeTlsGetValue(a, hook.tls_id_);
		a.mov(qword_ptr(rsp, rdi, 0, 0x60), rax);	// 刚刚预留的栈位置，放入jmp_addr，即下面ret返回的地址

		// 即将退出
		a.mov(rdx, 0);
		MakeTlsSetValue(a, hook.tls_id_);
		MakeStackFrameEnd(a, 0x20);

		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.pop(rdi);
		a.pop(rdx);
		a.pop(rcx);
		a.pop(rax);
		a.ret();

		a.PackCodeTo(forward_page_temp, forward_page_size);
	}

	hook.process_->WriteMemory(hook.forward_page_, forward_page_temp, forward_page_size);

	// 为目标地址挂hook
	hook.hook_addr_ = hook_addr;


	std::vector<uint8_t> jmp_instr(instr_size);
	if (hook.process_->IsCurrent() &&
		(
			(arch == Arch::kX86 && instr_size <= 8) ||
			(arch == Arch::kX64 && instr_size <= 16)
		)
	) {
		DWORD old_protect;
		if (!hook.process_->SetMemoryProtect(hook_addr, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect)) {
			return std::nullopt;
		}
		// 通过原子指令进行hook，降低错误的概率
		bool success = true;

		if (arch == Arch::kX86) {
			MakeJmp(arch, &jmp_instr, hook_addr, hook.forward_page_);
			if (jmp_instr.size() < 8) {
				size_t old_size = jmp_instr.size();
				jmp_instr.resize(8);
				memcpy(&jmp_instr[old_size], ((uint8_t*)hook_addr) + old_size, 8 - old_size);
			}
			InterlockedExchange64((volatile long long*)hook_addr, *(LONGLONG*)&jmp_instr[0]);
		} else {
#ifdef _WIN64
			MakeJmp(arch, &jmp_instr, hook_addr, hook.forward_page_);
			if (jmp_instr.size() < 16) {
				size_t old_size = jmp_instr.size();
				jmp_instr.resize(16);
				memcpy(&jmp_instr[old_size], ((uint8_t*)hook_addr) + old_size, 16 - old_size);
			}
			uint8_t buf[16];
			memcpy(buf, (void*)hook_addr, 16);
			success = InterlockedCompareExchange128((volatile long long*)hook_addr, *(LONGLONG*)&jmp_instr[8], *(LONGLONG*)&jmp_instr[0], (long long*)buf);
#else
                success = false;
#endif
		}
		hook.process_->SetMemoryProtect(hook_addr, 0x1000, old_protect, &old_protect);
		if (success == false) return std::nullopt;
	}
	else {
		MakeJmp(arch, &jmp_instr, hook_addr, hook.forward_page_);
		hook.process_->WriteMemory(hook_addr, &jmp_instr[0], instr_size, true);
	}
	return hook;
}

std::optional<InlineHook> InlineHook::InstallX86Ex(
	const Process* proc,
	uint32_t hook_addr, 
	HookCallbackX86 callback, 
	size_t instr_size,
	bool save_volatile_register,
	uint64_t forward_page_size)
{
	return InstallEx(proc, hook_addr, reinterpret_cast<uint64_t>(callback), Arch::kX86, instr_size, save_volatile_register, forward_page_size);
}

std::optional<InlineHook> InlineHook::InstallX64Ex(
	const Process* proc,
	uint64_t hook_addr,
	HookCallbackX64 callback,
	size_t instr_size,
	bool save_volatile_register,
	uint64_t forward_page_size)
{
	return InstallEx(proc, hook_addr, reinterpret_cast<uint64_t>(callback), Arch::kX64, instr_size, save_volatile_register, forward_page_size);
}

namespace {
using CallbackX32 = std::function<bool(InlineHook::HookContextX86* ctx)>;
std::unordered_map<uint32_t, std::unordered_map<uint64_t, CallbackX32>> callbacks_x32;

using CallbackX64 = std::function<bool(InlineHook::HookContextX64* ctx)>;
std::unordered_map<uint32_t, std::unordered_map<uint64_t, CallbackX64>> callbacks_x64;

/**
 * function版install内部使用的callback
 * 转发给function
 */
bool __fastcall InstallX32Callback(InlineHook::HookContextX86* ctx)
{
	// 查找进程对应的回调列表
	auto cbs = callbacks_x32.find(GetCurrentProcessId());
	assert(cbs != callbacks_x32.end());
	// 根据hook地址找到对应的function
	auto c = cbs->second.find(ctx->hook_addr);
	assert(c != cbs->second.end());
	// 调用function
	return c->second(ctx);
}

bool InstallX64Callback(InlineHook::HookContextX64* ctx)
{
	// 查找进程对应的回调列表
	auto cbs = callbacks_x64.find(GetCurrentProcessId());
	assert(cbs != callbacks_x64.end());
	// 根据hook地址找到对应的function
	auto c = cbs->second.find(ctx->hook_addr);
	assert(c != cbs->second.end());
	// 调用function
	return c->second(ctx);
}
}

std::optional<InlineHook> InlineHook::InstallX86(
	const Process* proc,
	uint32_t hook_addr,
	std::function<bool(HookContextX86* ctx)>&& callback,
	size_t instr_size,
	bool save_volatile_register,
	uint64_t forward_page_size)
{
	// TODO 跨进程hook支持
	if (!proc->IsCurrent())
		throw std::exception("Cross-process hooks are not yet supported");

	// 把function加入回调函数表中
	callbacks_x32[proc->ProcId()].emplace(hook_addr, std::move(callback));
	return InstallX86Ex(proc, hook_addr, &InstallX32Callback, instr_size, save_volatile_register, forward_page_size);
}

std::optional<InlineHook> InlineHook::InstallX64(
	const Process* proc,
	uint64_t hook_addr, 
	std::function<bool(HookContextX64* ctx)>&& callback,
	size_t instr_size,
	bool save_volatile_register,
	uint64_t forward_page_size)
{
	// TODO 跨进程hook支持
	if (!proc->IsCurrent())
		throw std::exception("Cross-process hooks are not yet supported");

	// 把function加入回调函数表中
	callbacks_x64[proc->ProcId()].emplace(hook_addr, std::move(callback));
	return InstallX64Ex(proc, hook_addr, &InstallX64Callback, instr_size, save_volatile_register, forward_page_size);
}

std::optional<InlineHook> InlineHook::InstallX86(uint32_t hook_addr, std::function<bool(HookContextX86* ctx)>&& callback, size_t instr_size,
	bool save_volatile_register, uint64_t forward_page_size)
{
	return InstallX86(&ThisProc(), hook_addr, std::move(callback), instr_size, save_volatile_register, forward_page_size);
}

std::optional<InlineHook> InlineHook::InstallX64(uint64_t hook_addr, std::function<bool(HookContextX64* ctx)>&& callback,
	size_t instr_size, bool save_volatile_register, uint64_t forward_page_size)
{
	return InstallX64(&ThisProc(), hook_addr, std::move(callback), instr_size, save_volatile_register, forward_page_size);
}

void InlineHook::Uninstall()
{
	if (hook_addr_) {
		process_->WriteMemory(hook_addr_, old_instr_.data(), old_instr_.size(), true);
		hook_addr_ = 0;
	}
	if (forward_page_) {
		process_->FreeMemory(forward_page_);
		forward_page_ = 0;
	}
	

	if (tls_id_ != TLS_OUT_OF_INDEXES) {
		TlsFree(tls_id_);
	}
}
}
