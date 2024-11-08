#include <assert.h>
#include <geek/hook/inline_hook.h>

#include <unordered_map>

#include <geek/process/process.h>
#include <geek/asm/assembler.h>
#include "insn_len.h"


#define GET_CURRENT_ADDR { 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x8c, 0xc0, 0x05 }         // call next;    next: pop eax/rax;    add eax/rax, 5;


#define GET_KERNEL32_IMAGE_BASE { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x0C, 0x8B, 0x00, 0x8B, 0x00, 0x8B, 0x40, 0x18 }
/* ��λkernel32
mov eax, dword ptr fs : [30h]     ;ָ��PEB�ṹ
mov eax, dword ptr[eax + 0Ch]     ;ָ��LDR Ptr32 _PEB_LDR_DATA
mov eax, dword ptr[eax + 0Ch]     ;ָ��InLoadOrderModuleList _LIST_ENTRY
mov eax, dword ptr[eax]         ;�ƶ�_LIST_ENTRY
mov eax, dword ptr[eax]         ;ָ��Kernel32
mov eax, dword ptr[eax + 18h]     ;ָ��DllBase��ַ
;ret
*/


namespace geek {
using namespace asm_reg;
namespace {
int64_t GetInstrOffset(uint64_t instr_addr, size_t instr_size, uint64_t dst_addr) {
	return dst_addr - instr_addr - instr_size;
}

// ������ת��ָ����ַ��ָ��
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

// ���ɹ���ջ֡��ָ��
// ��ʹ��rdi�Ĵ���
void MakeStackFrameStart(Assembler& a, uint8_t size)
{
	size_t i = 0;
	switch (a.GetArch()) {
	case Arch::kX86: {
		break;
	}
	case Arch::kX64: {
		// ����ջ֡
		a.sub(rsp, size);
		// ǿ��ʹջ16�ֽڶ���
		a.mov(rdi, rsp);
		a.and_(rdi, 0x8);
		a.sub(rsp, rdi);
		break;
	}
	}
}

// ���ɽ���ջ֡��ָ��
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

// ����TlsSetValue��ָ��
// X86:��ʹ��rax��Ҫ��value�Ѿ��Ƶ�ջ��
// X64:��ʹ��rcx��rax��Ҫ��value����rdx�У����Ѿ�������ջ֡
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

// ����TlsGetValue��ָ��
// ��ʹ��rcx��rax��Ҫ���Ѿ�������ջ֡
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

	// ����ת��ҳ��ָ��
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

	// ����ԭָ��
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
		// // ���������̰߳�ȫ�Ĵ���
		// {
		// 	// ����ԭ�Ĵ���
		// 	forward_page_temp[i++] = 0x50;        // push eax
		// 	forward_page_temp[i++] = 0x51;        // push ecx
		// 	forward_page_temp[i++] = 0x52;        // push edx
		// 	forward_page_temp[i++] = 0x9c;        // pushfd
		//
		// 	// ��ȡTlsValue
		// 	i += MakeTlsGetValue(arch, &forward_page_temp[i], hook.tls_id_);
		//
		//
		// 	// �ж��Ƿ�����
		// 	// cmp eax, 0
		// 	forward_page_temp[i++] = 0x83;
		// 	forward_page_temp[i++] = 0xf8;
		// 	forward_page_temp[i++] = 0x00;
		// 	// je _next
		// 	forward_page_temp[i++] = 0x74;
		// 	forward_page_temp[i++] = 4 + hook.old_instr_.size() + 5;
		//
		// 	// ��1λΪ1�������룬ִ��ԭָ�ת��
		// 	forward_page_temp[i++] = 0x9d;        // popfd
		// 	forward_page_temp[i++] = 0x5a;        // pop rdx
		// 	forward_page_temp[i++] = 0x59;        // pop rcx
		// 	forward_page_temp[i++] = 0x58;        // pop rax
		//
		// 	memcpy(&forward_page_temp[i], hook.old_instr_.data(), hook.old_instr_.size());
		// 	i += hook.old_instr_.size();
		//
		// 	// ����ԭ��������ִ��
		// 	std::vector<uint8_t> temp;
		// 	MakeJmp(arch, &temp, forward_page_uint + i, hook_addr + instr_size);
		// 	memcpy(&forward_page_temp[i], &temp[0], temp.size());
		// 	i += temp.size();
		//
		//
		// 	// _next:
		// 	// ����Ϊ1
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
		// // ����context_addr
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
		// 	// ѹ��ԭstack������ǰ��push��eax��ecx
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
		// 	// ʵ������ѹ��esp
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
		// 	// pop eax      // ������ʵ��ecx
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
		// // ecx���浽����ʧ�Ĵ���
		// // mov esi, ecx
		// forward_page_temp[i++] = 0x89;
		// forward_page_temp[i++] = 0xce;
		//
		// // ׼������
		// // ���ݲ���
		// // ʹ��fastcall����������ecx��
		//
		// forward_page_temp[i++] = 0xe8;        // call callback
		// *(uint32_t*)&forward_page_temp[i] = GetInstrOffset((forward_page_uint + i - 1), 5, callback);
		// i += 4;
		//
		// // mov ecx, esi     // �ٴ��õ�context
		// forward_page_temp[i++] = 0x89;
		// forward_page_temp[i++] = 0xf1;
		//
		// // �Ȱ�callback����ֵ��������
		// // mov [ecx + 0x280 + 0], al
		// forward_page_temp[i++] = 0x88;
		// forward_page_temp[i++] = 0x81; 
		// *(uint32_t*)&forward_page_temp[i] = (uint32_t)0x280 + 0;
		// i += 4;
		//
		// // ��jmp_addr���浽tls��
		// // push [ecx+0x8]
		// forward_page_temp[i++] = 0xff;
		// forward_page_temp[i++] = 0x71;
		// forward_page_temp[i++] = 0x8;
		// i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);
		//
		// // �ָ������Ļ���
		// // ��ecx��eax
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
		// // ��ԭָ��ִ��ǰ��ԭ���л���������ѹ���jmp_addr
		//
		// // ִ��ǰ����hook�ص��п����޸ĵ�esp
		// // mov esp, [ecx + 4]
		// forward_page_temp[i++] = 0x8b;
		// forward_page_temp[i++] = 0x61;
		// forward_page_temp[i++] = 0x04;
		//
  //           
		// // �õ�callback�ķ���ֵ
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
		// // ����Ļָ������Ļ�û�лָ�eax��ecx�������ٻָ�eax��ecx
		// // mov eax, [ecx + 0x44]        // ����ԭecx�ȱ��浽eax
		// forward_page_temp[i++] = 0x8b;
		// forward_page_temp[i++] = 0x81;
		// *(uint32_t*)&forward_page_temp[i] = 0x44;
		// i += 4;
		// // push eax     // ����ԭecx�Ѿ���ջ����
		// forward_page_temp[i++] = 0x50;
		//
		// // mov eax, [ecx + 0x40]
		// forward_page_temp[i++] = 0x8b;
		// forward_page_temp[i++] = 0x81;
		// *(uint32_t*)&forward_page_temp[i] = 0x40;
		// i += 4;
		//
		// // pop ecx      // �ָ�ԭecx
		// forward_page_temp[i++] = 0x59;
		//
		//
		// // je _skip_exec_old_insrt
		// forward_page_temp[i++] = 0x74;
		// forward_page_temp[i++] = 1 + hook.old_instr_.size() + 2;
		//
		// forward_page_temp[i++] = 0x9d;      // popfd
		// // ִ��ԭָ��
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
		// // push eax     // Ԥ��һ��ջλ�ã����jmp_addr
		// forward_page_temp[i++] = 0x50;
		// forward_page_temp[i++] = 0x50;      // push eax
		// forward_page_temp[i++] = 0x51;      // push ecx
		//
		//
		//
		// // �ָ�jmp_addr����
		//
		// // ��Tls�л�ȡjmp_addr
		// i += MakeTlsGetValue(arch, &forward_page_temp[i], hook.tls_id_);
		//
		//
		// // �ո�Ԥ����ջλ�ã�����jmp_addr��������ret���صĵ�ַ
		// // mov [esp+0x08], eax
		// forward_page_temp[i++] = 0x89;
		// forward_page_temp[i++] = 0x44;
		// forward_page_temp[i++] = 0x24;
		// forward_page_temp[i++] = 0x08;
		//
		// // ����
		// {
		// 	// ����Ϊ0
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
		// // ת��ȥ����ִ��
		// forward_page_temp[i++] = 0xc3;        // ret
	}
	else {
		if (instr_size < 14) {
			return std::nullopt;
		}
		auto a = Assembler(Arch::kX64);
		auto next_lab = a.NewLabel();

		// ����ԭ�Ĵ���
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
		// ��ȡTlsValue
		MakeTlsGetValue(a, hook.tls_id_);
		// �ж��Ƿ�����
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

		// ����ԭ��������ִ��
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
		// ѹ��ԭstack������ǰ��push��rax��rcx
		a.lea(rax, ptr(rsp, 0x400 + 0x10));
		a.mov(ptr(rcx), rax);
		// ʵ������ѹ��rsp
		a.mov(ptr(rcx, 8), rax);
		// ��ǰѹ��ת�ص�ַ���Ա�HookCallback�ܹ��޸�
		a.mov(rax, hook_addr + instr_size);
		a.mov(ptr(rcx, 0x10), rax);
		a.mov(rax, forward_page_uint);
		a.mov(ptr(rcx, 0x18), rax);
		a.mov(rax, hook_addr);
		a.mov(ptr(rcx, 0x20), rax);
		// ������ʵ��rcx
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

		// ��ѭx64����Լ����Ϊ��ǰ������ʹ����ǰ����ջ�ռ�
		MakeStackFrameStart(a, 0x20);

		// ������rcx���ڱ���������ʱ�Ѿ�������
		// ��context���浽����ʧ�Ĵ���
		a.mov(rsi, rcx);
		// ����
		a.mov(rax, callback);
		a.call(rax);
		// �ٴ��õ�context
		a.mov(rcx, rsi);
		// �ȱ���callback�ķ���ֵ
		a.mov(ptr(rcx, 0x280), al);
		// ��jmp_addr���浽tls��
		a.mov(rdx, ptr(rcx, 0x10));
		MakeTlsSetValue(a, hook.tls_id_);
		// �ٴ��õ�context
		a.mov(rcx, rsi);

		MakeStackFrameEnd(a, 0x20);

		// �ָ������Ļ���
		// ��rcx��rax
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

		// ��ԭָ��ִ��ǰ��ԭ���л��������������jmp_addr
		// ִ��ǰ����hook�ص��п����޸ĵ�rsp
		a.mov(rax, ptr(rcx, 8));
		a.mov(rsp, rax);

		// ׼��ִ��ԭָ��
		// �õ�callback�ķ���ֵ
		a.mov(al, ptr(rcx, 0x280));
		a.pushfq();
		a.cmp(al, 0);

		// ����Ļָ������Ļ�����û�лָ�rax��rcx�������ٻָ�rax��rcx
		a.mov(rax, ptr(rcx, 0x88));		// ԭrcx�ȱ��浽rax
		a.push(rax);					// ����ԭrcx�Ѿ���ջ����
		a.mov(rax, ptr(rcx, 0x80));
		a.pop(rcx);						// �ָ�ԭrcx

		auto skip_exec_old_insrt_lab = a.NewLabel();
		auto next_exec_old_insrt_lab = a.NewLabel();

		a.je(skip_exec_old_insrt_lab);
		a.popfq();
		// ִ��ԭָ��
		for (size_t i_ = 0; i_ < hook.old_instr_.size(); ++i_)
			a.db(hook.old_instr_[i_]);
		a.jmp(next_exec_old_insrt_lab);

		a.bind(skip_exec_old_insrt_lab);

		a.popfq();

		a.bind(next_exec_old_insrt_lab);

		a.push(rax);					// Ԥ��һ��ջλ�ã����jmp_addr
		a.push(rax);
		a.push(rcx);
		a.push(rdx);
		a.push(rdi);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);

		MakeStackFrameStart(a, 0x20);

		// �ָ�jmp_addr����
		// ��Tls�л�ȡjmp_addr
		MakeTlsGetValue(a, hook.tls_id_);
		a.mov(qword_ptr(rsp, rdi, 0, 0x60), rax);	// �ո�Ԥ����ջλ�ã�����jmp_addr��������ret���صĵ�ַ

		// �����˳�
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

	// ΪĿ���ַ��hook
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
		// ͨ��ԭ��ָ�����hook�����ʹ���ĸ���
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
 * function��install�ڲ�ʹ�õ�callback
 * ת����function
 */
bool __fastcall InstallX32Callback(InlineHook::HookContextX86* ctx)
{
	// ���ҽ��̶�Ӧ�Ļص��б�
	auto cbs = callbacks_x32.find(GetCurrentProcessId());
	assert(cbs != callbacks_x32.end());
	// ����hook��ַ�ҵ���Ӧ��function
	auto c = cbs->second.find(ctx->hook_addr);
	assert(c != cbs->second.end());
	// ����function
	return c->second(ctx);
}

bool InstallX64Callback(InlineHook::HookContextX64* ctx)
{
	// ���ҽ��̶�Ӧ�Ļص��б�
	auto cbs = callbacks_x64.find(GetCurrentProcessId());
	assert(cbs != callbacks_x64.end());
	// ����hook��ַ�ҵ���Ӧ��function
	auto c = cbs->second.find(ctx->hook_addr);
	assert(c != cbs->second.end());
	// ����function
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
	// TODO �����hook֧��
	if (!proc->IsCurrent())
		throw std::exception("Cross-process hooks are not yet supported");

	// ��function����ص���������
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
	// TODO �����hook֧��
	if (!proc->IsCurrent())
		throw std::exception("Cross-process hooks are not yet supported");

	// ��function����ص���������
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
