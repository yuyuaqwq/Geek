#include <assert.h>
#include <geek/hook/inline_hook.h>

#include <unordered_map>

#include <geek/process/process.h>
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
namespace {
uint64_t GetInstrOffset(uint64_t instr_addr, size_t instr_size, uint64_t dst_addr)
{
	return dst_addr - instr_addr - instr_size;
}

// ������ת��ָ����ַ��ָ��
uint64_t MakeJmp(Arch arch, std::vector<uint8_t>* buf, uint64_t cur_addr, uint64_t jmp_addr)
{
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
uint64_t MakeStackFrameStart(Arch arch, uint8_t* buf, int8_t size)
{
	int i = 0;
	switch (arch) {
	case Arch::kX86: {
		break;
	}
	case Arch::kX64: {

		// ����ջ֡
		buf[i++] = 0x48;        // sub rsp, size
		buf[i++] = 0x83;
		buf[i++] = 0xec;
		buf[i++] = size;

		// ǿ��ʹջ16�ֽڶ���
		{
			// mov rdi, rsp
			buf[i++] = 0x48;
			buf[i++] = 0x89;
			buf[i++] = 0xe7;

			// and rdi, 0x8
			buf[i++] = 0x48;
			buf[i++] = 0x83;
			buf[i++] = 0xe7;
			buf[i++] = 0x08;

			// sub rsp, rdi
			buf[i++] = 0x48;
			buf[i++] = 0x29;
			buf[i++] = 0xfc;
		}
		break;
	}
	}
	return i;
}

// ���ɽ���ջ֡��ָ��
uint64_t MakeStackFrameEnd(Arch arch, uint8_t* buf, int8_t size)
{
	int i = 0;
	switch (arch) {
	case Arch::kX86: {
		break;
	}
	case Arch::kX64: {
		// �ָ�ջ����
		{
			// add rsp, rdi
			buf[i++] = 0x48;
			buf[i++] = 0x01;
			buf[i++] = 0xfc;
		}
		// add rsp, size
		buf[i++] = 0x48;
		buf[i++] = 0x83;
		buf[i++] = 0xc4;
		buf[i++] = size;

		break;
	}
	}
	return i;
}

// ����TlsSetValue��ָ��
// X86:��ʹ��rax��Ҫ��value�Ѿ��Ƶ�ջ��
// X64:��ʹ��rcx��rax��Ҫ��value����rdx�У����Ѿ�������ջ֡
uint64_t MakeTlsSetValue(Arch arch, uint8_t* buf, uint32_t tls_id)
{
	int i = 0;
	switch (arch) {
	case Arch::kX86: {
		// call TlsSetValue
		// push tls_id_
		buf[i++] = 0x68;
		*(uint32_t*)&buf[i] = tls_id;
		i += 4;

		// mov eax, TlsSetValue
		buf[i++] = 0xb8;
		*(uint32_t*)&buf[i] = (uint32_t)TlsSetValue;
		i += 4;

		// call rax
		buf[i++] = 0xff;
		buf[i++] = 0xd0;
		break;
	}
	case Arch::kX64: {
		// call TlsSetValue
		// mov rcx, tls_id_
		buf[i++] = 0x48;
		buf[i++] = 0xb9;
		*(uint64_t*)&buf[i] = tls_id;
		i += 8;
		// mov rax, TlsSetValue
		buf[i++] = 0x48;
		buf[i++] = 0xb8;
		*(uint64_t*)&buf[i] = (uint64_t)TlsSetValue;
		i += 8;
		// call rax
		buf[i++] = 0xff;
		buf[i++] = 0xd0;
		break;
	}
	}
	return i;
}

// ����TlsGetValue��ָ��
// ��ʹ��rcx��rax��Ҫ���Ѿ�������ջ֡
uint64_t MakeTlsGetValue(Arch arch, uint8_t* buf, uint32_t tls_id)
{
	int i = 0;
	switch (arch) {
	case Arch::kX86: {
		// push tls_id_
		buf[i++] = 0x68;
		*(uint32_t*)&buf[i] = tls_id;
		i += 4;

		// mov eax, TlsGetValue
		buf[i++] = 0xb8;
		*(uint32_t*)&buf[i] = (uint32_t)TlsGetValue;
		i += 4;

		// call rax
		buf[i++] = 0xff;
		buf[i++] = 0xd0;
		break;
	}
	case Arch::kX64: {
		// mov rcx, tls_id_
		buf[i++] = 0x48;
		buf[i++] = 0xb9;
		*(uint64_t*)&buf[i] = (uint64_t)tls_id;
		i += 8;

		// mov rax, TlsGetValue
		buf[i++] = 0x48;
		buf[i++] = 0xb8;
		*(uint64_t*)&buf[i] = (uint64_t)TlsGetValue;
		i += 8;

		// call rax
		buf[i++] = 0xff;
		buf[i++] = 0xd0;
		break;
	}
	}
	return i;
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
        
	std::vector<uint8_t> jmp_instr(instr_size);

	if (arch == Arch::kX86) {
		if (instr_size < 5) {
			return std::nullopt;
		}

		int i = 0;
		uint32_t context_addr;

		// ���������̰߳�ȫ�Ĵ���
		{
			// ����ԭ�Ĵ���
			forward_page_temp[i++] = 0x50;        // push eax
			forward_page_temp[i++] = 0x51;        // push ecx
			forward_page_temp[i++] = 0x52;        // push edx
			forward_page_temp[i++] = 0x9c;        // pushfd

			// ��ȡTlsValue
			i += MakeTlsGetValue(arch, &forward_page_temp[i], hook.tls_id_);


			// �ж��Ƿ�����
			// cmp eax, 0
			forward_page_temp[i++] = 0x83;
			forward_page_temp[i++] = 0xf8;
			forward_page_temp[i++] = 0x00;
			// je _next
			forward_page_temp[i++] = 0x74;
			forward_page_temp[i++] = 4 + hook.old_instr_.size() + 5;

			// ��1λΪ1�������룬ִ��ԭָ�ת��
			forward_page_temp[i++] = 0x9d;        // popfd
			forward_page_temp[i++] = 0x5a;        // pop rdx
			forward_page_temp[i++] = 0x59;        // pop rcx
			forward_page_temp[i++] = 0x58;        // pop rax

			memcpy(&forward_page_temp[i], hook.old_instr_.data(), hook.old_instr_.size());
			i += hook.old_instr_.size();

			// ����ԭ��������ִ��
			std::vector<uint8_t> temp;
			MakeJmp(arch, &temp, forward_page_uint + i, hook_addr + instr_size);
			memcpy(&forward_page_temp[i], &temp[0], temp.size());
			i += temp.size();


			// _next:
			// ����Ϊ1
			// call TlsSetValue
			// push 1
			forward_page_temp[i++] = 0x6a;
			forward_page_temp[i++] = 0x01;
			i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);

			forward_page_temp[i++] = 0x9d;        // popfq
			forward_page_temp[i++] = 0x5a;        // pop rdx
			forward_page_temp[i++] = 0x59;        // pop rcx
			forward_page_temp[i++] = 0x58;        // pop rax
		}

		// sub rsp, 400
		forward_page_temp[i++] = 0x81;
		forward_page_temp[i++] = 0xec;
		*(uint32_t*)&forward_page_temp[i] = 0x400;
		i += 4;

		// ����context_addr
		{
			forward_page_temp[i++] = 0x50;        // push eax
			forward_page_temp[i++] = 0x51;        // push ecx

			// lea ecx, [esp+0x8]
			forward_page_temp[i++] = 0x8d;
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x24;
			forward_page_temp[i++] = 0x8;

			// ѹ��ԭstack������ǰ��push��eax��ecx
			// lea eax, [esp+0x400+0x8]
			forward_page_temp[i++] = 0x8d;
			forward_page_temp[i++] = 0x84;
			forward_page_temp[i++] = 0x24;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)0x400 + 8;
			i += 4;

			// mov [ecx], eax
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x01;

			// ʵ������ѹ��esp
			// mov [ecx+4], eax
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x04;


			// mov eax, hook_addr + instr_size
			forward_page_temp[i++] = 0xb8;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)hook_addr + instr_size;
			i += 4;
			// mov [ecx+0x8], eax
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x8;

			// mov eax, forward_page
			forward_page_temp[i++] = 0xb8;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)forward_page_uint;
			i += 4;
			// mov [ecx+0xc], rax
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0xc;

			// mov eax, hook_addr
			forward_page_temp[i++] = 0xb8;
			*(uint32_t*)&forward_page_temp[i] = (uint32_t)hook_addr;
			i += 4;
			// mov [ecx+0x10], eax
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x10;

			// pop eax      // ������ʵ��ecx
			forward_page_temp[i++] = 0x58;
			// mov [ecx+0x44], eax
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x44;

			// pop eax
			forward_page_temp[i++] = 0x58;
			// mov [ecx+0x40], eax
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x40;

			// mov [ecx+0x48], edx
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x51;
			forward_page_temp[i++] = 0x48;

			// mov [ecx+0x4c], ebx
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x59;
			forward_page_temp[i++] = 0x4c;

			// mov [ecx+0x50], esp
			//forward_page_temp[i++] = 0x89;
			//forward_page_temp[i++] = 0x61;
			//forward_page_temp[i++] = 0x50;

			// mov [ecx+0x54], ebp
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x69;
			forward_page_temp[i++] = 0x54;

			// mov [ecx+0x58], esi
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x71;
			forward_page_temp[i++] = 0x58;

			// mov [ecx+0x5c], edi
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x79;
			forward_page_temp[i++] = 0x5c;

			forward_page_temp[i++] = 0x9c;        // pushfd
			forward_page_temp[i++] = 0x58;        // pop eax
			// mov [ecx+0x60], eax
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x60;

		}
            

		// ecx���浽����ʧ�Ĵ���
		// mov esi, ecx
		forward_page_temp[i++] = 0x89;
		forward_page_temp[i++] = 0xce;

		// ׼������
		// ���ݲ���
		// ʹ��fastcall����������ecx��

		forward_page_temp[i++] = 0xe8;        // call callback
		*(uint32_t*)&forward_page_temp[i] = GetInstrOffset((forward_page_uint + i - 1), 5, callback);
		i += 4;

		// mov ecx, esi     // �ٴ��õ�context
		forward_page_temp[i++] = 0x89;
		forward_page_temp[i++] = 0xf1;

		// �Ȱ�callback����ֵ��������
		// mov [ecx + 0x280 + 0], al
		forward_page_temp[i++] = 0x88;
		forward_page_temp[i++] = 0x81; 
		*(uint32_t*)&forward_page_temp[i] = (uint32_t)0x280 + 0;
		i += 4;

		// ��jmp_addr���浽tls��
		// push [ecx+0x8]
		forward_page_temp[i++] = 0xff;
		forward_page_temp[i++] = 0x71;
		forward_page_temp[i++] = 0x8;
		i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);

		// �ָ������Ļ���
		// ��ecx��eax
		{
			// mov eax, [ecx + 0x60]
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x60;

			forward_page_temp[i++] = 0x50;        // push eax
			forward_page_temp[i++] = 0x9d;        // popfd

			// mov edx, [ecx + 0x48]
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x51;
			forward_page_temp[i++] = 0x48;

			// mov ebx, [ecx + 0x4c]
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x59;
			forward_page_temp[i++] = 0x4c;

			// mov esp, [ecx + 0x50]
			//forward_page_temp[i++] = 0x8b;
			//forward_page_temp[i++] = 0x61;
			//forward_page_temp[i++] = 0x50;

			// mov ebp, [ecx + 0x54]
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x69;
			forward_page_temp[i++] = 0x54;

			// mov esi, [ecx + 0x58]
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x71;
			forward_page_temp[i++] = 0x58;

			// mov edi, [ecx + 0x5c]
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x79;
			forward_page_temp[i++] = 0x5c;
		}
            

		// ��ԭָ��ִ��ǰ��ԭ���л���������ѹ���jmp_addr

		// ִ��ǰ����hook�ص��п����޸ĵ�esp
		// mov esp, [ecx + 4]
		forward_page_temp[i++] = 0x8b;
		forward_page_temp[i++] = 0x61;
		forward_page_temp[i++] = 0x04;

            
		// �õ�callback�ķ���ֵ
		// mov al, [ecx + 0x280 + 0]
		forward_page_temp[i++] = 0x8a;
		forward_page_temp[i++] = 0x81;
		*(uint32_t*)&forward_page_temp[i] = (uint32_t)0x280 + 0;
		i += 4;

            
		forward_page_temp[i++] = 0x9c;      // pushfd
		// cmp al, 0
		forward_page_temp[i++] = 0x3c;
		forward_page_temp[i++] = 0x00;

		// ����Ļָ������Ļ�û�лָ�eax��ecx�������ٻָ�eax��ecx
		// mov eax, [ecx + 0x44]        // ����ԭecx�ȱ��浽eax
		forward_page_temp[i++] = 0x8b;
		forward_page_temp[i++] = 0x81;
		*(uint32_t*)&forward_page_temp[i] = 0x44;
		i += 4;
		// push eax     // ����ԭecx�Ѿ���ջ����
		forward_page_temp[i++] = 0x50;

		// mov eax, [ecx + 0x40]
		forward_page_temp[i++] = 0x8b;
		forward_page_temp[i++] = 0x81;
		*(uint32_t*)&forward_page_temp[i] = 0x40;
		i += 4;

		// pop ecx      // �ָ�ԭecx
		forward_page_temp[i++] = 0x59;


		// je _skip_exec_old_insrt
		forward_page_temp[i++] = 0x74;
		forward_page_temp[i++] = 1 + hook.old_instr_.size() + 2;

		forward_page_temp[i++] = 0x9d;      // popfd
		// ִ��ԭָ��
		memcpy(&forward_page_temp[i], hook.old_instr_.data(), hook.old_instr_.size());
		i += hook.old_instr_.size();
		// jmp _next_exec_old_insrt
		forward_page_temp[i++] = 0xeb;
		forward_page_temp[i++] = 0x01;      // +1

		// _skip_exec_old_insrt:
		forward_page_temp[i++] = 0x9d;      // popfd
		// _next_exec_old_insrt:
            

		// push eax     // Ԥ��һ��ջλ�ã����jmp_addr
		forward_page_temp[i++] = 0x50;
		forward_page_temp[i++] = 0x50;      // push eax
		forward_page_temp[i++] = 0x51;      // push ecx



		// �ָ�jmp_addr����

		// ��Tls�л�ȡjmp_addr
		i += MakeTlsGetValue(arch, &forward_page_temp[i], hook.tls_id_);


		// �ո�Ԥ����ջλ�ã�����jmp_addr��������ret���صĵ�ַ
		// mov [esp+0x08], eax
		forward_page_temp[i++] = 0x89;
		forward_page_temp[i++] = 0x44;
		forward_page_temp[i++] = 0x24;
		forward_page_temp[i++] = 0x08;

		// ����
		{
			// ����Ϊ0
			// call TlsSetValue
			// push 0
			forward_page_temp[i++] = 0x6a;
			forward_page_temp[i++] = 0x00;
			i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);
		}

		forward_page_temp[i++] = 0x59;      // pop ecx
		forward_page_temp[i++] = 0x58;      // pop eax

		// ת��ȥ����ִ��
		forward_page_temp[i++] = 0xc3;        // ret
	}
	else {
		if (instr_size < 14) {
			return std::nullopt;
		}
		int i = 0;

		uint64_t context_addr;

		// ���������̰߳�ȫ�Ĵ���
		{
			// ����ԭ�Ĵ���
			forward_page_temp[i++] = 0x50;        // push rax
			forward_page_temp[i++] = 0x51;        // push rcx
			forward_page_temp[i++] = 0x52;        // push rdx
			forward_page_temp[i++] = 0x57;        // push rdi

			// push r8
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x50;
			// push r9
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x51;
			// push r10
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x52;
			// push r11
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x53;

			forward_page_temp[i++] = 0x9c;        // pushfq

			i += MakeStackFrameStart(arch, &forward_page_temp[i], 0x20);

			// ��ȡTlsValue
			i += MakeTlsGetValue(arch, &forward_page_temp[i], hook.tls_id_);


			// �ж��Ƿ�����
			// cmp rax, 0
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x83;
			forward_page_temp[i++] = 0xf8;
			forward_page_temp[i++] = 0x00;
			// je _next
			forward_page_temp[i++] = 0x74;
			forward_page_temp[i++] = 7 + 13 + hook.old_instr_.size() + 14;

			// ��1λΪ1�������룬ִ��ԭָ�ת��
                
			i += MakeStackFrameEnd(arch, &forward_page_temp[i], 0x20);

			forward_page_temp[i++] = 0x9d;        // popfq

			// pop r11
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x5b;
			// pop r10
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x5a;
			// pop r9
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x59;
			// pop r8
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x58;

			forward_page_temp[i++] = 0x5f;        // pop rdi
			forward_page_temp[i++] = 0x5a;        // pop rdx
			forward_page_temp[i++] = 0x59;        // pop rcx
			forward_page_temp[i++] = 0x58;        // pop rax

			memcpy(&forward_page_temp[i], hook.old_instr_.data(), hook.old_instr_.size());
			i += hook.old_instr_.size();

			// ����ԭ��������ִ��
			std::vector<uint8_t> temp;
			MakeJmp(arch, &temp, forward_page_uint + i, hook_addr + instr_size);
			memcpy(&forward_page_temp[i], &temp[0], temp.size());
			i += temp.size();


			// _next:
			// ����Ϊ1
			// call TlsSetValue
			// mov rdx, 1
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xc7;
			forward_page_temp[i++] = 0xc2;
			*(uint32_t*)&forward_page_temp[i] = 0x1;
			i += 4;
			i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);

			i += MakeStackFrameEnd(arch, &forward_page_temp[i], 0x20);

			forward_page_temp[i++] = 0x9d;        // popfq

			// pop r11
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x5b;
			// pop r10
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x5a;
			// pop r9
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x59;
			// pop r8
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x58;

			forward_page_temp[i++] = 0x5f;        // pop rdi
			forward_page_temp[i++] = 0x5a;        // pop rdx
			forward_page_temp[i++] = 0x59;        // pop rcx
			forward_page_temp[i++] = 0x58;        // pop rax
		}

            
		// sub rsp, 0x400
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x81;
		forward_page_temp[i++] = 0xec;
		*(uint32_t*)&forward_page_temp[i] = 0x400;
		i += 4;

		// ����context_addr
		{
			forward_page_temp[i++] = 0x50;        // push rax
			forward_page_temp[i++] = 0x51;        // push rcx

			// lea rcx, [rsp+0x10]
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x8d;
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x24;
			forward_page_temp[i++] = 0x10;

			// ѹ��ԭstack������ǰ��push��rax��rcx
			// lea rax, [rsp+0x400+0x10]
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x8d;
			forward_page_temp[i++] = 0x84;
			forward_page_temp[i++] = 0x24;
			*(uint32_t*)&forward_page_temp[i] = 0x400 + 0x10;
			i += 4;
			// mov [rcx], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x01;

			// ʵ������ѹ��rsp
			// mov [rcx+8], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x08;

			// ��ǰѹ��ת�ص�ַ���Ա�HookCallback�ܹ��޸�
			// mov rax, hook_addr + instr_size
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xb8;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)hook_addr + instr_size;
			i += 8;
			// mov [rcx+0x10], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x10;

			// mov rax, forward_page
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xb8;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)forward_page_uint;
			i += 8;
			// mov [rcx+0x18], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x18;

			// mov rax, hook_addr
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xb8;
			*(uint64_t*)&forward_page_temp[i] = (uint64_t)hook_addr;
			i += 8;
			// mov [rcx+0x20], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x41;
			forward_page_temp[i++] = 0x20;

			// pop rax      // ������ʵ��rcx
			forward_page_temp[i++] = 0x58;
			// mov [rcx+0x88], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x81;
			*(uint32_t*)&forward_page_temp[i] = 0x88;
			i += 4;

			// pop rax
			forward_page_temp[i++] = 0x58;
			// mov [rcx+0x80], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x81;
			*(uint32_t*)&forward_page_temp[i] = 0x80;
			i += 4;


			// mov [rcx+0x90], rdx
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x91;
			*(uint32_t*)&forward_page_temp[i] = 0x90;
			i += 4;


			// mov [rcx+0x98], rbx
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x99;
			*(uint32_t*)&forward_page_temp[i] = 0x98;
			i += 4;


			// mov [rcx+0xa0], rsp
			//forward_page_temp[i++] = 0x48;
			//forward_page_temp[i++] = 0x89;
			//forward_page_temp[i++] = 0xa1;
			//*(uint32_t*)&forward_page_temp[i] = 0xa0;
			//i += 4;


			// mov [rcx+0xa8], rbp
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0xa9;
			*(uint32_t*)&forward_page_temp[i] = 0xa8;
			i += 4;

			// mov [rcx+0xb0], rsi
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0xb1;
			*(uint32_t*)&forward_page_temp[i] = 0xb0;
			i += 4;

			// mov [rcx+0xb8], rdi
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0xb9;
			*(uint32_t*)&forward_page_temp[i] = 0xb8;
			i += 4;


			// mov [rcx+0xc0], r8
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x81;
			*(uint32_t*)&forward_page_temp[i] = 0xc0;
			i += 4;

			// mov [rcx+0xc8], r9
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x89;
			*(uint32_t*)&forward_page_temp[i] = 0xc8;
			i += 4;

			// mov [rcx+0xd0], r10
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x91;
			*(uint32_t*)&forward_page_temp[i] = 0xd0;
			i += 4;

			// mov [rcx+0xd8], r11
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x99;
			*(uint32_t*)&forward_page_temp[i] = 0xd8;
			i += 4;

			// mov [rcx+0xe0], r12
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0xa1;
			*(uint32_t*)&forward_page_temp[i] = 0xe0;
			i += 4;

			// mov [rcx+0xe8], r13
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0xa9;
			*(uint32_t*)&forward_page_temp[i] = 0xe8;
			i += 4;

			// mov [rcx+0xf0], r14
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0xb1;
			*(uint32_t*)&forward_page_temp[i] = 0xf0;
			i += 4;

			// mov [rcx+0xf8], r15
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0xb9;
			*(uint32_t*)&forward_page_temp[i] = 0xf8;
			i += 4;

			forward_page_temp[i++] = 0x9c;        // pushfq
			forward_page_temp[i++] = 0x58;        // pop rax
			// mov [rcx+0x100], rax
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x89;
			forward_page_temp[i++] = 0x81;
			*(uint32_t*)&forward_page_temp[i] = 0x100;
			i += 4;
		}

		// ��ѭx64����Լ����Ϊ��ǰ������ʹ����ǰ����ջ�ռ�
		i += MakeStackFrameStart(arch, &forward_page_temp[i], 0x20);

		// ������rcx���ڱ���������ʱ�Ѿ�������

		// mov rsi, rcx     // ��context���浽����ʧ�Ĵ���
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x89;
		forward_page_temp[i++] = 0xce;

		// ����
		forward_page_temp[i++] = 0x48;        // mov rax, addr
		forward_page_temp[i++] = 0xb8;
		*(uint64_t*)&forward_page_temp[i] = (uint64_t)callback;
		i += 8;
		// call rax
		forward_page_temp[i++] = 0xff;
		forward_page_temp[i++] = 0xd0;

		// mov rcx, rsi     // �ٴ��õ�context
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x89;
		forward_page_temp[i++] = 0xf1;


		// �ȱ���callback�ķ���ֵ
		// mov [rcx + 0x280 + 0], al
		forward_page_temp[i++] = 0x88;
		forward_page_temp[i++] = 0x81;
		*(uint32_t*)&forward_page_temp[i] = 0x280 + 0;
		i += 4;

		// ��jmp_addr���浽tls��
		// mov rdx, [rcx+0x10]
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x8b;
		forward_page_temp[i++] = 0x51;
		forward_page_temp[i++] = 0x10;
		i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);

		// mov rcx, rsi     // �ٴ��õ�context
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x89;
		forward_page_temp[i++] = 0xf1;

		i += MakeStackFrameEnd(arch, &forward_page_temp[i], 0x20);



		// �ָ������Ļ���
		// ��rcx��rax
		{
			// mov rax, [rcx + 0x100]
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x81;
			*(uint32_t*)&forward_page_temp[i] = 0x100;
			i += 4;
			forward_page_temp[i++] = 0x50;        // push rax
			forward_page_temp[i++] = 0x9d;        // popfq


			// mov rdx, [rcx + 0x90]
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x91;
			*(uint32_t*)&forward_page_temp[i] = 0x90;
			i += 4;

			// mov rbx, [rcx + 0x98]
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x99;
			*(uint32_t*)&forward_page_temp[i] = 0x98;
			i += 4;

			// mov rsp, [rcx + 0xa0]
			//forward_page_temp[i++] = 0x48;
			//forward_page_temp[i++] = 0x8b;
			//forward_page_temp[i++] = 0xa1;
			//*(uint32_t*)&forward_page_temp[i] = 0xa0;
			//i += 4;

			// mov rbp, [rcx + 0xa8]
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0xa9;
			*(uint32_t*)&forward_page_temp[i] = 0xa8;
			i += 4;

			// mov rsi, [rcx + 0xb0]
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0xb1;
			*(uint32_t*)&forward_page_temp[i] = 0xb0;
			i += 4;

			// mov rdi, [rcx + 0xb8]
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0xb9;
			*(uint32_t*)&forward_page_temp[i] = 0xb8;
			i += 4;


			// mov r8, [rcx + 0xc0]
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x81;
			*(uint32_t*)&forward_page_temp[i] = 0xc0;
			i += 4;

			// mov r9, [rcx + 0xc8]
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x89;
			*(uint32_t*)&forward_page_temp[i] = 0xc8;
			i += 4;

			// mov r10, [rcx + 0xd0]
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x91;
			*(uint32_t*)&forward_page_temp[i] = 0xd0;
			i += 4;

			// mov r11, [rcx + 0xd8]
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0x99;
			*(uint32_t*)&forward_page_temp[i] = 0xd8;
			i += 4;

			// mov r12, [rcx + 0xe0]
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0xa1;
			*(uint32_t*)&forward_page_temp[i] = 0xe0;
			i += 4;

			// mov r13, [rcx + 0xe8]
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0xa9;
			*(uint32_t*)&forward_page_temp[i] = 0xe8;
			i += 4;

			// mov r14, [rcx + 0xf0]
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0xb1;
			*(uint32_t*)&forward_page_temp[i] = 0xf0;
			i += 4;

			// mov r15, [rcx + 0xf8]
			forward_page_temp[i++] = 0x4c;
			forward_page_temp[i++] = 0x8b;
			forward_page_temp[i++] = 0xb9;
			*(uint32_t*)&forward_page_temp[i] = 0xf8;
			i += 4;
		}


		// ��ԭָ��ִ��ǰ��ԭ���л��������������jmp_addr

		// ִ��ǰ����hook�ص��п����޸ĵ�rsp
		// mov rax, [rcx + 8]
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x8b;
		forward_page_temp[i++] = 0x41;
		forward_page_temp[i++] = 0x08;
		// mov rsp, rax
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x89;
		forward_page_temp[i++] = 0xc4;


		// ׼��ִ��ԭָ��
		// �õ�callback�ķ���ֵ
		// mov al, [rcx + 0x280 + 0]
		forward_page_temp[i++] = 0x8a;
		forward_page_temp[i++] = 0x81;
		*(uint32_t*)&forward_page_temp[i] = 0x280;
		i += 4;

		forward_page_temp[i++] = 0x9c;      // pushfd
		// cmp al, 0
		forward_page_temp[i++] = 0x3c;
		forward_page_temp[i++] = 0x00;


		// ����Ļָ������Ļ�����û�лָ�rax��rcx�������ٻָ�rax��rcx
		// mov rax, [rcx + 0x88]        // ԭrcx�ȱ��浽rax
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x8b;
		forward_page_temp[i++] = 0x81;
		*(uint32_t*)&forward_page_temp[i] = 0x88;
		i += 4;

		// push rax     // ����ԭrcx�Ѿ���ջ����
		forward_page_temp[i++] = 0x50;

		// mov rax, [rcx + 0x80]
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x8b;
		forward_page_temp[i++] = 0x81;
		*(uint32_t*)&forward_page_temp[i] = 0x80;
		i += 4;

		// pop rcx      // �ָ�ԭrcx
		forward_page_temp[i++] = 0x59;
            

		// je _skip_exec_old_insrt
		forward_page_temp[i++] = 0x74;
		forward_page_temp[i++] = 1 + hook.old_instr_.size() + 2;

		forward_page_temp[i++] = 0x9d;      // popfd
		// ִ��ԭָ��
		memcpy(&forward_page_temp[i], hook.old_instr_.data(), hook.old_instr_.size());
		i += hook.old_instr_.size();
		// jmp _next_exec_old_insrt
		forward_page_temp[i++] = 0xeb;
		forward_page_temp[i++] = 0x01;      // +1

		// _skip_exec_old_insrt:
		forward_page_temp[i++] = 0x9d;      // popfd
		// _next_exec_old_insrt:



		// push rax     // Ԥ��һ��ջλ�ã����jmp_addr
		forward_page_temp[i++] = 0x50;

		forward_page_temp[i++] = 0x50;      // push rax
		forward_page_temp[i++] = 0x51;      // push rcx
		forward_page_temp[i++] = 0x52;      // push rdx
		forward_page_temp[i++] = 0x57;      // push rdi

		// push r8
		forward_page_temp[i++] = 0x41;
		forward_page_temp[i++] = 0x50;
		// push r9
		forward_page_temp[i++] = 0x41;
		forward_page_temp[i++] = 0x51;
		// push r10
		forward_page_temp[i++] = 0x41;
		forward_page_temp[i++] = 0x52;
		// push r11
		forward_page_temp[i++] = 0x41;
		forward_page_temp[i++] = 0x53;
            
		i += MakeStackFrameStart(arch, &forward_page_temp[i], 0x20);

		// �ָ�jmp_addr����
		// ��Tls�л�ȡjmp_addr
		i += MakeTlsGetValue(arch, &forward_page_temp[i], hook.tls_id_);

		// mov qword ptr ss:[rsp+rdi+0x60], rax     // �ո�Ԥ����ջλ�ã�����jmp_addr��������ret���صĵ�ַ
		forward_page_temp[i++] = 0x48;
		forward_page_temp[i++] = 0x89;
		forward_page_temp[i++] = 0x44;
		forward_page_temp[i++] = 0x3c;
		forward_page_temp[i++] = 0x60;

		// �����˳�
		{
			// ����Ϊ0
			// call TlsSetValue
			forward_page_temp[i++] = 0x48;
			forward_page_temp[i++] = 0xc7;
			forward_page_temp[i++] = 0xc2;
			*(uint32_t*)&forward_page_temp[i] = 0x0;
			i += 4;
			i += MakeTlsSetValue(arch, &forward_page_temp[i], hook.tls_id_);
		}
            
		i += MakeStackFrameEnd(arch, &forward_page_temp[i], 0x20);

		// pop r11
		forward_page_temp[i++] = 0x41;
		forward_page_temp[i++] = 0x5b;
		// pop r10
		forward_page_temp[i++] = 0x41;
		forward_page_temp[i++] = 0x5a;
		// pop r9
		forward_page_temp[i++] = 0x41;
		forward_page_temp[i++] = 0x59;
		// pop r8
		forward_page_temp[i++] = 0x41;
		forward_page_temp[i++] = 0x58;

		forward_page_temp[i++] = 0x5f;      // pop rdi
		forward_page_temp[i++] = 0x5a;      // pop rdx
		forward_page_temp[i++] = 0x59;      // pop rcx
		forward_page_temp[i++] = 0x58;      // pop rax

		// ת��ȥ����ִ��
		forward_page_temp[i++] = 0xc3;        // ret
	}

	hook.process_->WriteMemory(hook.forward_page_, forward_page_temp, forward_page_size);

	// ΪĿ���ַ��hook
	hook.hook_addr_ = hook_addr;

        
	if (hook.process_->IsCurrent() &&
		(
			arch == Arch::kX86 && instr_size <= 8 || 
			arch == Arch::kX64 && instr_size <= 16
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
