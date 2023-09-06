#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <vector>

#include <stdio.h>
#include <stdint.h>

#include <windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#pragma  comment(lib,"dbghelp.lib")

#include <Geek/file/file.hpp>
#include <Geek/system/system.hpp>
#include <Geek/process/process.hpp>
#include <Geek/thread/thread.hpp>

/**
 * ��SymInitialize ����������ΪFALSE���ֶ�����SymLoadModule64 ��������ģ�飬��ʱ��һ������Ϊ�����Ψһ����ֵ�����ڱ�־����
 * ���� ��һ�� hProcess ����Ϊ���̾�����Զ����ؽ��̵�����ģ��ĵ��Է��ţ�SymInitialize ʹ��UserSearchPath ָ����·���ҷ����ļ�
 * ���·���Էֺ�(;)�ָ�
 */

// https://blog.csdn.net/qq_18218335/article/details/73555860



class StackWalker {
#define USED_CONTEXT_FLAGS CONTEXT_FULL
#define  STACKWALK_MAX_NAMELEN  1024

#if defined(_M_IX86)
#ifdef CURRENT_THREAD_VIA_EXCEPTION
	// TODO: ����ʹ���쳣�ķ�ʽ�õ���ջ
#define GET_CURRENT_CONTEXT(c, contextFlags) \
  do { \
    memset(&c, 0, sizeof(CONTEXT)); \
    EXCEPTION_POINTERS *pExp = NULL; \
    __try { \
      throw 0; \
    } __except( ( (pExp = GetExceptionInformation()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_EXECUTE_HANDLER)) {} \
    if (pExp != NULL) \
      memcpy(&c, pExp->ContextRecord, sizeof(CONTEXT)); \
      c.ContextFlags = contextFlags; \
  } while(0);
#else
	// �õ���ǰ�̵߳��߳�������
#define GET_CURRENT_CONTEXT(c, contextFlags) \
  do { \
    memset(&c, 0, sizeof(CONTEXT)); \
    c.ContextFlags = contextFlags; \
    __asm    call x \
    __asm x: pop eax \
    __asm    mov c.Eip, eax \
    __asm    mov c.Ebp, ebp \
    __asm    mov c.Esp, esp \
  } while(0);
#endif

#else

	// The following is defined for x86 (XP and higher), x64 and IA64:
#define GET_CURRENT_CONTEXT(c, contextFlags) \
  do { \
    memset(&c, 0, sizeof(CONTEXT)); \
    c.ContextFlags = contextFlags; \
    RtlCaptureContext(&c); \
} while(0);
#endif

public:
	struct CallStackEntry {
		uint64_t offset;  // if 0, we have no valid entry
		std::string func_name;
		uint64_t offset_from_smybol;
		std::wstring module_name;
		uint64_t base_of_image;
		std::wstring loaded_image_name;
		std::wstring process_image_name;
		uint64_t	process_entry_point;
	};

	struct CallStackInfo {
		std::vector<uint8_t> buf;
		uint64_t base;
		uint64_t pc;
		uint64_t stack;
	};

public:

	/*
	 * �õ����Ų���ʼ������
	 */
	BOOL InitSymbol(const std::wstring& append_sym_path = L"", Geek::Process* process = nullptr) {
		process_ = process;

		if (modules_loaded_ != FALSE) {
			return TRUE;
		}

		// ��������·��
		// ���Ƚ��û��ṩ�ķ���·����ӽ���

		sym_path_ += append_sym_path;
		sym_path_ += L";";

		sym_path_ += L".;";		// ��ǰĿ¼

		WCHAR temp[MAX_PATH];
		// �õ���ģ���·��
		auto app_path = Geek::File::GetAppPath();
		sym_path_ += app_path + L";";

		// �õ���������·�� ϵͳ����·��
		sym_path_ += Geek::System::GetEnvironmentVariable(L"_NT_SYMBOL_PATH") + L";";

		// �õ� NT �������·��
		sym_path_ += Geek::System::GetEnvironmentVariable(L"_NT_ALTERNATE_SYMBOL_PATH") + L";";

		// �õ�ϵͳ��·�� ���� \\system32 ��·��
		auto system_root_path = Geek::System::GetEnvironmentVariable(L"SYSTEMROOT");
		if (!system_root_path.empty()) {
			sym_path_ += system_root_path + L";";
			sym_path_ += system_root_path + L"\\system" + L";";
		}

		// �õ� ϵͳ���� ��������
		// ������΢��Ĺٷ����߷��ű�
		auto system_drive_path = Geek::System::GetEnvironmentVariable(L"SYSTEMDRIVE");
		if (system_drive_path.empty()) {
			system_drive_path = L"c:";
		}
		sym_path_ += L"SRV*" + system_drive_path + L"\\websysbols*http://msdl.microsoft.com/download/symbols" + L";";

		if (SymInitializeW(process_->Get(), sym_path_.c_str(), FALSE) == FALSE) {
			return FALSE;
		}
		if (modules_loaded_ == FALSE) {
			this->LoadModules();
		}

		return TRUE;
	}


	~StackWalker() { }

	/*
	 * ����ģ���Ӧ�ķ���
	 */
	DWORD LoadModule(HANDLE hProcess, LPCWSTR img, LPCWSTR mod, DWORD64 baseAddr, DWORD size) {
		WCHAR* szImg = _wcsdup(img);
		WCHAR* szMod = _wcsdup(mod);
		DWORD result = ERROR_SUCCESS;
		if ((szImg == NULL) || (szMod == NULL)) {
			result = ERROR_NOT_ENOUGH_MEMORY;
		}
		else {
			if (SymLoadModuleExW(hProcess, 0, szImg, szMod, baseAddr, size, NULL, 0) == 0) {
				result = GetLastError();
			}
		}
		if (szImg != NULL) free(szImg);
		if (szMod != NULL) free(szMod);
		return result;
	}

	/**
	 * ö�ٽ���ģ�鲢Ϊÿ��ģ����ط���
	 */
	BOOL LoadModules() {
		DWORD	Threads[50];
		int		i = 0;
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_->GetId());
		if (hSnap == INVALID_HANDLE_VALUE) {
			return FALSE;
		}
		MODULEENTRY32 me;
		me.dwSize = sizeof(me);
		if (Module32First(hSnap, &me) == FALSE) {
			CloseHandle(hSnap);
			return FALSE;
		}
		do {
			LoadModule(process_->Get(), me.szExePath, me.szModule, (DWORD64)me.modBaseAddr, me.modBaseSize);
		} while (Module32Next(hSnap, &me) != FALSE);
		modules_loaded_ = TRUE;
		return TRUE;
	}


	CallStackEntry StackFrameToCallStackEntry(const STACKFRAME64& stack_frame) {
		CallStackEntry entry;
		entry.offset = stack_frame.AddrPC.Offset;// �����AddrPC������������� ����EIP/RIP��������λ��
		IMAGEHLP_MODULEW64 Module;
		memset(&Module, 0, sizeof(Module));
		Module.SizeOfStruct = sizeof(Module);

		IMAGEHLP_SYMBOL64* pSym = (IMAGEHLP_SYMBOL64*)malloc(sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
		if (!pSym) goto cleanup;  // �ڴ治��
		memset(pSym, 0, sizeof(IMAGEHLP_SYMBOL64) + STACKWALK_MAX_NAMELEN);
		pSym->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
		pSym->MaxNameLength = STACKWALK_MAX_NAMELEN;

		if (stack_frame.AddrPC.Offset != 0) {
			// �õ��˺Ϸ���IP
			// ��ʾ���������Ϣ(SymGetSymFromAddr64())
			if (SymGetSymFromAddr64(process_->Get(), stack_frame.AddrPC.Offset, &(entry.offset_from_smybol), pSym) != FALSE) {
				entry.func_name = pSym->Name;
			}

			// �õ�ģ����Ϣ (SymGetModuleInfo64())
			if (SymGetModuleInfoW64(process_->Get(), stack_frame.AddrPC.Offset, &Module) != FALSE) {
				entry.module_name = Module.ModuleName;
				entry.base_of_image = Module.BaseOfImage;
				entry.loaded_image_name = Module.LoadedImageName;
			}
		}

	cleanup:
		if (pSym) free(pSym);
		return entry;

	}

	std::vector<STACKFRAME64> RecordCallStack(DWORD thread_id = GetCurrentThreadId(), CallStackInfo* stack_info = nullptr) {
		std::vector<STACKFRAME64> res;
		res.reserve(30);

		CONTEXT context;
		memset(&context, 0, sizeof(context));

		Geek::Thread thread;
		thread.Open(thread_id);
		if (thread_id == GetCurrentThreadId()) {
			GET_CURRENT_CONTEXT(context, USED_CONTEXT_FLAGS);
		}
		else {
			thread.Suspend();
			context.ContextFlags = USED_CONTEXT_FLAGS;
			if (GetThreadContext(thread.Get(), &context) == FALSE)
			{
				thread.Resume();
				return res;
			}
		}

		// init STACKFRAME for first call
		// Ϊ��һ�ε��� ��ʼ�� STACKFRAME64 �ṹ
		/**
		* Ӧ�����ĳ�ʼ����
		* 1.	AddrPC ��ǰָ��ָ�루Eip in X86,Rip in X64,StIIP in IA 64)
		* 2.	AddrStack	��ǰ��ջָ��(Esp,Rsp,IntSp)
		* 3.	AddrFrame	��ǰָ֡��������ʱ(Ebg,Rsp(���ǲ����ã�VC2005B2,Rdi),RsBSP),StackWalk64���ڲ���Ҫչ��ʱ���Ը�ֵ
		* 4. ���� AddrBStore �� RsBSP	IA64
		*/
		STACKFRAME64 stack_frame; // in/out stackframe
		memset(&stack_frame, 0, sizeof(stack_frame));
		DWORD imageType;
#ifdef _M_IX86
		if (pc != 0) {
			context.Eip = pc;
		}
		if (stack != 0) {
			context.Esp = ebp;
			context.Esp = stack;
		}

		imageType = IMAGE_FILE_MACHINE_I386;
		stack_frame.AddrPC.Offset = context.Eip;
		stack_frame.AddrPC.Mode = AddrModeFlat;
		stack_frame.AddrFrame.Offset = context.Ebp;
		stack_frame.AddrFrame.Mode = AddrModeFlat;
		stack_frame.AddrStack.Offset = context.Esp;
		stack_frame.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
		if (stack_info->pc != 0) {
			context.Rip = stack_info->pc;
		}
		if (stack_info->stack != 0) {
			context.Rsp = stack_info->stack;
		}

		imageType = IMAGE_FILE_MACHINE_AMD64;
		stack_frame.AddrPC.Offset = context.Rip;
		stack_frame.AddrPC.Mode = AddrModeFlat;
		stack_frame.AddrFrame.Offset = context.Rsp;		/// �̵߳�ǰջ֡
		stack_frame.AddrFrame.Mode = AddrModeFlat;
		stack_frame.AddrStack.Offset = context.Rsp;		// �߳�ջ��
		stack_frame.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64
		imageType = IMAGE_FILE_MACHINE_IA64;
		s.AddrPC.Offset = c.StIIP;
		s.AddrPC.Mode = AddrModeFlat;
		s.AddrFrame.Offset = c.IntSp;
		s.AddrFrame.Mode = AddrModeFlat;
		s.AddrBStore.Offset = c.RsBSP;
		s.AddrBStore.Mode = AddrModeFlat;
		s.AddrStack.Offset = c.IntSp;
		s.AddrStack.Mode = AddrModeFlat;
#else
#error "Platform not supported!"
#endif

		s_stack_info = stack_info;

		for (int frameNum = 0; ; ++frameNum) {
			// ȡ��һ��ջ֡(StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64())
			// �����������ص��������Դ����Լ��Ļص�������Ҳ���Դ���DbgHelp.dll �Լ��ĺ���
			if (stack_info == nullptr) {
				if (!StackWalk64(imageType, process_->Get(), thread.Get(), &stack_frame, &context, myReadProcMem, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
					//printf("StackWalk64\t%d\n", GetLastError());
					break;
				}
			}
			else {
				if (!StackWalk64(imageType, process_->Get(), thread.Get(), &stack_frame, &context, myReadStack, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
					//printf("StackWalk64\t%d\n", GetLastError());
					break;
				}
			}

			// ShowMessage(csEntry);
			if (stack_frame.AddrReturn.Offset == 0) {
				// ���
				break;
			}
			res.push_back(stack_frame);
		}

		thread.Resume();
		return res;
	}

	void ShowMessage(FILE* file, const CallStackEntry& entry) {
		

		if (!entry.func_name.empty()) {
	#ifndef _M_X64
			fprintf(file, "    call address: %8p ", entry.offset);
			fprintf(file, "%ws", entry.module_name.c_str());
			fprintf(file, "!%s", entry.func_name.c_str());
			fprintf(file, "+0x%8p\n", entry.offset_from_smybol);
	#else
			fprintf(file, "    call address: %llx  %ws!%s+0x%llx \n", entry.offset, entry.module_name.c_str(), entry.func_name.c_str(), entry.offset_from_smybol);
	#endif
		}
		else {
	#ifndef _M_X64
			fprintf(file, "    call address: %llx\t%ws+0x%8p \n", entry.offset, entry.module_name.c_str(), entry.offset - entry.base_of_image);
	#else // !_M_X64
			fprintf(file, "    call address: %llx\t%ws+0x%llx \n", entry.offset, entry.module_name.c_str(), entry.offset - entry.base_of_image);
	#endif
		}
	}

public:
	static CallStackInfo RecordCallStackInfo(uint64_t any_stack_addr, uint64_t pc) {
		MEMORY_BASIC_INFORMATION info;
		// printf("%p\n", &context->stack[0]);
		VirtualQuery((void*)any_stack_addr, &info, sizeof(info));
		CallStackInfo call_stack_info;
		call_stack_info.base = (uint64_t)info.BaseAddress;
		call_stack_info.pc = pc;
		call_stack_info.stack = any_stack_addr;
		call_stack_info.buf.resize(info.RegionSize);
		memcpy(call_stack_info.buf.data(), info.BaseAddress, info.RegionSize);
		return call_stack_info;
	}


private:
	static BOOL __stdcall myReadProcMem(HANDLE hProcess, DWORD64 qwBaseAddress, PVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead) {
		SIZE_T st;
		BOOL bRet = ReadProcessMemory(hProcess, (LPVOID)qwBaseAddress, lpBuffer, nSize, &st);
		*lpNumberOfBytesRead = (DWORD)st;
		return bRet;
	}

private:
	inline static CallStackInfo* s_stack_info;
	static BOOL __stdcall myReadStack(HANDLE hProcess, DWORD64 qwBaseAddress, PVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead) {
		if (qwBaseAddress < s_stack_info->base || qwBaseAddress + nSize > s_stack_info->base + s_stack_info->buf.size()) {
			return myReadProcMem(hProcess, qwBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
		}
		auto offset = qwBaseAddress - s_stack_info->base;
		memcpy(lpBuffer, &s_stack_info->buf[offset], nSize);
		*lpNumberOfBytesRead = nSize;
		return true;
	}


protected:
	Geek::Process* process_;
	BOOL modules_loaded_;
	std::wstring sym_path_;
};



static bool StackWalkCustom(
	_In_ DWORD MachineType,
	_In_ HANDLE hProcess,
	_In_ HANDLE hThread,
	_Inout_ LPSTACKFRAME64 StackFrame,
	_Inout_ PVOID ContextRecord,
	_In_opt_ PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
	_In_opt_ PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
	_In_opt_ PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
	_In_opt_ PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress
) {
	// ��λջ�е�һ��
	StackFrame->AddrReturn.Offset = 1;
	do {
		MEMORY_BASIC_INFORMATION info;
		if (!VirtualQueryEx(GetCurrentProcess(), (void*)StackFrame->AddrFrame.Offset, &info, sizeof(info))) {
			break;
		}
		if (StackFrame->AddrFrame.Offset < (uint64_t)info.BaseAddress || StackFrame->AddrFrame.Offset + 8 >= (uint64_t)info.BaseAddress + info.RegionSize) {
			break;
		}

		StackFrame->AddrFrame.Offset += 8;
		uint64_t stack_data = *((uint64_t*)(StackFrame->AddrFrame.Offset));


		if (!VirtualQueryEx(GetCurrentProcess(), (void*)stack_data, &info, sizeof(info))) {
			continue;
		}
		if (stack_data < (uint64_t)info.BaseAddress || stack_data >= (uint64_t)info.BaseAddress + info.RegionSize) {
			break;
		}

		if (info.Protect & 0xf0) {
			// ��ִ��
			StackFrame->AddrPC.Offset = stack_data;
			return true;
		}

	} while (true);

	return false;
}
