#ifndef GEEK_PAGE_HOOK_H_
#define GEEK_PAGE_HOOK_H_

#include <type_traits>
#include <map>

#include <Windows.h>


namespace geek {

// �����������ӻᵼ��ʵ�ʺ�����ַ��ͨ����������ȡ�ĵ�ַ��һ��
class PageHook {
public:
	typedef void (*HookCallBack)(LPCONTEXT context);

public:
	enum class Error {
		kDuplicateAddress,
		kSetProtectFailed,
		kRepeatInstall,
		kRepeatUninstall,
	};


public:
	PageHook() {
		mStatus = Status::kInvalid;
		mHookAddr = nullptr;
		mCallback = nullptr;

		if (msVEHCount == 0) {
			// ע��VEH
			mExceptionHandlerHandle = AddVectoredExceptionHandler(TRUE, ExceptionHandler);
		}
		++msVEHCount;
	}

	~PageHook() noexcept {
		--msVEHCount;
		if (msVEHCount == 0) {
			// �Ƴ�VEH
			RemoveVectoredExceptionHandler(mExceptionHandlerHandle);
		}

		Uninstall();
	}


public:
	// ��װHook
	void Install(LPVOID hookAddr, HookCallBack callback) {
		if (mStatus == Status::kValid) {
			throw Error::kRepeatInstall;
		}

		auto it_addr = msPageHook_addr.find(hookAddr);
		if (it_addr != msPageHook_addr.end()) {
			throw Error::kDuplicateAddress;
		}

		LPVOID pageBase = PageAlignment(hookAddr);

		mHookAddr = hookAddr;
		mCallback = callback;
		mStatus = Status::kValid;

		msPageHook_addr.insert(std::pair<LPVOID, PageHook&>(hookAddr, *this));
		auto it_base = msPageHook_base.find(pageBase);
		if (it_base == msPageHook_base.end()) {
			PageRecord pageRecord;
			pageRecord.count = 1;
			pageRecord.pageBase = pageBase;
			pageRecord.protect = 0;
			msPageHook_base.insert(std::pair<LPVOID, PageRecord>(pageBase, pageRecord));
			it_base = msPageHook_base.find(pageBase);
			if (!VirtualProtect(pageBase, 0x1000, PAGE_READONLY, &it_base->second.protect)) {
				Uninstall();
				throw Error::kSetProtectFailed;
			}
		}
		else {
			++it_base->second.count;
		}
	}

	// ж��Hook
	void Uninstall() noexcept {
		if (mStatus == Status::kInvalid) {
			return;
		}

		LPVOID pageBase = PageAlignment(mHookAddr);
		auto it_base = msPageHook_base.find(pageBase);

		if (it_base != msPageHook_base.end()) {
			if (it_base->second.count == 1) {
				if (!VirtualProtect(pageBase, 0x1000, it_base->second.protect, &it_base->second.protect)) {
					throw Error::kSetProtectFailed;
				}
				msPageHook_base.erase(it_base);
			}
			else {
				--it_base->second.count;
			}
		}

		msPageHook_addr.erase(mHookAddr);

		mHookAddr = nullptr;
		mCallback = nullptr;

		mStatus = Status::kInvalid;
	}



private:
	enum class Status {
		kInvalid,
		kValid,
	};

	struct PageRecord {
		LPVOID pageBase;
		size_t count;
		DWORD protect;
	};

private:
	static LPVOID PageAlignment(LPVOID addr) {
		return (LPVOID)((UINT_PTR)addr & (UINT_PTR)(~0xfff));
	}

	static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {

		// �ж��쳣����
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

			LPVOID pageBase = PageAlignment(ExceptionInfo->ExceptionRecord->ExceptionAddress);
			auto it_base = msPageHook_base.find(pageBase);
			if (it_base == msPageHook_base.end()) {
				// �����������õ�ҳ�����Բ������쳣������
				return EXCEPTION_CONTINUE_SEARCH;
			}

			// ִ�е�ָ�������ǵ�Hookλ��ͬһҳ�棬�ָ�ԭ������
			DWORD uselessProtect;
			VirtualProtect(pageBase, 0x1000, it_base->second.protect, &uselessProtect);


			// ��ȡ�����쳣���̵߳�������
			LPCONTEXT context = ExceptionInfo->ContextRecord;


			auto it_addr = msPageHook_addr.find(ExceptionInfo->ExceptionRecord->ExceptionAddress);
			if (it_addr != msPageHook_addr.end()) {
				// �Ǳ�hook�ĵ�ַ

				// ���ûص�
				it_addr->second.mCallback(context);
			}

			// ���õ����������壬���ڵ������������ô�Hook
			context->EFlags |= 0x100;

			// ����ʶ���Ƿ��������õĵ���
			msPageHook_step.insert(std::pair<DWORD, PageRecord&>(GetCurrentThreadId(), it_base->second));


			//�쳣������� �ó������ִ��
			return EXCEPTION_CONTINUE_EXECUTION;


		}
		else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		{
			LPCONTEXT pContext = ExceptionInfo->ContextRecord;

			// �ж��Ƿ�DR�Ĵ����������쳣
			if (pContext->Dr6 & 0xf) {
				// �ų�DR�Ĵ��������ĵ����쳣
				return EXCEPTION_CONTINUE_SEARCH;
			}
			else {
				// �����쳣
				auto it = msPageHook_step.find(GetCurrentThreadId());
				if (it == msPageHook_step.end()) {
					//�����������õĵ����ϵ㣬������
					return EXCEPTION_CONTINUE_SEARCH;
				}


				DWORD uselessProtect;
				// �ָ�Hook
				VirtualProtect(it->second.pageBase, 0x1000, PAGE_READWRITE, &uselessProtect);

				msPageHook_step.erase(GetCurrentThreadId());

				// ����Ҫ����TF�������쳣�Զ���TF��0
				// �����쳣���������쳣�������޸�ip

				// �쳣������� �ó������ִ��
				return EXCEPTION_CONTINUE_EXECUTION;
			}

		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

private:
	Status mStatus;
	LPVOID mExceptionHandlerHandle;
	LPVOID mHookAddr;
	HookCallBack mCallback;

	// C++17
	inline static int msVEHCount = 0;
	inline static std::map<LPVOID, PageRecord> msPageHook_base;
	inline static std::map<LPVOID, PageHook&> msPageHook_addr;
	inline static std::map<DWORD, PageRecord&> msPageHook_step;
};

} // namespace PageHook

#endif // GEEK_INLINE_HOOK_H_
