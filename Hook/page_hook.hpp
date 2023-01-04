#ifndef GEEK_HOOK_PAGE_HOOK_H_
#define GEEK_HOOK_PAGE_HOOK_H_

#include <type_traits>
#include <map>

#include <Windows.h>


namespace geek {

// �����������ӻᵼ��ʵ�ʺ�����ַ��ͨ����������ȡ�ĵ�ַ��һ��
// �����ݽ��ж�дhookʱ����֤���е�������̬��Ա���ⲿ��������ͬһҳ��
class PageHook {
public:
	typedef void (*HookCallBack)(LPCONTEXT context);

public:
	enum class Status {
		kNormal = 0,
		kUnhooked,
		kDuplicateAddress,
		kSetProtectFailed,
		kRepeatInstall,
		kRepeatUninstall,
	};


public:
	PageHook() {
		mStatus = Status::kNormal;
		mHookAddr = nullptr;
		mCallback = nullptr;

		if (msVEHCount == 0) {
			// ע��VEH
			mExceptionHandlerHandle = AddVectoredExceptionHandler(TRUE, ExceptionHandler);
		}
		++msVEHCount;
	}

	~PageHook() {
		--msVEHCount;
		if (msVEHCount == 0) {
			// �Ƴ�VEH
			RemoveVectoredExceptionHandler(mExceptionHandlerHandle);
		}

		Uninstall();
	}


public:
	// ��װHook��protect���ڿ��Ʊ�hookҳ��ı��������Դ���hook
	bool Install(void* hookAddr, HookCallBack callback, DWORD protect = PAGE_READONLY) {
		if (mStatus == Status::kNormal) {
			mStatus = Status::kRepeatInstall;
			return false;
		}

		auto it_addr = msPageHookAddr.find(hookAddr);
		if (it_addr != msPageHookAddr.end()) {
			mStatus = Status::kDuplicateAddress;
			return false;
		}

		LPVOID pageBase = PageAlignment(hookAddr);

		mHookAddr = hookAddr;
		mCallback = callback;
		mStatus = Status::kNormal;

		msPageHookAddr.insert(std::pair<void*, PageHook&>(hookAddr, *this));
		auto it_base = msPageHookBase.find(pageBase);
		if (it_base == msPageHookBase.end()) {
			PageRecord pageRecord;
			pageRecord.count = 1;
			pageRecord.pageBase = pageBase;
			pageRecord.protect = 0;
			msPageHookBase.insert(std::pair<void*, PageRecord>(pageBase, pageRecord));
			it_base = msPageHookBase.find(pageBase);
			if (!VirtualProtect(pageBase, 0x1000, protect, &it_base->second.protect)) {
				Uninstall();
				mStatus = Status::kSetProtectFailed;
				return false;
			}
		}
		else {
			++it_base->second.count;
		}
		return true;
	}

	// ж��Hook
	bool Uninstall() noexcept {
		if (mStatus != Status::kNormal) {
			return true;
		}

		LPVOID pageBase = PageAlignment(mHookAddr);
		auto it_base = msPageHookBase.find(pageBase);

		if (it_base != msPageHookBase.end()) {
			if (it_base->second.count == 1) {
				if (!VirtualProtect(pageBase, 0x1000, it_base->second.protect, &it_base->second.protect)) {
					mStatus = Status::kSetProtectFailed;
					return false;
				}
				msPageHookBase.erase(it_base);
			}
			else {
				--it_base->second.count;
			}
		}

		msPageHookAddr.erase(mHookAddr);

		mHookAddr = nullptr;
		mCallback = nullptr;

		mStatus = Status::kUnhooked;
		return true;
	}


private:

	struct PageRecord {
		LPVOID pageBase;
		size_t count;
		DWORD protect;
	};

private:
	static LPVOID PageAlignment(LPVOID addr) noexcept {
		return (LPVOID)((UINT_PTR)addr & (UINT_PTR)(~0xfff));
	}

	static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {

		// �ж��쳣����
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

			LPVOID address = (LPVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
			LPVOID pageBase = PageAlignment(address);
			auto it_base = msPageHookBase.find(pageBase);
			if (it_base == msPageHookBase.end()) {
				// �����������õ�ҳ�����Բ������쳣������
				return EXCEPTION_CONTINUE_SEARCH;
			}

			// ִ�е�ָ�������ǵ�Hookλ��ͬһҳ�棬�ָ�ԭ������
			VirtualProtect(pageBase, 0x1000, it_base->second.protect, &it_base->second.protect);

			// ��ȡ�����쳣���̵߳�������
			LPCONTEXT context = ExceptionInfo->ContextRecord;


			auto it_addr = msPageHookAddr.find(address);
			if (it_addr != msPageHookAddr.end()) {
				// �Ǳ�hook�ĵ�ַ

				// ���ûص�
				it_addr->second.mCallback(context);
			}

			// ���õ����������壬���ڵ������������ô�Hook
			context->EFlags |= 0x100;

			// ����ʶ���Ƿ��������õĵ���
			msPageHookStep.insert(std::pair<DWORD, PageRecord&>(GetCurrentThreadId(), it_base->second));

			// �쳣������� �ó������ִ��
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
				auto it = msPageHookStep.find(GetCurrentThreadId());
				if (it == msPageHookStep.end()) {
					//�����������õĵ����ϵ㣬������
					return EXCEPTION_CONTINUE_SEARCH;
				}


				DWORD uselessProtect;
				// �ָ�Hook
				VirtualProtect(it->second.pageBase, 0x1000, it->second.protect, &it->second.protect);

				msPageHookStep.erase(GetCurrentThreadId());

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
	void* mExceptionHandlerHandle;
	void* mHookAddr;
	HookCallBack mCallback;

	// C++17
	inline static int msVEHCount = 0;
	inline static std::map<void*, PageRecord> msPageHookBase;
	inline static std::map<void*, PageHook&> msPageHookAddr;
	inline static std::map<DWORD, PageRecord&> msPageHookStep;
};

} // namespace PageHook

#endif // GEEK_HOOK_PAGE_HOOK_H_
