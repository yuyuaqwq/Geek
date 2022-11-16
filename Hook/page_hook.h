#ifndef GEEK_PAGE_HOOK_H_
#define GEEK_PAGE_HOOK_H_

#include <type_traits>
#include <map>

#include <Windows.h>


namespace geek {

// 启用增量链接会导致实际函数地址与通过函数名获取的地址不一致
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
			// 注册VEH
			mExceptionHandlerHandle = AddVectoredExceptionHandler(TRUE, ExceptionHandler);
		}
		++msVEHCount;
	}

	~PageHook() noexcept {
		--msVEHCount;
		if (msVEHCount == 0) {
			// 移除VEH
			RemoveVectoredExceptionHandler(mExceptionHandlerHandle);
		}

		Uninstall();
	}


public:
	// 安装Hook
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

	// 卸载Hook
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

		// 判断异常类型
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

			LPVOID pageBase = PageAlignment(ExceptionInfo->ExceptionRecord->ExceptionAddress);
			auto it_base = msPageHook_base.find(pageBase);
			if (it_base == msPageHook_base.end()) {
				// 不是咱们设置的页面属性产生的异常，忽略
				return EXCEPTION_CONTINUE_SEARCH;
			}

			// 执行的指令与我们的Hook位于同一页面，恢复原有属性
			DWORD uselessProtect;
			VirtualProtect(pageBase, 0x1000, it_base->second.protect, &uselessProtect);


			// 获取发生异常的线程的上下文
			LPCONTEXT context = ExceptionInfo->ContextRecord;


			auto it_addr = msPageHook_addr.find(ExceptionInfo->ExceptionRecord->ExceptionAddress);
			if (it_addr != msPageHook_addr.end()) {
				// 是被hook的地址

				// 调用回调
				it_addr->second.mCallback(context);
			}

			// 设置单步触发陷阱，用于单步后重新启用此Hook
			context->EFlags |= 0x100;

			// 用于识别是否咱们设置的单步
			msPageHook_step.insert(std::pair<DWORD, PageRecord&>(GetCurrentThreadId(), it_base->second));


			//异常处理完成 让程序继续执行
			return EXCEPTION_CONTINUE_EXECUTION;


		}
		else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		{
			LPCONTEXT pContext = ExceptionInfo->ContextRecord;

			// 判断是否DR寄存器触发的异常
			if (pContext->Dr6 & 0xf) {
				// 排除DR寄存器触发的单步异常
				return EXCEPTION_CONTINUE_SEARCH;
			}
			else {
				// 单步异常
				auto it = msPageHook_step.find(GetCurrentThreadId());
				if (it == msPageHook_step.end()) {
					//不是咱们设置的单步断点，不处理
					return EXCEPTION_CONTINUE_SEARCH;
				}


				DWORD uselessProtect;
				// 恢复Hook
				VirtualProtect(it->second.pageBase, 0x1000, PAGE_READWRITE, &uselessProtect);

				msPageHook_step.erase(GetCurrentThreadId());

				// 不需要重设TF，单步异常自动将TF置0
				// 单步异常是陷阱类异常，无需修复ip

				// 异常处理完成 让程序继续执行
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
