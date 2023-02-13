#ifndef GEEK_HOOK_PAGE_HOOK_H_
#define GEEK_HOOK_PAGE_HOOK_H_

#include <type_traits>
#include <map>

#include <Windows.h>


namespace geek {

// 启用增量链接会导致实际函数地址与通过函数名获取的地址不一致
// 对数据进行读写hook时，保证类中的内联静态成员与外部变量不在同一页面
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
		m_status = Status::kNormal;
		m_hook_addr = nullptr;
		m_callback = nullptr;

		if (ms_veh_count == 0) {
			// 注册VEH
			m_exception_handler_handle = AddVectoredExceptionHandler(TRUE, ExceptionHandler);
		}
		++ms_veh_count;
	}

	~PageHook() {
		--ms_veh_count;
		if (ms_veh_count == 0) {
			// 移除VEH
			RemoveVectoredExceptionHandler(m_exception_handler_handle);
		}

		Uninstall();
	}


public:
	// 安装Hook，protect用于控制被hook页面的保护属性以触发hook
	bool Install(void* hookAddr, HookCallBack callback, DWORD protect = PAGE_READONLY) {
		if (m_status == Status::kNormal) {
			m_status = Status::kRepeatInstall;
			return false;
		}

		auto it_addr = ms_page_hook_addr.find(hookAddr);
		if (it_addr != ms_page_hook_addr.end()) {
			m_status = Status::kDuplicateAddress;
			return false;
		}

		LPVOID page_base = PageAlignment(hookAddr);

		m_hook_addr = hookAddr;
		m_callback = callback;
		m_status = Status::kNormal;

		ms_page_hook_addr.insert(std::pair<void*, PageHook&>(hookAddr, *this));
		auto it_base = ms_page_hook_base.find(page_base);
		if (it_base == ms_page_hook_base.end()) {
			PageRecord pageRecord;
			pageRecord.count = 1;
			pageRecord.page_base = page_base;
			pageRecord.protect = 0;
			ms_page_hook_base.insert(std::pair<void*, PageRecord>(page_base, pageRecord));
			it_base = ms_page_hook_base.find(page_base);
			if (!VirtualProtect(page_base, 0x1000, protect, &it_base->second.protect)) {
				Uninstall();
				m_status = Status::kSetProtectFailed;
				return false;
			}
		}
		else {
			++it_base->second.count;
		}
		return true;
	}

	// 卸载Hook
	bool Uninstall() noexcept {
		if (m_status != Status::kNormal) {
			return true;
		}

		LPVOID page_base = PageAlignment(m_hook_addr);
		auto it_base = ms_page_hook_base.find(page_base);

		if (it_base != ms_page_hook_base.end()) {
			if (it_base->second.count == 1) {
				if (!VirtualProtect(page_base, 0x1000, it_base->second.protect, &it_base->second.protect)) {
					m_status = Status::kSetProtectFailed;
					return false;
				}
				ms_page_hook_base.erase(it_base);
			}
			else {
				--it_base->second.count;
			}
		}

		ms_page_hook_addr.erase(m_hook_addr);

		m_hook_addr = nullptr;
		m_callback = nullptr;

		m_status = Status::kUnhooked;
		return true;
	}


private:

	struct PageRecord {
		LPVOID page_base;
		size_t count;
		DWORD protect;
	};

private:
	static LPVOID PageAlignment(LPVOID addr) noexcept {
		return (LPVOID)((UINT_PTR)addr & (UINT_PTR)(~0xfff));
	}

	static LONG NTAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {

		// 判断异常类型
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

			LPVOID address = (LPVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
			LPVOID page_base = PageAlignment(address);
			auto it_base = ms_page_hook_base.find(page_base);
			if (it_base == ms_page_hook_base.end()) {
				// 不是我们设置的页面属性产生的异常，忽略
				return EXCEPTION_CONTINUE_SEARCH;
			}

			// 执行的指令与我们的Hook位于同一页面，恢复原有属性
			VirtualProtect(page_base, 0x1000, it_base->second.protect, &it_base->second.protect);

			// 获取发生异常的线程的上下文
			LPCONTEXT context = ExceptionInfo->ContextRecord;


			auto it_addr = ms_page_hook_addr.find(address);
			if (it_addr != ms_page_hook_addr.end()) {
				// 是被hook的地址

				// 调用回调
				it_addr->second.mCallback(context);
			}

			// 设置单步触发陷阱，用于单步后重新启用此Hook
			context->EFlags |= 0x100;

			// 用于识别是否咱们设置的单步
			ms_page_hook_step.insert(std::pair<DWORD, PageRecord&>(GetCurrentThreadId(), it_base->second));

			// 异常处理完成 让程序继续执行
			return EXCEPTION_CONTINUE_EXECUTION;


		}
		else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		{
			LPCONTEXT context = ExceptionInfo->ContextRecord;

			// 判断是否DR寄存器触发的异常
			if (context->Dr6 & 0xf) {
				// 排除DR寄存器触发的单步异常
				return EXCEPTION_CONTINUE_SEARCH;
			}
			else {
				// 单步异常
				auto it = ms_page_hook_step.find(GetCurrentThreadId());
				if (it == ms_page_hook_step.end()) {
					//不是咱们设置的单步断点，不处理
					return EXCEPTION_CONTINUE_SEARCH;
				}


				DWORD uselessProtect;
				// 恢复Hook
				VirtualProtect(it->second.page_base, 0x1000, it->second.protect, &it->second.protect);

				ms_page_hook_step.erase(GetCurrentThreadId());

				// 不需要重设TF，单步异常自动将TF置0
				// 单步异常是陷阱类异常，无需修复ip

				// 异常处理完成 让程序继续执行
				return EXCEPTION_CONTINUE_EXECUTION;
			}

		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

private:
	Status m_status;
	void* m_exception_handler_handle;
	void* m_hook_addr;
	HookCallBack m_callback;

	// C++17
	inline static int ms_veh_count = 0;
	inline static std::map<void*, PageRecord> ms_page_hook_base;
	inline static std::map<void*, PageHook&> ms_page_hook_addr;
	inline static std::map<DWORD, PageRecord&> ms_page_hook_step;
};

} // namespace PageHook

#endif // GEEK_HOOK_PAGE_HOOK_H_
