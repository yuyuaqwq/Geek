#ifndef GEEK_MEMORY_H_
#define GEEK_MEMORY_H_

#include <exception>
#include <memory>

#include <Windows.h>

#include <Process\Process.h>

namespace geek {

class MemoryException {
public:
	enum class Type {
		kReadProcessMemoryError,
		kWriteProcessMemoryError,
	};

public:
	MemoryException(Type t_type, const char* t_msg = "") noexcept : m_type{ m_type }, std::exception{ t_msg } {
		m_type = t_type;
	}

public:
	Type GetType() const noexcept {
		return m_type;
	}

private:
	Type m_type;
};


template<typename T>
class Memory {
public:
	explicit Memory(T* t_ptr, Process* t_process = nullptr) noexcept : m_ptr{ t_ptr }, m_mode{ Ownership::kWeak }, m_process{ t_process } {
		
	};
	explicit Memory(std::unique_ptr<T> t_ptr, Process* t_process = nullptr) noexcept : m_ptr{ t_ptr.release() }, m_mode{ Ownership::kUnique }, m_process{ t_process } {
		
	};
	~Memory() noexcept {
		if (m_mode == Ownership::kUnique && m_mode != nullptr) {
			delete m_ptr;
		}
	}

public:
	
	inline T* Get() const noexcept {
		return m_ptr;
	}

	inline T* Get(int inedx) const noexcept {
		return m_ptr + index;
	}

	std::unique_ptr<T> Read(size_t tOffset, size_t tCount = 1) {
		std::unique_ptr<T> buf{ new T[tCount] };
		DWORD readByte;
		if (!ReadProcessMemory(m_process->Get(), m_ptr + tOffset, buf.get(), tCount * sizeof(T), &readByte)) {
			throw MemoryException(MemoryException::Type::kReadProcessMemoryError);
		}
		return buf;
	}

	void Write(void* buf, size_t byteOffset, size_t byteCount) {
		DWORD readByte;
		if (!WriteProcessMemory(m_process->Get(), (char*)m_ptr + byteOffset, buf, byteCount, &readByte)) {
			throw MemoryException(MemoryException::Type::kWriteProcessMemoryError);
		}
	}


	inline bool Valid() const noexcept {
		return m_ptr == nullptr;
	}

private:
	inline void Close() noexcept {

	}

private:
	enum class Ownership {
		kUnique,
		kWeak,
		// kShared,
	};

private:
	Ownership m_mode;
	T* m_ptr;
	size_t m_byteCount;
	Process* m_process;
};

} // namespace geek

#endif // GEEK_HANDLE_H_
