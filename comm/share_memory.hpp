#ifndef GEEK_COMM_SHARE_MEMORY_H_
#define GEEK_COMM_SHARE_MEMORY_H_

#include <Geek/sync/event.hpp>
#include <Geek/ring_queue.hpp>
#include <Geek/process/process.hpp>


namespace Geek {
namespace comm {

namespace internal {
struct Buffer {
    Buffer() : base_{ nullptr }, size_{0}  {

    }
    Buffer(void* base, size_t size) : base_{ (uint8_t*)base }, size_{ size } {

    }

    void resize(size_t size) {

    }

    size_t size() {
        return size_;
    }

    uint8_t& operator[](ptrdiff_t i) {
        return base_[i];
    }

    uint8_t* base_;
    size_t size_;
};
}

class ShareMemory {
public:
    ShareMemory() : base_{ nullptr }, queue_{}{
    }

    bool Create(const std::wstring& name, size_t max_buf_size = 4096) {
        if (max_buf_size < 4096) {
            max_buf_size = 4096;
        }
        sync::Event temp_event;
        if (!temp_event.Create((L"Geek_Event_" + name).c_str())) {
            return false;
        }
        UniqueHandle temp_memory_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, max_buf_size >> 32, max_buf_size & 0xffffffff, (L"Geek_Map_" + name).c_str());
        if (!temp_memory_map.IsValid()) {
            return false;
        }
        base_ = MapViewOfFile(temp_memory_map.Get(), FILE_MAP_ALL_ACCESS, 0, max_buf_size >> 32, max_buf_size & 0xffffffff);
        if (!base_) {
            return false;
        }
        event_ = std::move(temp_event);
        memory_map_ = std::move(temp_memory_map);
        queue_ = (RingQueue<uint8_t, internal::Buffer>*)base_;
        queue_->Reset(internal::Buffer(((uint8_t*)base_) + 0x100, max_buf_size));
    }

    bool WaitConnect() {

    }
    
    bool Connect(const std::wstring& name) {
        sync::Event temp_event;
        if (!temp_event.Open((L"Geek_Event_" + name).c_str())) {
            return false;
        }
        UniqueHandle temp_memory_map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, (L"Geek_Map_" + name).c_str());
        if (!temp_memory_map.IsValid()) {
            return false;
        }
        base_ = MapViewOfFile(temp_memory_map.Get(), FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!base_) {
            return false;
        }
        event_ = std::move(temp_event);
        memory_map_ = std::move(temp_memory_map);

        queue_ = (RingQueue<uint8_t, internal::Buffer>*)base_;
    }

    void Close() {
        if (base_) UnmapViewOfFile(base_);
    }

    void SendPackage(void* buf, uint64_t size) {
        queue_->Enquene((uint8_t*)&size, sizeof(uint64_t));
        queue_->Enquene((uint8_t*)buf, size);
    }

    std::vector<uint8_t> RecvPackage() {
        uint64_t size;
        queue_->Dequeue((uint8_t*)&size, sizeof(uint64_t));
        std::vector<uint8_t> data(size);
        queue_->Dequeue(data.data(), size);
        return data;
    }


private:
    sync::Event event_;
    UniqueHandle memory_map_;
    void* base_;
    RingQueue<uint8_t, internal::Buffer>* queue_;
};


}
}

#endif GEEK_COMM_SHARE_MEMORY_H_