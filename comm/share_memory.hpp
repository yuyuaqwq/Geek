#ifndef GEEK_COMM_SHARE_MEMORY_H_
#define GEEK_COMM_SHARE_MEMORY_H_

#include <Geek/sync/event.hpp>
#include <Geek/ring_queue.hpp>
#include <Geek/process/process.hpp>


namespace Geek {
namespace comm {


class ShareMemory {
public:
    ShareMemory() : base_{ nullptr }{
    }

    bool Create(const std::wstring& name, size_t max_buf_size = 0x1000) {
        if (max_buf_size < 0x1000) {
            max_buf_size = 0x1000;
        }
        max_buf_size += 0x100;
        sync::Event temp_server_readable_event;
        if (!temp_server_readable_event.Create((L"Geek_ShareMemory_Server_ReadableEvent_" + name).c_str(), false)) {
            return false;
        }
        sync::Event temp_server_writable_event;
        if (!temp_server_writable_event.Create((L"Geek_ShareMemory_Server_WritableEvent_" + name).c_str(), false)) {
            return false;
        }
        sync::Event temp_client_readable_event;
        if (!temp_client_readable_event.Create((L"Geek_ShareMemory_Client_ReadableEvent_" + name).c_str(), false)) {
            return false;
        }
        sync::Event temp_client_writable_event;
        if (!temp_client_writable_event.Create((L"Geek_ShareMemory_Client_WritableEvent_" + name).c_str(), false)) {
            return false;
        }
        UniqueHandle temp_memory_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, max_buf_size >> 32, max_buf_size & 0xffffffff, (L"Geek_ShareMemory_Map_" + name).c_str());
        if (!temp_memory_map.IsValid()) {
            return false;
        }
        base_ = MapViewOfFile(temp_memory_map.Get(), FILE_MAP_ALL_ACCESS, 0, max_buf_size >> 32, max_buf_size & 0xffffffff);
        if (!base_) {
            return false;
        }
        server_readable_event_ = std::move(temp_server_readable_event);
        server_writable_event_ = std::move(temp_server_writable_event);
        client_readable_event_ = std::move(temp_client_readable_event);
        client_writable_event_ = std::move(temp_client_writable_event);
        memory_map_ = std::move(temp_memory_map);

        share_info_ = (ShareInfo*)base_;

        size_t size = ((max_buf_size - 0x100) / 2);

        share_info_->server_send_queue_.Reset((uint8_t*)base_ + 0x100, size);
        share_info_->client_send_queue_.Reset((uint8_t*)base_ + 0x100 + size, size);

        is_server_ = true;
    }

    bool Connect(const std::wstring& name) {
        sync::Event temp_server_readable_event;
        if (!temp_server_readable_event.Open((L"Geek_ShareMemory_Server_ReadableEvent_" + name).c_str())) {
            return false;
        }
        sync::Event temp_server_writable_event;
        if (!temp_server_writable_event.Open((L"Geek_ShareMemory_Server_WritableEvent_" + name).c_str())) {
            return false;
        }
        sync::Event temp_client_readable_event;
        if (!temp_client_readable_event.Open((L"Geek_ShareMemory_Client_ReadableEvent_" + name).c_str())) {
            return false;
        }
        sync::Event temp_client_writable_event;
        if (!temp_client_writable_event.Open((L"Geek_ShareMemory_Client_WritableEvent_" + name).c_str())) {
            return false;
        }
        UniqueHandle temp_memory_map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, (L"Geek_ShareMemory_Map_" + name).c_str());
        if (!temp_memory_map.IsValid()) {
            return false;
        }
        base_ = MapViewOfFile(temp_memory_map.Get(), FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!base_) {
            return false;
        }
        server_readable_event_ = std::move(temp_server_readable_event);
        server_writable_event_ = std::move(temp_server_writable_event);
        client_readable_event_ = std::move(temp_client_readable_event);
        client_writable_event_ = std::move(temp_client_writable_event);
        memory_map_ = std::move(temp_memory_map);

        share_info_ = (ShareInfo*)base_;

        is_server_ = false;
    }

    void Close() {
        if (base_) UnmapViewOfFile(base_);
    }

    void write(const char* str, std::streamsize size) {
        RingQueue<uint8_t>* queue;
        sync::Event* readable_event_, * writable_event_;
        if (is_server_) {
            queue = &share_info_->server_send_queue_;
            readable_event_ = &server_readable_event_;
            writable_event_ = &server_writable_event_;
        }
        else {
            queue = &share_info_->client_send_queue_;
            readable_event_ = &client_readable_event_;
            writable_event_ = &client_writable_event_;
        }

        for (uint64_t i = 0; i < size; i++) {
            while (!queue->Enqueue(std::move(((uint8_t*)str)[i]))) {
                // 环形队列写满了，通知可读事件，并等待可写事件
                readable_event_->Set();
                writable_event_->Wait();
                //Sleep(0);
            }
        }
        // 可能有读事件在等待可读，通知一下
        readable_event_->Set();
    }

    void read(char* str, std::streamsize size) {
        RingQueue<uint8_t>* queue;
        sync::Event* readable_event_, * writable_event_;
        if (is_server_) {
            queue = &share_info_->client_send_queue_;
            readable_event_ = &client_readable_event_;
            writable_event_ = &client_writable_event_;
        }
        else {
            queue = &share_info_->server_send_queue_;
            readable_event_ = &server_readable_event_;
            writable_event_ = &server_writable_event_;
        }

        for (uint64_t i = 0; i < size; i++) {
            while (!queue->Dequeue(&((uint8_t*)str)[i])) {
                // 环形队列没有数据，通知可写事件，并等待可读事件
                writable_event_->Set();
                readable_event_->Wait();
                //Sleep(0);
            }
        }
        // 可能有写事件在等待可写，通知一下
        writable_event_->Set();
    }

    void SendPackage(void* buf, uint64_t size) {
        write((char*)&size, sizeof(size));
        write((char*)buf, size);
    }

    std::vector<uint8_t> RecvPackage() {
        uint64_t size;
        read((char*)&size, sizeof(uint64_t));
        std::vector<uint8_t> data(size);
        read((char*)data.data(), size);
        return data;
    }


private:
    struct ShareInfo {
        RingQueue<uint8_t> server_send_queue_;
        RingQueue<uint8_t> client_send_queue_;
    };

    bool is_server_;
    sync::Event server_readable_event_;
    sync::Event server_writable_event_;
    sync::Event client_readable_event_;
    sync::Event client_writable_event_;

    UniqueHandle memory_map_;
    void* base_;
    ShareInfo* share_info_;
};


}
}

#endif GEEK_COMM_SHARE_MEMORY_H_