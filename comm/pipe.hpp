#ifndef GEEK_COMM_PIPE_H_
#define GEEK_COMM_PIPE_H_

#include <string>
#include <vector>

#include <Windows.h>
#include <geek/handle.hpp>


namespace Geek {

class Pipe {
public:
    bool Create(const std::wstring& name, size_t buf_size = 0x1000, DWORD open_mode = PIPE_ACCESS_DUPLEX, DWORD pipe_mode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT) {
        m_buf_size = buf_size;
        m_pipe_handle.Reset(CreateNamedPipeW((LR"(\\.\pipe\Geek_Pipe_)" + name).c_str(), open_mode, pipe_mode, 1, buf_size, buf_size, 0, NULL));
        return m_pipe_handle.IsValid();
    }

    void WaitConnect() {
        ConnectNamedPipe(m_pipe_handle.Get(), NULL);
    }

    bool Connect(const std::wstring& name) {
        if (!WaitNamedPipeW((LR"(\\.\pipe\Geek_Pipe_)" + name).c_str(), NMPWAIT_USE_DEFAULT_WAIT)) {
            return false;
        }
        m_pipe_handle.Reset(CreateFileW((LR"(\\.\pipe\Geek_Pipe_)" + name).c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL));
        if (!m_pipe_handle.IsValid()) {
            return false;
        }
        DWORD dwMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
        if (!SetNamedPipeHandleState(m_pipe_handle.Get(), &dwMode, NULL, NULL)) {
            return false;
        }
        return true;
    }

    bool Disconnect() {
        if (m_pipe_handle.IsValid()) {
            return DisconnectNamedPipe(m_pipe_handle.Get());
        }
        return false;
    }

    std::vector<uint8_t> Recv() {
        std::vector<uint8_t> packet(4096);
        DWORD read_len;
        uint8_t* ptr = packet.data();
        bool success = false;
        int64_t i = 0;
        do {
            success = ReadFile(m_pipe_handle.Get(), ptr, 4096, &read_len, NULL);
            if (read_len == 0) {
                continue;
            }
            if (!success && GetLastError() != ERROR_MORE_DATA) {
                packet.clear();
                break;
            }
            if (success) {
                i += read_len;
                packet.resize(read_len);
                break;
            }
            packet.resize(packet.size() + 4096);
            ptr = &packet[i+=4096ll];
        } while (true);
        return packet;
    }

    bool Send(const void* buf, size_t len) {
        DWORD write_len;
        return WriteFile(m_pipe_handle.Get(), buf, len, &write_len, NULL);
    }

private:
    UniqueHandle m_pipe_handle;
    size_t m_buf_size;
};

}


#endif // GEEK_COMM_PIPE_H_