#ifndef GEEK_NETWORK_HTTP_HPP_
#define GEEK_NETWORK_HTTP_HPP_

#include <vector>
#include <map>
#include <string>
#include <memory>
#include <optional>
#include <stdexcept>
#include <functional>

#include <algorithm>

#include <Windows.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")

#include <geek/string/string.hpp>

namespace Geek {

namespace http {

enum class StatusCode {
    kContinue = 100,
    kSwitchingProtocols = 101,

    kOK = 200,
    kCreated = 201,
    kAccepted = 202,
    kNon_AuthoritativeInformation = 203,
    kNoContent = 204,
    kResetContent = 205,
    kPartialContent = 206,
    kMulti_Status = 207,

    kMultipleChoices = 300,
    kMovedPermanently = 301,
    kMoveTemporarily = 302,
    kSeeOther = 303,
    kNotModified = 304,
    kUseProxy = 305,
    kSwitchProxy = 306,
    kTemporaryRedirect = 307,

    kBadRequest = 400,
    kUnauthorized = 401,
    kPaymentRequired = 402,
    kForbidden = 403,
    kNotFound = 404,
    kMethodNotAllowed = 405,
    kNotAcceptable = 406,
    kProxyAuthenticationRequired = 407,
    kRequestTimeout = 408,
    kConflict = 409,
    kGone = 410,
    kLengthRequired = 411,
    kPreconditionFailed = 412,
    kRequestEntityTooLarge = 413,
    kRequest_URITooLong = 414,
    kUnsupportedMediaType = 415,
    kRequestedRangeNotSatisfiable = 416,
    kExpectationFailed = 417,
    kIm_a_teapot = 418,
    kMisdirectedRequest = 421,
    kUnprocessableEntity = 422,
    kLocked = 423,
    kFailedDependency = 424,
    kTooEarly = 425,
    kUpgradeRequired = 426,
    kRetryWith = 449,
    kUnavailableForLegalReasons = 451,

    kInternalServerError = 500,
    kNotImplemented = 501,
    kBadGateway = 502,
    kServiceUnavailable = 503,
    kGatewayTimeout = 504,
    kVersionNotSupported = 505,
    kVariantAlsoNegotiates = 506,
    kInsufficientStorage = 507,
    kBandwidthLimitExceeded = 508,
    kNotExtended = 510,

    kUnparseableResponseHeaders = 600,
};

enum class Method {
    kGet,
    kPost,
    kHead,
    kPut,
    kDelete,
    kConnect,
    kOptions,
    kTrace,
    kPatch,
};


class Headers {
public:
    Headers() = default;

    static Headers Parse(std::wstring_view headers_text) {
        Headers headers;
        headers.headers_.clear();
        headers.AddMultiLine(headers_text);
        return headers;
    }

    std::wstring Print() const {
        std::wstring headers_str;
        for (const auto& line : headers_) {
            for (const auto& value : line.second) {
                if (headers_str.empty()) {
                    headers_str = line.first + L": " + value;
                }
                else {
                    headers_str = headers_str + L"\r\n" + line.first + L": " + value;
                }
            }
        }
        headers_str += L"\r\n";
        return headers_str;
    }

    bool Hash(std::wstring_view name) const {
        return headers_.find(name.data()) != headers_.end();
    }

    void Delete(std::wstring_view name) {
        headers_.erase(name.data());
    }

    bool Empty() {
        return headers_.empty();
    }

    void Clear() {
        headers_.clear();
    }

    void AddMultiLine(std::wstring_view headers) {
        auto linearr = Geek::String::Split(std::wstring(headers), L"\r\n", false);
        for (auto& line : linearr) {
            AddLine(line);
        }
    }

    void AddLine(std::wstring_view line) {
        size_t offset = line.find(L':');

        if (offset == -1) {
            return;
        }

        std::wstring name, value;
        name = line.substr(0, offset);
        value = line.substr(offset + 1);
        if (value.front() == L'\r') {
            value.pop_back();
        }
        value = Geek::String::DeleteHeadSpace(value);

        AddPair(name, value);
    }

    void AddPair(std::wstring name, std::wstring value) {
        headers_[name].push_back(value);
    }

    std::optional<size_t> GetInt(std::wstring name) {
        if (!Hash(name)) {
            return {};
        }
        auto& vec = operator[](name);
        if (vec.size() != 1) {
            return {};
        }

        return std::stoll(vec[0]);
    }

    std::vector<std::wstring>& operator[](const std::wstring& name) {
        return headers_[name];
    }

    const std::vector<std::wstring>& operator[](const std::wstring& name) const {
        return headers_.at(name);
    }


private:
    std::map<std::wstring, std::vector<std::wstring>> headers_;
};

class Cookies {
public:
    void ParseByResponseHeaders(const Headers& responseHeaders, bool reset) {
        if (reset) {
            cookies_.clear();
        }

        if (!responseHeaders.Hash(L"Set-Cookie")) {
            return;
        }

        for (const auto& value : responseHeaders[L"Set-Cookie"]) {
            size_t offset = value.find(L';');
            std::wstring cookie;
            if (offset == -1) {
                cookie = value;
            }
            else {
                cookie = value.substr(0, offset);
                cookie = Geek::String::DeleteHeadSpace(cookie);
            }

            offset = cookie.find(L'=');
            if (offset != -1) {
                std::wstring key = cookie.substr(0, offset);
                std::wstring value = cookie.substr(offset + 1);
                std::wstring value_lw = value;
                transform(value_lw.begin(), value_lw.end(), value_lw.begin(), ::towupper);
                if (value_lw != L"delete") {
                    cookies_[key] = value;
                }
                else {
                    cookies_.erase(key);
                }
            }

        }

    }

    std::wstring Print() const {
        std::wstring cookiesStr;
        for (auto& it : cookies_) {
            if (cookiesStr.empty()) {
                cookiesStr = it.first + L'=' + it.second;
            }
            else {
                cookiesStr += L';' + it.first + L'=' + it.second;
            }
        }
        return cookiesStr;
    }

    bool Hash(const std::wstring& name) const {
        return cookies_.find(name) != cookies_.end();
    }

    void Delete(const std::wstring& name) {
        cookies_.erase(name);
    }

    void Clear() {
        cookies_.clear();
    }

    bool Empty() {
        return cookies_.empty();
    }

    std::wstring& operator[](const std::wstring& name) {
        return cookies_[name];
    }

    const std::wstring& operator[](const std::wstring& name) const {
        return cookies_.at(name);
    }

    std::vector<std::wstring> Merge() {
        std::vector<std::wstring> res;
        for (auto& it : cookies_) {
            res.push_back(it.first + L'=' + it.second);
        }
        return res;
    }

private:
    std::map<std::wstring, std::wstring> cookies_;
};



class Session {
public:
    Session(std::wstring_view user_agent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)") {
        // 新创建的Session需要设置下忽略证书错误
        session_handle_ = WinHttpOpen(user_agent.data(), WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session_handle_) {
            throw std::runtime_error("Session.WinHttpOpen");
        }
    }

    Session(Session&& other) noexcept {
        operator=(std::forward<Session>(other));
    }

    void operator=(Session&& other) noexcept {
        session_handle_ = other.session_handle_;
        other.session_handle_ = NULL;
    }

    Session(const Session&) = delete;
    void operator=(const Session&) = delete;

    ~Session() {
        if (session_handle_) {
            WinHttpCloseHandle(session_handle_);
            session_handle_ = NULL;
        }
    }

    HINTERNET Get() {
        return session_handle_;
    }

private:
    HINTERNET session_handle_;
};

class Connect {
private:
<<<<<<< HEAD
    Connect() = default;
=======
    Connect() {

    }
>>>>>>> a11b09f6090423b3f6dea351e68d02acbffe7aef

public:
    //Connect(const std::wstring& url, bool ignore_error = true) {
    //    auto connect_res = Create(url, ignore_error);
    //    if (!connect_res) throw std::runtime_error("Connect::Create");
    //    operator=(std::move(*connect_res));
    //}

    Connect(Connect&& other) noexcept {
        operator=(std::forward<Connect>(other));
    }
    void operator=(Connect&& other) noexcept {
        session_ = std::move(other.session_);

        auto_cookie_ = other.auto_cookie_;
        auto_request_header_ = other.auto_request_header_;
        https_ = other.https_;
        set_ignore_error_ = other.set_ignore_error_;
        
        set_proxy_info_ = other.set_proxy_info_;
        
        set_proxy_ = std::move(other.set_proxy_);
        set_proxy_pass_ = std::move(other.set_proxy_pass_);
        set_proxy_user_ = std::move(other.set_proxy_user_);


        connection_handle_ = other.connection_handle_;
        other.connection_handle_ = NULL;

        url_ = std::move(other.url_);
        host_name_ = std::move(other.host_name_);
        port_ = other.port_;
        path_ = other.path_;
        flags_ = other.flags_;

        request_handle_ = other.request_handle_;
        other.request_handle_ = NULL;

        mark_send_ = other.mark_send_;

        
        request_headers_ = std::move(other.request_headers_);
        response_headers_ = std::move(other.response_headers_);
        cookies_ = std::move(other.cookies_);

        other.Clear();
    }

    Connect(const Connect&) = delete;
    void operator=(const Connect& other) = delete;

    ~Connect() {
        if (connection_handle_) {
            WinHttpCloseHandle(connection_handle_);
        }
        if (request_handle_) {
            WinHttpCloseHandle(request_handle_);
        }
        Clear();
    }


    static std::optional<Connect> Create(const std::wstring& url, bool ignore_error = true) {
        Connect connect;

        // 拆解URL
        URL_COMPONENTS url_comp = { 0 };
        url_comp.dwStructSize = sizeof(url_comp);
        url_comp.dwSchemeLength = -1;
        url_comp.dwHostNameLength = -1;
        url_comp.dwUrlPathLength = -1;
        url_comp.dwExtraInfoLength = -1;
        if (!WinHttpCrackUrl(url.c_str(), url.size(), NULL, &url_comp)) {
            return {};
        }
        if (!url_comp.lpszHostName) {
            return {};
        }
        std::wstring host_name = url_comp.lpszHostName;
        size_t offset = host_name.find('/');
        if (offset != -1) {
            host_name = host_name.substr(0, offset);
        }

        connect.url_ = url;
        offset = host_name.find(L':');
        if (offset != -1) {
            host_name = host_name.substr(0, offset);
        }
        // 建立连接
        connect.connection_handle_ = WinHttpConnect(connect.session_.Get(), host_name.c_str(), url_comp.nPort, 0);
        if (!connect.connection_handle_) {
            return {};
        }
        connect.host_name_ = host_name;
        connect.port_ = url_comp.nPort;
<<<<<<< HEAD
        connect.path_ = std::wstring(url_comp.lpszUrlPath);
=======
        connect.path_ = url_comp.lpszUrlPath;
>>>>>>> a11b09f6090423b3f6dea351e68d02acbffe7aef


        connect.set_ignore_error_ = ignore_error;

        connect.flags_ = 0;
        connect.https_ = url_comp.nScheme == INTERNET_SCHEME_HTTPS;
        if (connect.https_) {
            connect.flags_ |= WINHTTP_FLAG_SECURE;
        }

        return connect;
    }


    bool Open(std::wstring_view path = L"", Method method = Method::kGet) {
        const wchar_t* method_str;
        switch (method) {
        case Method::kGet:
            method_str = L"GET";
            break;
        case Method::kPost:
            method_str = L"POST";
            break;
        case Method::kHead:
            method_str = L"HEAD";
            break;
        case Method::kPut:
            method_str = L"PUT";
            break;
        case Method::kDelete:
            method_str = L"DELETE";
            break;
        case Method::kConnect:
            method_str = L"CONNECT";
            break;
        case Method::kOptions:
            method_str = L"OPTIONS";
            break;
        case Method::kTrace:
            method_str = L"TRACE";
            break;
        case Method::kPatch:
            method_str = L"PATCH";
            break;
        default:
            return false;
        }

        if (!path_.empty() && path.empty()) {
<<<<<<< HEAD
            path = path_;
=======
            path = std::move(path_);
>>>>>>> a11b09f6090423b3f6dea351e68d02acbffe7aef
        }

        auto_cookie_ = true;
        auto_request_header_ = true;
        InitOpen();

        request_handle_ = WinHttpOpenRequest(connection_handle_, method_str, path.data(), 0, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags_);
        if (!request_handle_) {
            return false;
        }
        return true;
    }

    Headers& GetRequestHeaders() {
        return request_headers_;
    }

    void SetRequestHeaders(const Headers& headers) {
        request_headers_ = headers;
    }

    bool Send(bool redirects = false) {
        if (!request_handle_) {
            return false;
        }

        InitSend();

        LoadRequestHeaders();

        DWORD flags = 0;
        if (redirects == false) {
            // 禁止重定向
            DWORD flags = WINHTTP_DISABLE_REDIRECTS;
            if (!WinHttpSetOption(request_handle_, WINHTTP_OPTION_DISABLE_FEATURE, &flags, sizeof(flags))) {
                return false;
            }
        }

        bool success = WinHttpSendRequest(request_handle_, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (!success) {
            return false;
        }

        success = WinHttpReceiveResponse(request_handle_, NULL);
        if (!success) {
            return false;
        }
        mark_send_ = true;

        return true;

    }

    void SetProxy(std::wstring_view proxy = L"", std::wstring_view user = L"", std::wstring_view pass = L"") {
        set_proxy_info_ = true;
        set_proxy_ = proxy;
        set_proxy_user_ = user;
        set_proxy_pass_ = pass;
    }


    std::optional<StatusCode> GetStatusCode() {
        if (!request_handle_) {
            return {};
        }
        if (!mark_send_) {
            return {};
        }

        DWORD size = 0;
        if (!WinHttpQueryHeaders(request_handle_, WINHTTP_QUERY_STATUS_CODE, NULL, NULL, &size, NULL) || size == 0) {
            auto error_code = GetLastError();
            if (error_code != ERROR_INSUFFICIENT_BUFFER) {
                return {};
            }
        }

        std::vector<wchar_t> buf(size);

        if (!WinHttpQueryHeaders(request_handle_, WINHTTP_QUERY_STATUS_CODE, NULL, buf.data(), &size, NULL) || size == 0) {
            return {};
        }

        auto status_code_string = std::wstring(buf.data(), size);

        auto status_code = (StatusCode)std::stoi(status_code_string);
        return status_code;
    }

    std::optional<Cookies> GetResponseCookies() {
        if (!request_handle_) {
            return {};
        }
        LoadResponseHeaders();
        cookies_.ParseByResponseHeaders(response_headers_, !auto_cookie_);
        return cookies_;
    }

    std::optional<Headers*> GetResponseHeaders() {
        if (!request_handle_) {
            return {};
        }
        LoadResponseHeaders();
        return &response_headers_;
    }

    std::optional<size_t> GetResponseContentLength() {
        auto response_headers_res = GetResponseHeaders();
        if (!response_headers_res) return {};

        auto& response_headers = *response_headers_res;

        return response_headers->GetInt(L"Content-Length");
    }

    std::optional<std::vector<uint8_t>> GetResponseContent(std::function<bool(size_t total_read_size, size_t content_length)> read_callback = {}) {
        if (!request_handle_) {
            return {};
        }
        if (!mark_send_) {
            return {};
        }
        auto response_headers_res = GetResponseHeaders();
        if (!response_headers_res) return {};

        auto content_length_res = GetResponseContentLength();
        
        size_t buff_size, content_length = 0;
        if (content_length_res) {
            content_length = *content_length_res;
            buff_size = content_length;
            if (buff_size == 0) {
                buff_size = 1024;
            }
        }
        else {
            buff_size = 1024;
        }

       
        size_t total_read_size = 0;
        std::vector<uint8_t> buff(buff_size);
        do {
            DWORD availablelen = 0;
            if (!WinHttpQueryDataAvailable(request_handle_, &availablelen) || availablelen == 0) {
                if (total_read_size == 0) {
                    return {};
                }
                break;
            }

            size_t old_buff_size = buff_size;
            while (buff_size < total_read_size + availablelen) {
                if (buff_size == 0) {
                    buff_size = availablelen;
                }
                else {
                    buff_size *= 2;
                }
            }

            if (old_buff_size != buff_size) {
                buff.resize(buff_size);
            }

            DWORD read_size = 0;
            if (!WinHttpReadData(request_handle_, &buff[total_read_size], availablelen, &read_size)) {
                return {};
            }
            if (read_callback) {
                read_callback(total_read_size, content_length);
            }
            if (read_size == 0) {
                break;
            }
            total_read_size += read_size;

        } while (true);


        if (total_read_size) {
            buff.resize(total_read_size);
            return buff;
        }
        return {};

    }

private:
    void InitOpen() {
        if (!auto_cookie_) {
            cookies_.Clear();
        }
        else {
            if (mark_send_) {
                GetResponseCookies();        // Open前合并一下
            }
        }

        response_headers_.Clear();

        request_headers_.Clear();

        if (request_handle_) {
            WinHttpCloseHandle(request_handle_);
            request_handle_ = NULL;
        }

        mark_send_ = false;
    }

    void SetProxyInternal() {
        if (!set_proxy_info_) {
            return;
        }

        if (set_proxy_.empty()) {
            WINHTTP_PROXY_INFOW proxyInfo = { 0 };
            proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
            if (!WinHttpSetOption(session_.Get(), WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo))) {
                throw std::runtime_error("SetProxy.WinHttpSetOption");
            }
            return;
        }

        if (!WinHttpSetOption(session_.Get(), WINHTTP_OPTION_PROXY_USERNAME, (LPVOID)set_proxy_user_.data(), set_proxy_user_.size())) {
            throw std::runtime_error("SetProxy.WinHttpSetOption");
        }
        if (!WinHttpSetOption(session_.Get(), WINHTTP_OPTION_PROXY_PASSWORD, (LPVOID)set_proxy_pass_.data(), set_proxy_pass_.size())) {
            throw std::runtime_error("SetProxy.WinHttpSetOption");
        }

        WINHTTP_PROXY_INFOW proxyInfo = { 0 };
        proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        proxyInfo.lpszProxy = (LPWSTR)set_proxy_.data();
        if (!WinHttpSetOption(session_.Get(), WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo))) {
            throw std::runtime_error("SetProxy.WinHttpSetOption");
        }

        set_proxy_info_ = false;
        
    }

    void InitSend() {
        DWORD flags = 0;

        // 设置一次自动忽略错误/证书错误 设置一次就一直有效
        if (set_ignore_error_) {

            flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
            flags |= SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            flags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            flags |= SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;


            if (!WinHttpSetOption(request_handle_, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags))) {
                throw std::runtime_error("InitSend.WinHttpSetOption");
            }
            set_ignore_error_ = false;
        }

        SetProxyInternal();

        // 禁止Winhttp内部自动处理Cookies
        flags = WINHTTP_DISABLE_COOKIES;
        if (!WinHttpSetOption(request_handle_, WINHTTP_OPTION_DISABLE_FEATURE, &flags, sizeof(flags))) {
            return;
        }

    }

    void LoadRequestHeaders() {
        std::wstring headers_string = request_headers_.Print();

        if (!WinHttpAddRequestHeaders(request_handle_, headers_string.c_str(), headers_string.size(), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
            throw std::runtime_error("SetRequestHeaders.WinHttpAddRequestHeaders");
        }

        if (auto_cookie_ && !cookies_.Empty()) {
            request_headers_[L"Cookie"] = cookies_.Merge();
        }

        if (auto_request_header_) {
            if (!request_headers_.Hash(L"Accept")) {
                request_headers_.AddLine(L"Accept: */*");
            }
            if (!request_headers_.Hash(L"Referer")) {
                request_headers_.AddLine(L"Referer:" + url_);
            }
        }
    }

    void LoadResponseHeaders() {
        if (mark_send_ == false) {
            return;
        }
        if (!response_headers_.Empty()) {
            return;
        }


        DWORD headersSize = 0;
        WinHttpQueryHeaders(request_handle_, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, NULL, &headersSize, NULL);
        if (headersSize == 0) {
            return;
        }

        std::unique_ptr<wchar_t> buf((wchar_t*)new char[headersSize]);

        if (!WinHttpQueryHeaders(request_handle_, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, buf.get(), &headersSize, NULL)) {
            return;
        }

        response_headers_ = http::Headers::Parse(buf.get());
    }

    void Clear() {
        flags_ = 0;

        connection_handle_ = NULL;
        host_name_ = L"";
        port_ = 0;

        request_handle_ = NULL;
        https_ = false;

        mark_send_ = false;

        request_headers_.Clear();
        response_headers_.Clear();
    }


private:
    Session session_;

    bool auto_cookie_;               // 自动补全cookie
    bool auto_request_header_;       // 自动不全请求头
    bool https_;                     // 是https连接
    bool set_ignore_error_;          // 是否忽略证书错误

    bool set_proxy_info_;
    std::wstring set_proxy_;
    std::wstring set_proxy_user_;
    std::wstring set_proxy_pass_;


    HINTERNET connection_handle_;

    std::wstring url_;
    std::wstring host_name_;
    std::wstring path_;
    INTERNET_PORT port_;
    DWORD flags_;

    HINTERNET request_handle_;
    
    bool mark_send_;

    Cookies cookies_;
    Headers request_headers_;
    Headers response_headers_;
};


class Client {

};

} // namespace http 

} // namespace Geek

#endif // GEEK_NETWORK_HTTP_HPP_