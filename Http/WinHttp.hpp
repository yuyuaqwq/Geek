#ifndef GEEK_HTTP_WIN_HTTP_H_
#define GEEK_HTTP_WIN_HTTP_H_

#include <vector>
#include <map>
#include <string>
#include <memory>
#include <algorithm>

#include <Windows.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")

#include <Geek/String/string.hpp>

namespace Geek {

namespace WinHttp {

class Headers {
public:
  void Parse(const std::wstring& headers) {
    m_Headers.clear();
    auto linearr = Geek::String::Split(headers, L"\r\n", false);

    for (auto& line : linearr) {
      size_t offset = line.find(L':');

      if (offset == -1) {
        continue;
      }

      std::wstring key, value;
      key = line.substr(0, offset);
      value = line.substr(offset + 1);
      value = Geek::String::DeleteHeadSpace(value);

      m_Headers[key].push_back(value);    // 可以直接push，map会自动构造不存在的key
    }
    return;
  }

  std::wstring Print() const {
    std::wstring headersStr;
    for (const auto& line : m_Headers) {
      for (const auto& value : line.second) {
        if (headersStr.empty()) {
          headersStr = line.first + L": " + value;
        }
        else {
          headersStr = headersStr + L"\r\n" + line.first + L": " + value;
        }
      }
    }
    headersStr += L"\r\n";
    return headersStr;
  }


  bool Hash(const std::wstring& name) const {
    return m_Headers.find(name) != m_Headers.end();
  }

  void Delete(const std::wstring& name) {
    m_Headers.erase(name);
  }

  bool Empty() {
    return m_Headers.empty();
  }

  void Clear() {
    m_Headers.clear();
  }


  vector<std::wstring>& operator[](const std::wstring& name) {
    return m_Headers[name];
  }

  const vector<std::wstring>& operator[](const std::wstring& name) const {
    return m_Headers.at(name);
  }

private:
  std::map<std::wstring, vector<std::wstring>> m_Headers;
};

class Cookies {
public:
  void ParseByResponseHeaders(const Headers& responseHeaders, bool reset) {
    if (reset) {
      m_Cookies.clear();
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
          m_Cookies[key] = value;
        }
        else {
          m_Cookies.erase(key);
        }
      }

    }

  }

  std::wstring Print() const {
    std::wstring cookiesStr;
    for (auto& it : m_Cookies) {
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
    return m_Cookies.find(name) != m_Cookies.end();
  }

  void Delete(const std::wstring& name) {
    m_Cookies.erase(name);
  }

  void Clear() {
    m_Cookies.clear();
  }

  bool Empty() {
    return m_Cookies.empty();
  }

  std::wstring& operator[](const std::wstring& name) {
    return m_Cookies[name];
  }

  const std::wstring& operator[](const std::wstring& name) const {
    return m_Cookies.at(name);
  }

private:
  std::map<std::wstring, std::wstring> m_Cookies;
};

class Connect {
public:
  enum class HttpStatusCode {
    Unknown = 0,

    Continue = 100,
    SwitchingProtocols = 101,

    OK = 200,
    Created = 201,
    Accepted = 202,
    Non_AuthoritativeInformation = 203,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,
    Multi_Status = 207,

    MultipleChoices = 300,
    MovedPermanently = 301,
    MoveTemporarily = 302,
    SeeOther = 303,
    NotModified = 304,
    UseProxy = 305,
    SwitchProxy = 306,
    TemporaryRedirect = 307,

    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PreconditionFailed = 412,
    RequestEntityTooLarge = 413,
    Request_URITooLong = 414,
    UnsupportedMediaType = 415,
    RequestedRangeNotSatisfiable = 416,
    ExpectationFailed = 417,
    Im_a_teapot = 418,
    MisdirectedRequest = 421,
    UnprocessableEntity = 422,
    Locked = 423,
    FailedDependency = 424,
    TooEarly = 425,
    UpgradeRequired = 426,
    RetryWith = 449,
    UnavailableForLegalReasons = 451,

    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    VersionNotSupported = 505,
    VariantAlsoNegotiates = 506,
    InsufficientStorage = 507,
    BandwidthLimitExceeded = 508,
    NotExtended = 510,

    UnparseableResponseHeaders = 600,
  };

public:
  Connect() {
    Clear();
  }

  ~Connect() {
    Reset();
  }

  void Clear() {
    m_hSession = NULL;

    m_hConnection = NULL;
    m_HostName = L"";
    m_Port = 0;

    m_hRequest = NULL;
    m_HTTPS = false;


    m_SetIgnoreError = false;


    m_SetProxyInfo = false;
    m_SetProxyUser = L"";
    m_SetProxyPass = L"";


    m_MarkSend = false;

    m_RequestHeaders.Clear();
    m_ResponseHeaders.Clear();
  }

  void SessionInit(const std::wstring& User_Agent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)") {
    if (m_hSession != NULL) {
      return;
    }

    // 新创建的Session需要设置下忽略证书错误
    m_SetIgnoreError = true;

    m_hSession = WinHttpOpen(User_Agent.c_str(), WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!m_hSession)
    {
      return;
    }

    // 新的Session 不需要设置代理信息了
    if (m_SetProxyInfo) {
      m_SetProxyUser = L"";
      m_SetProxyPass = L"";
    }

  }

  void InitOpen() {
    if (!m_AutoCookie) {
      m_Cookies.Clear();
    }
    else {
      if (m_MarkSend) {
        GetResponseCookies();    // Open前合并一下
      }
    }

    m_ResponseHeaders.Clear();

    m_RequestHeaders.Clear();

    if (m_hRequest) {
      WinHttpCloseHandle(m_hRequest);
      m_hRequest = NULL;
    }

    m_MarkSend = false;
  }

  void SendInit() {
    DWORD flags = 0;


    // 设置一次自动忽略错误/证书错误 设置一次就一直有效
    if (m_SetIgnoreError == true) {

      flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
      flags |= SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
      flags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
      flags |= SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;


      if (!WinHttpSetOption(m_hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags))) {
        return;
      }
      m_SetIgnoreError = false;
    }

    if (m_SetProxyInfo) {
      if (!m_SetProxyUser.empty()) {
        if (!WinHttpSetOption(m_hSession, WINHTTP_OPTION_PROXY_USERNAME, (LPVOID)m_SetProxyUser.c_str(), m_SetProxyUser.size())) {
          return;
        }
      }
      if (!m_SetProxyPass.empty()) {
        if (!WinHttpSetOption(m_hSession, WINHTTP_OPTION_PROXY_PASSWORD, (LPVOID)m_SetProxyPass.c_str(), m_SetProxyPass.size())) {
          return;
        }
      }
      m_SetProxyInfo = false;
    }


    // 禁止重定向
    flags = WINHTTP_DISABLE_REDIRECTS;
    if (!WinHttpSetOption(m_hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &flags, sizeof(flags))) {
      return;
    }


    // 设置禁止Winhttp内部自动处理Cookies
    flags = WINHTTP_DISABLE_COOKIES;
    if (!WinHttpSetOption(m_hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &flags, sizeof(flags))) {
      return;
    }

  }

  void LoadRequestHeaders() {
    if (m_AutoCookie && !m_Cookies.Empty()) {
      SetRequestHeader(L"Cookie", m_Cookies.Print());
    }

    if (m_AutoRequestHeader) {
      SetRequestHeaders(L"Accept:*/*\r\nReferer:" + m_Url, WINHTTP_ADDREQ_FLAG_ADD_IF_NEW);
    }


  }

  void LoadResponseHeaders() {
    if (m_MarkSend == false) {
      return;
    }
    if (!m_ResponseHeaders.Empty()) {
      return;
    }


    DWORD headersSize = 0;
    WinHttpQueryHeaders(m_hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, NULL, &headersSize, NULL);
    if (headersSize == 0) {
      return;
    }

    std::unique_ptr<wchar_t> buf((wchar_t*)new char[headersSize]);

    if (!WinHttpQueryHeaders(m_hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, buf.get(), &headersSize, NULL)) {
      return;
    }

    m_ResponseHeaders.Parse(buf.get());
  }


  void Reset() {
    if (m_hSession) {
      WinHttpCloseHandle(m_hSession);
    }
    if (m_hConnection) {
      WinHttpCloseHandle(m_hConnection);
    }
    if (m_hRequest) {
      WinHttpCloseHandle(m_hRequest);
    }

    Clear();
  }

  bool Open(const std::wstring& method, const std::wstring& url) {
    SessionInit();
    m_AutoCookie = true;
    m_AutoRequestHeader = true;
    InitOpen();

    URL_COMPONENTS urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = -1;
    urlComp.dwHostNameLength = -1;
    urlComp.dwUrlPathLength = -1;
    urlComp.dwExtraInfoLength = -1;
    // 拆解URL
    if (!WinHttpCrackUrl(url.c_str(), url.size(), NULL, &urlComp)) {
      return false;
    }

    std::wstring hostName = urlComp.lpszHostName;
    size_t offset = hostName.find('/');
    if (offset != -1) {
      hostName = hostName.substr(0, offset);
    }

    m_Url = url;
    // 还是上次的域名和端口，就不需要重新连接
    if (!m_hConnection || hostName != m_HostName || urlComp.nPort != m_Port) {
      if (m_hConnection) {
        WinHttpCloseHandle(m_hConnection);
        m_hConnection = NULL;
      }
      size_t offset = hostName.find(L':');
      if (offset != -1) {
        hostName = hostName.substr(0, offset);
      }
      // 建立连接
      m_hConnection = WinHttpConnect(m_hSession, hostName.c_str(), urlComp.nPort, 0);
      if (!m_hConnection)
      {
        return false;
      }
      m_HostName = hostName;
      m_Port = urlComp.nPort;
    }


    DWORD flags = 0;
    m_HTTPS = urlComp.nScheme == INTERNET_SCHEME_HTTPS;
    if (m_HTTPS) {
      flags |= WINHTTP_FLAG_SECURE;
    }


    m_hRequest = WinHttpOpenRequest(m_hConnection, method.c_str(), urlComp.lpszUrlPath, 0, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!m_hRequest)
    {
      return false;
    }
    return true;

  }

  void SetProxy(const std::wstring& proxy, const std::wstring& user, const std::wstring& pass) {
    SessionInit();
    if (proxy.empty()) {
      WINHTTP_PROXY_INFOW proxyInfo = { 0 };
      proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
      if (!WinHttpSetOption(m_hSession, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo))) {
        return;
      }
      return;
    }

    if (m_hRequest) {
      if (!WinHttpSetOption(m_hSession, WINHTTP_OPTION_PROXY_USERNAME, (LPVOID)user.c_str(), user.size())) {
        return;
      }
      if (!WinHttpSetOption(m_hSession, WINHTTP_OPTION_PROXY_PASSWORD, (LPVOID)pass.c_str(), pass.size())) {
        return;
      }
    }
    else {
      // 还没有Open，在Send时设置。
      m_SetProxyInfo = true;
      m_SetProxyUser = user;
      m_SetProxyPass = pass;
    }

    WINHTTP_PROXY_INFOW proxyInfo = { 0 };
    proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    proxyInfo.lpszProxy = (LPWSTR)proxy.c_str();
    if (!WinHttpSetOption(m_hSession, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo))) {
      return;
    }


  }

  void SetRequestHeader(const std::wstring& header, const std::wstring& value, DWORD flag = WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE /* WINHTTP_ADDREQ_FLAG_ */) {
    if (!m_hRequest)
    {
      return;
    }

    std::wstring headerLine = header + L":" + value;
    if (!WinHttpAddRequestHeaders(m_hRequest, headerLine.c_str(), headerLine.size(), flag)) {
      return;
    }
  }

  void SetRequestHeaders(const std::wstring& headers, DWORD flag = WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE /* WINHTTP_ADDREQ_FLAG_ */) {
    if (!m_hRequest)
    {
      return;
    }

    if (!WinHttpAddRequestHeaders(m_hRequest, headers.c_str(), headers.size(), flag)) {
      return;
    }
  }

  void SetRequestHeaders(const Headers& headers, DWORD flag = WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE /* WINHTTP_ADDREQ_FLAG_ */) {
    if (!m_hRequest)
    {
      return;
    }

    m_RequestHeaders = headers;

    const std::wstring& headersString = headers.Print();
    if (!WinHttpAddRequestHeaders(m_hRequest, headersString.c_str(), headersString.size(), flag)) {
      return;
    }

  }

  void DelRequestHeader(const std::wstring& header) {
    if (!m_hRequest)
    {
      return;
    }

    std::wstring headerLine = header + L":";
    if (!WinHttpAddRequestHeaders(m_hRequest, headerLine.c_str(), headerLine.size(), WINHTTP_ADDREQ_FLAG_REPLACE)) {
      return;
    }
  }


  bool Send() {
    if (!m_hRequest)
    {
      return false;
    }

    SendInit();


    LoadRequestHeaders();


    bool success = WinHttpSendRequest(m_hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!success) {
      return false;
    }

    success = WinHttpReceiveResponse(m_hRequest, NULL);
    if (!success)
    {
      return false;
    }
    m_MarkSend = true;

    return true;

  }

  HttpStatusCode GetStatusCode() {
    if (!m_hRequest) {
      return HttpStatusCode::Unknown;
    }
    if (!m_MarkSend) {
      return HttpStatusCode::Unknown;
    }

    DWORD size = 0;
    if (!WinHttpQueryHeaders(m_hRequest, WINHTTP_QUERY_STATUS_CODE, NULL, NULL, &size, NULL) || size == 0) {
      DWORD errorCode = GetLastError();
      if (errorCode != ERROR_INSUFFICIENT_BUFFER) {
        return HttpStatusCode::Unknown;
      }
    }

    std::vector<wchar_t> buf(size);

    if (!WinHttpQueryHeaders(m_hRequest, WINHTTP_QUERY_STATUS_CODE, NULL, buf.data(), &size, NULL) || size == 0) {
      return HttpStatusCode::Unknown;
    }

    auto statusCodeString = std::wstring(buf.data(), size);

    auto statusCode = (HttpStatusCode)stoi(statusCodeString);
    return statusCode;
  }

  const Cookies& GetResponseCookies() {
    if (!m_hRequest) {
      return Cookies();
    }
    LoadResponseHeaders();
    m_Cookies.ParseByResponseHeaders(m_ResponseHeaders, !m_AutoCookie);
    return m_Cookies;
  }

  Headers& GetResponseHeaders() {
    if (!m_hRequest) {
      return Headers();
    }
    LoadResponseHeaders();
    return m_ResponseHeaders;
  }

  std::string GetResponseContent() {
    if (!m_hRequest) {
      return "";
    }
    if (!m_MarkSend)
    {
      return "";
    }
    size_t buffSize = 0;
    size_t totalReadSize = 0;
    std::unique_ptr<char> buff(nullptr);
    do {
      DWORD availablelen = 0;
      if (!WinHttpQueryDataAvailable(m_hRequest, &availablelen) || availablelen == 0) {
        if (totalReadSize == 0) {
          return "";
        }
        break;
      }

      size_t oldBuffSize = buffSize;
      while (buffSize < totalReadSize + availablelen) {
        if (buffSize == 0) {
          buffSize = availablelen;
        }
        else {
          buffSize *= 2;
        }
      }

      if (oldBuffSize != buffSize) {
        std::unique_ptr<char> newBuff(new char[buffSize]);

        memcpy(newBuff.get(), buff.get(), totalReadSize);

        buff = std::move(newBuff);

      }

      DWORD readSize = 0;
      if (!WinHttpReadData(m_hRequest, buff.get() + totalReadSize, availablelen, &readSize)) {
        return "";
      }
      if (readSize == 0) {
        break;
      }
      totalReadSize += readSize;

    } while (false);


    if (totalReadSize) {
      return std::string(buff.get(), totalReadSize);
    }
    return "";

  }


      private:
        HINTERNET m_hSession;

        HINTERNET m_hConnection;

        std::wstring m_Url;
        std::wstring m_HostName;
        INTERNET_PORT m_Port;

        HINTERNET m_hRequest;
        bool m_HTTPS;


        bool m_SetIgnoreError;


        bool m_SetProxyInfo;
        std::wstring m_SetProxyUser;
        std::wstring m_SetProxyPass;


        bool m_AutoCookie;

        bool m_AutoRequestHeader;


        bool m_MarkSend;


        Cookies m_Cookies;

        Headers m_RequestHeaders;

        Headers m_ResponseHeaders;

    public:
      
};

} // namespace WinHttp 

} // namespace Geek

#endif // GEEK_HTTP_WIN_HTTP_H_