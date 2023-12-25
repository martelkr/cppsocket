
#ifdef LINUX

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#else

#include <winsock2.h>
#include <ws2tcpip.h>

#include <BaseTsd.h>
using ssize_t = SSIZE_T;
using size_t = SIZE_T;

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cstdlib>
#include <string>
#include <cstring>
#include <stdexcept>
#include <mutex>
#include <functional>
#include <thread>
#include <array>

namespace com::github::socket
{
    class Socket
    {
    public:

        auto operator=(Socket&) -> Socket& = delete;
        auto operator=(Socket&&) -> Socket& = delete;
        Socket(Socket&) = delete;

        Socket() noexcept(false)
#ifdef LINUX
            : m_fd(-1)
#else
            : m_fd(INVALID_SOCKET)
#endif
        {
            init();
        }

#ifdef LINUX
        explicit Socket(const int filedescriptor) noexcept
#else
        explicit Socket(SOCKET filedescriptor) noexcept
#endif
            : m_fd(filedescriptor)
        {
        }

        Socket(const int domain, const int type, const int protocol) noexcept(false)
            : Socket()
        {
            initSocket(domain, type, protocol);
        }

        virtual ~Socket()
        {
#ifdef LINUX
            static_cast<void>(::shutdown(m_fd, SHUT_RDWR));
            static_cast<void>(::close(m_fd));
#else
            static_cast<void>(::shutdown(m_fd, SD_BOTH));
            static_cast<void>(::closesocket(m_fd));
#endif
        }

        void initSocket(const int domain, const int type, const int protocol) noexcept(false)
        {
            m_fd = ::socket(domain, type, protocol);
#ifdef LINUX
            if (m_fd < 0)
#else
            if (m_fd == INVALID_SOCKET)
#endif
            {
                throw std::runtime_error("Failed to create Socket");
            }
        }

#ifdef LINUX
        auto accept(sockaddr* address, socklen_t* addrlen) const noexcept -> int
#else
        auto accept(sockaddr* address, socklen_t* addrlen) const noexcept -> SOCKET
#endif
        {
            return ::accept(m_fd, address, addrlen);
        }

#ifdef LINUX
        [[nodiscard]] auto accept(std::string& ipAddr, uint16_t& port) const noexcept(false) -> int
#else
        [[nodiscard]] auto accept(std::string& ipAddr, uint16_t& port) const noexcept(false) -> SOCKET
#endif
        {
            sockaddr_in addr = {};
            socklen_t length = sizeof(addr);
            auto retval = accept(reinterpret_cast<sockaddr*>(&addr), &length);
#ifdef LINUX
            if (retval > 0)
#else
            if (retval != INVALID_SOCKET)
#endif
            {
                ipAddr = getIpAddress(addr.sin_addr);
                port = addr.sin_port;
            }

            return retval;
        }

        [[nodiscard]] auto bind(const sockaddr* address, int length) const noexcept -> ssize_t
        {
            return ::bind(m_fd, address, length);
        }

        [[nodiscard]] auto bind(const std::string& ipAddr, const uint16_t port) const noexcept(false) -> bool
        {
            sockaddr_in addr = {};
            initAddr(ipAddr, port, addr);
            socklen_t length = sizeof(addr);
            auto retval = true;
            if (bind(reinterpret_cast<sockaddr*>(&addr), length) < 0)
            {
                retval = false;
            }

            return retval;
        }

        [[nodiscard]] auto connect(const sockaddr* serveraddr, int addrlength) const noexcept -> ssize_t
        {
            return ::connect(m_fd, serveraddr, addrlength);
        }

        [[nodiscard]] virtual auto connect(const std::string& ipAddr, const uint16_t port) noexcept(false) -> bool
        {
            sockaddr_in addr = {};
            initAddr(ipAddr, port, addr);
            socklen_t length = sizeof(addr);
            auto retval = true;
            if (connect(reinterpret_cast<sockaddr*>(&addr), length) < 0)
            {
                retval = false;
            }
            return retval;
        }

        [[nodiscard]] auto listen(int backlog) const noexcept -> ssize_t
        {
            return ::listen(m_fd, backlog);
        }

        [[nodiscard]] auto read(void* buffer, size_t length) const noexcept -> ssize_t
        {
#ifdef LINUX
            return ::read(m_fd, buffer, length);
#else
            return ::recv(m_fd, reinterpret_cast<char*>(buffer), length, 0);
#endif
        }

        [[nodiscard]] auto readfrom(void* buffer, size_t length, sockaddr* from, socklen_t* fromlength) const noexcept -> ssize_t
        {
#ifdef LINUX
            return ::recvfrom(m_fd, buffer, length, 0, from, fromlength);
#else
            return ::recvfrom(m_fd, reinterpret_cast<char*>(buffer), length, 0, from, fromlength);
#endif
        }

        [[nodiscard]] auto readfrom(void* buffer, size_t length, std::string& ipAddr, uint16_t& port) const noexcept(false) -> ssize_t
        {
            sockaddr_in addr = {};
            socklen_t addrlength = sizeof(addr);
            auto retval = readfrom(buffer, length, reinterpret_cast<sockaddr*>(&addr), &addrlength);
            if (retval > 0)
            {
                ipAddr = getIpAddress(addr.sin_addr);
                port = addr.sin_port;
            }

            return retval;
        }

        auto send(const void* buffer, size_t length) const noexcept -> ssize_t
        {
#ifdef LINUX
            return ::send(m_fd, buffer, length, 0);
#else
            return ::send(m_fd, reinterpret_cast<const char*>(buffer), length, 0);
#endif
        }

        auto sendto(const void* buffer, size_t length, const sockaddr* toaddr, int tolength) const noexcept -> ssize_t
        {
#ifdef LINUX
            return ::sendto(m_fd, buffer, length, 0, toaddr, tolength);
#else
            return ::sendto(m_fd, reinterpret_cast<const char*>(buffer), length, 0, toaddr, tolength);
#endif
        }

        auto sendto(const void* buffer, size_t length, const std::string& ipAddr, const uint16_t port) const noexcept(false) -> ssize_t
        {
            sockaddr_in addr = {};
            initAddr(ipAddr, port, addr);
            return sendto(buffer, length, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        }

        [[nodiscard]] auto select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout) const noexcept -> ssize_t
        {
            return ::select(m_fd, readfds, writefds, exceptfds, timeout);
        }

        [[nodiscard]] auto select(fd_set& readfds, fd_set& writefds, fd_set& exceptfds, timeval& timeout) const noexcept -> ssize_t
        {
            return ::select(m_fd, &readfds, &writefds, &exceptfds, &timeout);
        }

        [[nodiscard]] auto select(fd_set& readfds, fd_set& writefds, fd_set& exceptfds, const int milliseconds) const noexcept -> ssize_t
        {
            ssize_t retval;
            if (milliseconds < 0)
            {
                retval = ::select(m_fd, &readfds, &writefds, &exceptfds, nullptr);
            }
            else
            {
                timeval timeout 
                {
                    .tv_sec = static_cast<time_t>(milliseconds * MILLISECONDS_PER_SECOND),
                    .tv_usec = static_cast<time_t>(milliseconds / MILLISECONDS_PER_SECOND)
                };

                retval = select(readfds, writefds, exceptfds, timeout);
            }

            return retval;
        }

        auto getsockopt(const int level, const int optname, void *optval, socklen_t* optlen) const noexcept -> ssize_t
        {
#ifdef LINUX
            return ::getsockopt(m_fd, level, optname, optval, optlen);
#else
            return ::getsockopt(m_fd, level, optname, reinterpret_cast<char*>(optval), optlen);
#endif
        }

        auto setsockopt(const int level, const int optname, const void *optval, const int optlen) const noexcept -> ssize_t
        {
#ifdef LINUX
            return ::setsockopt(m_fd, level, optname, optval, optlen);
#else
            return ::setsockopt(m_fd, level, optname, reinterpret_cast<const char*>(optval), optlen);
#endif
        }

    protected:

        [[nodiscard]] static auto getIpAddress(const in_addr inaddr) noexcept(false) -> std::string
        {
            char* receivedAddr = ::inet_ntoa(inaddr); // NOLINT
            if (receivedAddr == reinterpret_cast<char*>(INADDR_NONE)) // NOLINT
            {
                throw std::runtime_error("Invalid IP address received on readfrom.");
            }

            return {receivedAddr};
        }

        /**
         * @brief Initialize the Windows socket library one time
         * 
         */
        void init() noexcept(false)
        {
#ifdef WINDOWS
            std::call_once(m_onetime, [this]()
            {
                if (::WSAStartup(MAKEWORD(2, 2), &m_wsaData) != 0) 
                {
                    throw std::runtime_error("Could not start-up Windows sockets");
                }
            });
#endif
        }

        /**
         * @brief Initialize the sockaddr_in structure with the provided IP and port
         * 
         * @param ipAddr IP address 
         * @param port port value
         * @param addr Address structure to fill out
         */
        static void initAddr(const std::string& ipAddr, const int port, sockaddr_in& addr) noexcept(false)
        {
            addr.sin_family = AF_INET;
            if (ipAddr.empty() || ipAddr == "0.0.0.0")
            {
                addr.sin_addr.s_addr = INADDR_ANY;
            }
            else
            {
                if (::inet_pton(AF_INET, ipAddr.c_str(), &addr.sin_addr) <= 0)
                {
                    throw std::runtime_error("Failed to parse IP address");
                }
            }
            addr.sin_port = ::htons(port);
        }

        /**
         * @brief Generate a new cookie to use for the DTLS connection
         * 
         * @param ssl SSL context
         * @param cookie Buffer to create the cookie 
         * @param len Cookie buffer length
         * 
         * @return int 1 for success
         */
        // NOLINTNEXTLINE
        static auto genCookie(SSL *ssl, unsigned char* cookie, unsigned int* len) noexcept -> int
        {
            std::srand(std::time(nullptr)); // NOLINT

            for (unsigned int i = 0; i < COOKIE_LEN; ++i)
            {
                m_cookie[i] = static_cast<unsigned char>(::rand()); // NOLINT
            }

            const auto length = sizeof(in_addr) + sizeof(uint16_t);
            sockaddr_in addr;
            static_cast<void>(BIO_dgram_get_peer(SSL_get_rbio(ssl), &addr));
            std::array<unsigned char, length> buffer = {};

            ::memcpy(buffer.data(), &addr.sin_port, sizeof(uint16_t));
            ::memcpy(&buffer[sizeof(addr.sin_port)], &addr.sin_addr, sizeof(in_addr));

            std::array<unsigned char, EVP_MAX_MD_SIZE> result = {};
            unsigned int resLen = 0;
            HMAC(EVP_sha1(), m_cookie.data(), COOKIE_LEN, buffer.data(), length, result.data(), &resLen);
            ::memcpy(cookie, result.data(), resLen);
            *len = resLen;
            return 1;
        }

        /**
         * @brief Verify the cookie passed in is valid
         * 
         * @param ssl SSL context
         * @param cookie Cookie to verify
         * @param len Length of cookie
         * 
         * @return int 1 for valid cookie, 0 for invalid
         */
        // NOLINTNEXTLINE
        static auto verifyCookie(SSL* ssl, const unsigned char* cookie, unsigned int len) noexcept -> int
        {
            sockaddr_in addr;
            static_cast<void>(BIO_dgram_get_peer(SSL_get_rbio(ssl), &addr));

            const auto length = sizeof(in_addr) + sizeof(uint16_t);
            std::array<unsigned char, length> buffer = {};

            ::memcpy(buffer.data(), &addr.sin_port, sizeof(uint16_t));
            ::memcpy(&buffer[sizeof(addr.sin_port)], &addr.sin_addr, sizeof(in_addr));
            std::array<unsigned char, EVP_MAX_MD_SIZE> result = {};
            unsigned int resLen = 0;
            HMAC(EVP_sha1(), m_cookie.data(), COOKIE_LEN, buffer.data(), length, result.data(), &resLen);

            if ((len == resLen) && (::memcmp(result.data(), cookie, resLen) == 0))
            {
                return 1;
            }

            return 0;
        }

        /**
         * @brief Callback verification method
         * 
         * @return int 1 for good callback
         */
        // NOLINTNEXTLINE
        static auto verifyCallback (int val, X509_STORE_CTX *ctx) noexcept -> int
        {
            static_cast<void>(val);
            static_cast<void>(ctx);

            return 1;
        }

        constexpr static unsigned int MILLISECONDS_PER_SECOND = 1000; // NOLINT
        constexpr static unsigned int COOKIE_LEN = 16; // NOLINT
        constexpr static unsigned int ONE_HUNDRED_MILLISEC = 100; // NOLINT
        constexpr static unsigned int FIVE_SECONDS = 5; // NOLINT

        static std::array<unsigned char, COOKIE_LEN> m_cookie; // NOLINT
#ifdef LINUX
        int m_fd; // NOLINT
#else
        SOCKET m_fd; // NOLINT
        WSADATA m_wsaData; // NOLINT
        std::once_flag m_onetime; // NOLINT
#endif
    };

    std::array<unsigned char, Socket::COOKIE_LEN> Socket::m_cookie = {}; // NOLINT

    class TcpClient : public Socket
    {
    public:

        auto operator=(TcpClient&) -> TcpClient& = delete;
        auto operator=(TcpClient&&) -> TcpClient& = delete;
        TcpClient(TcpClient&) = delete;

        TcpClient() noexcept(false)
            : Socket(AF_INET, SOCK_STREAM, 0)
        {
            init();
        }

        explicit TcpClient(const int filedescriptor) noexcept(false)
            : Socket(filedescriptor)
        {
        }

        TcpClient(const std::string& ipAddr, const uint16_t port) noexcept(false)
            : TcpClient()
        {
            if (ipAddr.empty())
            {
                throw std::runtime_error("IP address is empty! Cannot connect to empty server!");
            }

            sockaddr_in addr = {};
            initAddr(ipAddr, port, addr);

            auto ret = ::connect(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#ifdef LINUX
            if (ret < 0)
#else
            if (ret == SOCKET_ERROR)
#endif
            {
                throw std::runtime_error("Failed to connect to server!");
            }
        }

    protected:

        void init() noexcept(false)
        {
            int flag = 1;
#ifdef LINUX
            if (setsockopt(IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) != 0)
#else
            if (setsockopt(IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag)) == SOCKET_ERROR)
#endif
            {
                throw std::runtime_error("Failed to setup socket!");
            }
        }
    };

    class TcpServer : public Socket
    {
    public:

        auto operator=(TcpServer&) -> TcpServer& = delete;
        auto operator=(TcpServer&&) -> TcpServer& = delete;
        TcpServer(TcpServer&) = delete;

        TcpServer() noexcept(false)
            : Socket(AF_INET, SOCK_STREAM, 0)
        {
            init();
        }

        explicit TcpServer(const uint16_t port, const std::string& ipAddr = "0.0.0.0") noexcept(false)
            : TcpServer()
        {
            if (!bind(ipAddr, port))
            {
                throw std::runtime_error("Failed to bind TCP server.");
            }
        }

        TcpServer(const std::string& ipAddr, const uint16_t port, const int backlog) noexcept(false)
            : TcpServer(port, ipAddr)
        {
            if (listen(backlog) < 0)
            {
                throw std::runtime_error("Failed to listen on TCP server.");
            }
        }

        /**
         * @brief Accept a new TCP connection either secure or unsecure
         * 
         * @return TcpClient Newly accepted TCP connection
         */
        [[nodiscard]] auto accept() noexcept(false) -> TcpClient
        {
            sockaddr_in client = {};
            socklen_t clientLen = sizeof(client);
            auto fileD = Socket::accept(reinterpret_cast<sockaddr*>(&client), &clientLen);
#ifdef LINUX
            if (fileD < 0)
#else
            if (fileD == INVALID_SOCKET)
#endif
            {
                throw std::runtime_error("Failed to accept client!");
            }

            return TcpClient(fileD);
        }

    protected:

        void init() noexcept(false)
        {
            int opt = 1;
#ifdef LINUX
            if (setsockopt(SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) != 0)
#else
            if (setsockopt(SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
#endif
            {
                throw std::runtime_error("Failed to setup socket!");
            }
        }
    };

    class UdpClient : public Socket
    {
    public:

        auto operator=(UdpClient&) -> UdpClient& = delete;
        auto operator=(UdpClient&&) -> UdpClient& = delete;
        UdpClient(UdpClient&) = delete;

        UdpClient() noexcept(false)
            : Socket(AF_INET, SOCK_DGRAM, 0)
        {
        }

        UdpClient(const std::string& ipAddr, const uint16_t port) noexcept(false)
            : UdpClient()
        {
            if (!connect(ipAddr, port))
            {
                throw std::runtime_error("Failed to connect to UDP server!");
            }
        }

        [[nodiscard]] auto connect(sockaddr* serveraddr, int addrlength) noexcept -> ssize_t
        {
            m_serverAddr = *(reinterpret_cast<sockaddr_in*>(serveraddr));
            return ::connect(m_fd, reinterpret_cast<sockaddr*>(&m_serverAddr), addrlength);
        }

        [[nodiscard]] auto connect(const std::string& ipAddr, const uint16_t port) noexcept(false) -> bool override
        {
            initAddr(ipAddr, port, m_serverAddr);
            socklen_t length = sizeof(m_serverAddr);
            return (::connect(m_fd, reinterpret_cast<sockaddr*>(&m_serverAddr), length) == 0);
        }

        [[nodiscard]] auto read(void* buffer, size_t length) noexcept -> ssize_t
        {
            socklen_t fromlength = sizeof(m_serverAddr);
#ifdef LINUX
            return ::recvfrom(m_fd, buffer, length, 0, reinterpret_cast<sockaddr*>(&m_serverAddr), &fromlength);
#else
            return ::recvfrom(m_fd, reinterpret_cast<char*>(buffer), length, 0, reinterpret_cast<sockaddr*>(&m_serverAddr), &fromlength);
#endif
        }

        auto send(const void* buffer, size_t length) noexcept -> ssize_t
        {
#ifdef LINUX
            return ::sendto(m_fd, buffer, length, 0, reinterpret_cast<sockaddr*>(&m_serverAddr), sizeof(m_serverAddr));
#else
            return ::sendto(m_fd, reinterpret_cast<const char*>(buffer), length, 0, reinterpret_cast<sockaddr*>(&m_serverAddr), sizeof(m_serverAddr));
#endif
        }

    private:

        sockaddr_in m_serverAddr;
    };

    class UdpServer : public Socket
    {
    public:

        auto operator=(UdpServer&) -> UdpServer& = delete;
        auto operator=(UdpServer&&) -> UdpServer& = delete;
        UdpServer(UdpServer&) = delete;

        UdpServer() noexcept(false)
            : Socket(AF_INET, SOCK_DGRAM, 0)
        {
            UdpServer::init();
        }

        explicit UdpServer(const uint16_t port, const std::string &ipAddr = "0.0.0.0") noexcept(false)
            : UdpServer()
        {
            if (!bind(ipAddr, port))
            {
                throw std::runtime_error("Failed to bind UDP server.");
            }
        }

        [[nodiscard]] auto read(void* buffer, size_t length) noexcept -> ssize_t
        {
            socklen_t fromlength = sizeof(m_clientAddr);
#ifdef LINUX
            return ::recvfrom(m_fd, buffer, length, 0, reinterpret_cast<sockaddr*>(&m_clientAddr), &fromlength);
#else
            return ::recvfrom(m_fd, reinterpret_cast<char*>(buffer), length, 0, reinterpret_cast<sockaddr*>(&m_clientAddr), &fromlength);
#endif
        }

        auto send(const void* buffer, size_t length) noexcept -> ssize_t
        {
#ifdef LINUX
            return ::sendto(m_fd, buffer, length, 0, reinterpret_cast<sockaddr*>(&m_clientAddr), sizeof(m_clientAddr));
#else
            return ::sendto(m_fd, reinterpret_cast<const char*>(buffer), length, 0, reinterpret_cast<sockaddr*>(&m_clientAddr), sizeof(m_clientAddr));
#endif
        }

    private:

        void init() noexcept(false)
        {
            int opt = 1;
#ifdef LINUX
            if (setsockopt(SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) != 0)
#else
            if (setsockopt(SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
#endif
            {
                throw std::runtime_error("Failed to setup socket!");
            }
        }

        sockaddr_in m_clientAddr;
    };

    class SecureTcpClient : public Socket
    {
    public:

        auto operator=(SecureTcpClient&) -> SecureTcpClient& = delete;
        auto operator=(SecureTcpClient&&) -> SecureTcpClient& = delete;
        SecureTcpClient(SecureTcpClient&) = delete;

#ifdef LINUX
        SecureTcpClient(const int filedescriptor, SSL_CTX* sslctx) noexcept(false)
#else
        SecureTcpClient(SOCKET filedescriptor, SSL_CTX *sslctx) noexcept(false)
#endif
            : Socket(filedescriptor)
            , m_cSSL(nullptr)
            , m_sslctx(nullptr)
        {
            initSsl(sslctx);

            if (SSL_accept(m_cSSL) <= 0)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Failed to SSL accept client");
            }
        }

        SecureTcpClient(const std::string& ipAddr, const uint16_t port) noexcept(false)
            : m_cSSL(nullptr)
            , m_sslctx(nullptr)
        {
            OpenSSL_add_ssl_algorithms();
            const auto* method = SSLv23_client_method();
            SSL_load_error_strings();
            m_sslctx = SSL_CTX_new(method);

            init();

            if (ipAddr.empty())
            {
                throw std::runtime_error("IP address is empty! Cannot connect to empty server!");
            }

            sockaddr_in addr = {};
            initAddr(ipAddr, port, addr);

            auto ret = connect(reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#ifdef LINUX
            if (ret < 0)
#else
            if (ret == SOCKET_ERROR)
#endif
            {
                throw std::runtime_error("Failed to connect to server!");
            }

            initSsl(m_sslctx);

            if (SSL_connect(m_cSSL) <= 0)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Failed to SSL connect to server");
            }
        }

        ~SecureTcpClient() override
        {
            if (m_cSSL != nullptr)
            {
                SSL_shutdown(m_cSSL);
                SSL_free(m_cSSL);
            }
            if (m_sslctx != nullptr)
            {
                SSL_CTX_free(m_sslctx);
            }
        }

        [[nodiscard]] auto read(void* buffer, size_t len) noexcept -> ssize_t
        {
            int length = static_cast<int>(len);
            return SSL_read(m_cSSL, buffer, length);
        }

        auto send(const void* buffer, size_t len) noexcept -> ssize_t
        {
            int length = static_cast<int>(len);
            return SSL_write(m_cSSL, buffer, length);
        }

    private:

        void init() noexcept(false)
        {
            m_fd = ::socket(AF_INET, SOCK_STREAM, 0);
#ifdef LINUX
            if (m_fd < 0)
#else
            if (m_fd == INVALID_SOCKET)
#endif
            {
                throw std::runtime_error("Failed to create Socket FD");
            }

            int flag = 1;
#ifdef LINUX
            if (setsockopt(IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) != 0)
#else
            if (setsockopt(IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag)) == SOCKET_ERROR)
#endif
            {
                throw std::runtime_error("Failed to setup socket!");
            }
        }

        void initSsl(SSL_CTX *sslctx) noexcept(false)
        {
            m_cSSL = SSL_new(sslctx);
            if (m_cSSL == nullptr)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Unable to create new SSL client");
            }
            SSL_set_fd(m_cSSL, m_fd);
        }

        /// @brief SSL/TLS instance
        SSL* m_cSSL;
        /// @brief SSL/TLS context
        SSL_CTX* m_sslctx;
    };

    class SecureTcpServer : public Socket
    {
    public:

        auto operator=(SecureTcpServer&) -> SecureTcpServer& = delete;
        auto operator=(SecureTcpServer&&) -> SecureTcpServer& = delete;
        SecureTcpServer(SecureTcpServer&) = delete;

        SecureTcpServer(const std::string& keyFile, const std::string& certFile) noexcept(false) // NOLINT
            : m_sslctx(nullptr)
            , m_keyFile(keyFile)
            , m_certFile(certFile)
        {
            if (m_certFile.empty() || m_keyFile.empty())
            {
                throw std::runtime_error("Invalid key file or cert file for TCP server.");
            }

            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            const auto* method = SSLv23_server_method();
            m_sslctx = SSL_CTX_new(method);
            if (m_sslctx == nullptr)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Failed to create server SSL context");
            }

            init();
        }

        SecureTcpServer(const std::string& keyFile, const std::string& certFile, const uint16_t port, const std::string& ipAddr = "0.0.0.0") noexcept(false)
            : SecureTcpServer(keyFile, certFile)
        {
            if (!bind(ipAddr, port))
            {
                throw std::runtime_error("Failed to bind Secure TCP server.");
            }
        }

        ~SecureTcpServer() override
        {
            if (m_sslctx != nullptr)
            {
                SSL_CTX_free(m_sslctx);
            }
        }

        /**
         * @brief Accept a new TCP connection either secure or unsecure
         * 
         * @param ipAddr Returned IP address of accepted client
         * @param port Returned port of accepted client
         * 
         * @return SecureTcpClient Newly accepted TCP connection
         */
        [[nodiscard]] auto accept(std::string& ipAddr, uint16_t& port) noexcept(false) -> SecureTcpClient
        {
            auto fileD = Socket::accept(ipAddr, port);
#ifdef LINUX
            if (fileD < 0)
#else
            if (fileD == INVALID_SOCKET)
#endif
            {
                throw std::runtime_error("Failed to accept client!");
            }

            initSecureFiles();

            return {fileD, m_sslctx};
        }

        /**
         * @brief Accept a new TCP connection either secure or unsecure
         * 
         * @return SecureTcpClient Newly accepted TCP connection
         */
        [[nodiscard]] auto accept() noexcept(false) -> SecureTcpClient
        {
            sockaddr_in client = {};
            socklen_t clientLen = sizeof(client);
            auto fileD = Socket::accept(reinterpret_cast<sockaddr*>(&client), &clientLen);
#ifdef LINUX
            if (fileD < 0)
#else
            if (fileD == INVALID_SOCKET)
#endif
            {
                throw std::runtime_error("Failed to accept client!");
            }

            initSecureFiles();

            return {fileD, m_sslctx};
        }

    private:

        void init() noexcept(false)
        {
            Socket::init();

            m_fd = ::socket(AF_INET, SOCK_STREAM, 0);
#ifdef LINUX
            if (m_fd < 0)
#else
            if (m_fd == INVALID_SOCKET)
#endif
            {
                throw std::runtime_error("Failed to create Socket FD");
            }
            
            int opt = 1;
#ifdef LINUX
            if (setsockopt(SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) != 0)
#else
            if (setsockopt(SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
#endif
            {
                throw std::runtime_error("Failed to setup socket!");
            }
        }
        
        void initSecureFiles() noexcept(false)
        {
            if (SSL_CTX_use_certificate_file(m_sslctx, m_certFile.c_str(), SSL_FILETYPE_PEM) != 1)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Failed to use pem certificate file");
            }
            if (SSL_CTX_use_PrivateKey_file(m_sslctx, m_keyFile.c_str(), SSL_FILETYPE_PEM) != 1)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Failed to use pem private key file");
            }
            if (SSL_CTX_check_private_key(m_sslctx) != 1)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Keys do not match!");
            }
        }

        /// @brief SSL/TLS context
        SSL_CTX* m_sslctx;
        /// @brief Key file to use for communication
        const std::string m_keyFile;
        /// @brief Certificate file for key file
        const std::string m_certFile;
    };

    class SecureUdpClient : public Socket
    {
    public:

        auto operator=(SecureUdpClient&) -> SecureUdpClient& = delete;
        auto operator=(SecureUdpClient&&) -> SecureUdpClient& = delete;
        SecureUdpClient(SecureUdpClient&) = delete;

        SecureUdpClient(const std::string& keyFile, const std::string& certFile)
            : m_cSSL(nullptr)
            , m_sslctx(nullptr)
            , m_bio(nullptr)
        {
            if (certFile.empty() || keyFile.empty())
            {
                throw std::runtime_error("Invalid key file or cert file for Secure UDP client.");
            }

            init(keyFile, certFile);
        }

        SecureUdpClient(const std::string& ipAddr, const uint16_t port, const std::string& keyFile, const std::string& certFile)
            : SecureUdpClient(keyFile, certFile)
        {
            if (!connect(ipAddr, port))
            {
                throw std::runtime_error("Failed to connect SSL");
            }
        }

        ~SecureUdpClient() override
        {
            if (m_cSSL != nullptr)
            {
                SSL_shutdown(m_cSSL);
                SSL_free(m_cSSL);
            }
            if (m_sslctx != nullptr)
            {
                SSL_CTX_free(m_sslctx);
            }
        }

        [[nodiscard]] auto connect(const std::string& ipAddr, const uint16_t port) noexcept -> bool override
        {
            if (!Socket::connect(ipAddr, port))
            {
                return false;
            }

            sockaddr_in addr = {};
            initAddr(ipAddr, port, addr);
            BIO_ctrl(m_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addr);
            SSL_set_bio(m_cSSL, m_bio, m_bio);

            if (SSL_connect(m_cSSL) <= 0)
            {
                ERR_print_errors_fp(stderr);
                return false;
            }

            return true;
        }

        [[nodiscard]] auto read(void* buffer, size_t len) noexcept -> ssize_t
        {
            int length = static_cast<int>(len);
            return SSL_read(m_cSSL, buffer, length);
        }

        auto send(const void* buffer, size_t len) noexcept -> ssize_t
        {
            int length = static_cast<int>(len);
            return SSL_write(m_cSSL, buffer, length);
        }

    private:

        void init(const std::string& keyFile, const std::string& certFile) noexcept(false)
        {
            m_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
#ifdef LINUX
            if (m_fd < 0)
#else
            if (m_fd == INVALID_SOCKET)
#endif
            {
                throw std::runtime_error("Failed to create Socket FD");
            }

            OpenSSL_add_ssl_algorithms();
            SSL_load_error_strings();
            m_sslctx = SSL_CTX_new(DTLS_client_method());
            if (SSL_CTX_use_certificate_file(m_sslctx, certFile.c_str(), SSL_FILETYPE_PEM) != 1)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Failed to use pem certificate file");
            }
            if (SSL_CTX_use_PrivateKey_file(m_sslctx, keyFile.c_str(), SSL_FILETYPE_PEM) != 1)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Failed to use pem private key file");
            }
            if (SSL_CTX_check_private_key(m_sslctx) != 1)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Keys do not match!");
            }

            SSL_CTX_set_verify_depth(m_sslctx, 2);
            SSL_CTX_set_read_ahead(m_sslctx, 1);

            m_cSSL = SSL_new(m_sslctx);

            m_bio = BIO_new_dgram(m_fd, BIO_CLOSE);
        }

        /// @brief SSL/TLS instance
        SSL* m_cSSL;
        /// @brief SSL/TLS context
        SSL_CTX* m_sslctx;
        /// @brief SSL BIO instance
        BIO* m_bio;
    };

    class SecureUdpServer : public Socket
    {
    public:

        auto operator=(SecureUdpServer&) -> SecureUdpServer& = delete;
        auto operator=(SecureUdpServer&&) -> SecureUdpServer& = delete;
        SecureUdpServer(SecureUdpServer&) = delete;

        SecureUdpServer(const std::string& keyFile, const std::string& certFile)
            : m_cSSL(nullptr)
            , m_sslctx(nullptr)
            , m_bio(nullptr)
        {
            init(keyFile, certFile);
        }

        SecureUdpServer(const std::string& keyFile, const std::string& certFile, const uint16_t port, const std::string& ipAddr = "0.0.0.0")
            : SecureUdpServer(keyFile, certFile)
        {
            if (!bind(ipAddr, port))
            {
                throw std::runtime_error("Failed to bind UDP server.");
            }

            initSsl();
        }

        ~SecureUdpServer() override
        {
            if (m_cSSL != nullptr)
            {
                SSL_shutdown(m_cSSL);
                SSL_free(m_cSSL);
            }
            if (m_sslctx != nullptr)
            {
                SSL_CTX_free(m_sslctx);
            }
        }

        [[nodiscard]] auto read(void* buffer, size_t len) noexcept -> ssize_t
        {
            int length = static_cast<int>(len);
            return SSL_read(m_cSSL, buffer, length);
        }

        auto send(const void* buffer, size_t len) noexcept -> ssize_t
        {
            int length = static_cast<int>(len);
            return SSL_write(m_cSSL, buffer, length);
        }

        void accept() noexcept
        {
            sockaddr_in addr;
            while (DTLSv1_listen(m_cSSL, reinterpret_cast<BIO_ADDR*>(&addr)) <= 0)
            {
                ERR_print_errors_fp(stderr);
                // wait a bit to allow other things to run
                std::this_thread::sleep_for(std::chrono::milliseconds(ONE_HUNDRED_MILLISEC));
            }

            SSL_accept(m_cSSL);
        }

        void initSsl() noexcept
        {
            m_bio = BIO_new_dgram(m_fd, BIO_NOCLOSE);
            timeval tval{.tv_sec = FIVE_SECONDS, .tv_usec = 0};
            BIO_ctrl(m_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tval);
            m_cSSL = SSL_new(m_sslctx);
            SSL_set_bio(m_cSSL, m_bio, m_bio);
            SSL_set_options(m_cSSL, SSL_OP_COOKIE_EXCHANGE);
        }

    private:

        void init(const std::string& keyFile, const std::string& certFile) noexcept(false)
        {
            OpenSSL_add_ssl_algorithms();
            SSL_load_error_strings();
            m_sslctx = SSL_CTX_new(DTLS_server_method());
            SSL_CTX_set_session_cache_mode(m_sslctx, SSL_SESS_CACHE_OFF);

            if (SSL_CTX_use_certificate_file(m_sslctx, certFile.c_str(), SSL_FILETYPE_PEM) != 1)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Failed to use pem certificate file");
            }
            if (SSL_CTX_use_PrivateKey_file(m_sslctx, keyFile.c_str(), SSL_FILETYPE_PEM) != 1)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Failed to use pem private key file");
            }
            if (SSL_CTX_check_private_key(m_sslctx) != 1)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("Keys do not match!");
            }

            SSL_CTX_set_verify(m_sslctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, Socket::verifyCallback);

            SSL_CTX_set_read_ahead(m_sslctx, 1);
            SSL_CTX_set_cookie_generate_cb(m_sslctx, Socket::genCookie);
            SSL_CTX_set_cookie_verify_cb(m_sslctx, &Socket::verifyCookie);

            m_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
#ifdef LINUX
            if (m_fd < 0)
#else
            if (m_fd == INVALID_SOCKET)
#endif
            {
                throw std::runtime_error("Failed to create Socket FD");
            }

            int opt = 1;
#ifdef LINUX
            if (setsockopt(SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) != 0)
#else
            if (setsockopt(SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
#endif
            {
                throw std::runtime_error("Failed to setup socket!");
            }
        }

        /// @brief SSL/TLS instance
        SSL* m_cSSL;
        /// @brief SSL/TLS context
        SSL_CTX* m_sslctx;
        /// @brief SSL BIO instance
        BIO* m_bio;
    };
}
