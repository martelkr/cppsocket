
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

#include <iostream>

namespace
{
    constexpr unsigned int COOKIE_LEN = 16;
    std::array<unsigned char, COOKIE_LEN> gcookie = {};
    constexpr unsigned int ONE_HUNDRED_MILLISEC = 100;
    constexpr unsigned int FIVE_SECONDS = 5;

    /**
     * @brief Initialize a sockaddr_in structure
     * 
     * @param port Port value to use
     * @param ip IP address to use
     * @param addr sockaddr_in structure to populate
     */
    void initAddr(const int port, const std::string& ipAddr, sockaddr_in& addr) noexcept(false)
    {
        addr.sin_family = AF_INET;
        if (ipAddr.empty() || ipAddr.compare("0.0.0.0") == 0)
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
    auto genCookie(SSL *ssl, unsigned char* cookie, unsigned int* len) noexcept -> int
    {
        std::srand(std::time(nullptr));

        for (unsigned int i = 0; i < COOKIE_LEN; ++i)
        {
            gcookie[i] = static_cast<unsigned char>(::rand());
        }

        const auto length = sizeof(in_addr) + sizeof(uint16_t);
        sockaddr_in addr;
        static_cast<void>(BIO_dgram_get_peer(SSL_get_rbio(ssl), &addr));
        std::array<unsigned char, length> buffer = {};

        ::memcpy(buffer.data(), &addr.sin_port, sizeof(uint16_t));
        ::memcpy(&buffer[sizeof(addr.sin_port)], &addr.sin_addr, sizeof(in_addr));

        std::array<unsigned char, EVP_MAX_MD_SIZE> result = {};
        unsigned int resLen = 0;
        HMAC(EVP_sha1(), gcookie.data(), COOKIE_LEN, buffer.data(), length, result.data(), &resLen);
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
    auto verifyCookie(SSL* ssl, const unsigned char* cookie, unsigned int len) noexcept -> int
    {
        sockaddr_in addr;
        static_cast<void>(BIO_dgram_get_peer(SSL_get_rbio(ssl), &addr));

        const auto length = sizeof(in_addr) + sizeof(uint16_t);
        std::array<unsigned char, length> buffer = {};

        ::memcpy(buffer.data(), &addr.sin_port, sizeof(uint16_t));
        ::memcpy(&buffer[sizeof(addr.sin_port)], &addr.sin_addr, sizeof(in_addr));
        std::array<unsigned char, EVP_MAX_MD_SIZE> result = {};
        unsigned int resLen = 0;
        HMAC(EVP_sha1(), gcookie.data(), COOKIE_LEN, buffer.data(), length, result.data(), &resLen);

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
    auto verifyCallback (int val, X509_STORE_CTX *ctx) noexcept -> int
    {
        static_cast<void>(val);
        static_cast<void>(ctx);

        return 1;
    }
}

namespace com
{
    namespace socket
    {
#ifdef WINDOWS
        std::mutex gWsaMutex;

        /**
         * @brief Check if windows sockets are initialized
         * 
         * @return true Windows sockets are ready
         * @return false Windows sockets not ready yet
         */
        bool WinsockInitialized() noexcept
        {
            SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            if (s == INVALID_SOCKET) 
            {
                return false;
            }

            ::closesocket(s);
            return true;
        }
#endif

        class TCPClient
        {
        public:

            TCPClient& operator=(TCPClient&&) = default;
            TCPClient& operator=(TCPClient&) = delete;
            TCPClient(TCPClient&) = delete;

            /**
             * @brief Construct a new TCPClient object for normal or SSL/TLS connections
             * 
             * @param filedescriptor Previously created socket file descriptor
             * @param sslctx Previously created SSL context or default null pointer for non secure connection
             */
#ifdef LINUX
            explicit TCPClient(const int filedescriptor, SSL_CTX* sslctx = nullptr) noexcept(false)
#else
            explicit TCPClient(SOCKET filedescriptor, SSL_CTX *sslctx = nullptr) noexcept(false)
#endif
                : m_sockFd(filedescriptor)
#ifdef WINDOWS
                , m_wsaData()
#endif
                , m_cSSL(nullptr)
                , m_sslctx(nullptr)
            {
                if (sslctx != nullptr)
                {
                    m_cSSL = SSL_new(sslctx);
                    if (m_cSSL == nullptr)
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Unable to create new SSL client");
                    }

                    SSL_set_fd(m_cSSL, m_sockFd);

                    if (SSL_accept(m_cSSL) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Failed to SSL accept client");
                    }
                }
            }

            /**
             * @brief Construct a new TCPClient object for normal or SSL/TLS connections
             * 
             * @param ip IP address of the TCP server
             * @param port Port of the TCP server
             * @param ssl Flag to indicate if this TCP client is going to be used for SSL/TLS
             */
            TCPClient(const std::string &ipAddr, const uint16_t port, const bool ssl = false) noexcept(false)
                : m_sockFd(-1)
#ifdef WINDOWS
                , m_wsaData()
#endif
                , m_cSSL(nullptr)
                , m_sslctx(nullptr)
            {
#ifdef WINDOWS
                {
                    std::lock_guard<std::mutex> lock(gWsaMutex);
                    if (!WinsockInitialized()) 
                    {
                        if (::WSAStartup(MAKEWORD(2, 2), &m_wsaData) != 0) 
                        {
                            throw std::runtime_error("Could not start-up Windows sockets");
                        }
                    }
                }
#endif
                if (ipAddr.empty())
                {
                    throw std::runtime_error("IP address is empty! Cannot connect to empty server!");
                }

                if (ssl)
                {
                    OpenSSL_add_ssl_algorithms();
                    const auto* method = SSLv23_client_method();
                    SSL_load_error_strings();
                    m_sslctx = SSL_CTX_new(method);
                }

                m_sockFd = ::socket(AF_INET, SOCK_STREAM, 0);
#ifdef LINUX
                if (m_sockFd < 0)
#else
                if (m_sockFd == INVALID_SOCKET)
#endif
                {
                    throw std::runtime_error("Failed to create Socket FD");
                }

                init();

                sockaddr_in addr = {};
                initAddr(port, ipAddr, addr);

                auto ret = ::connect(m_sockFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#ifdef LINUX
                if (ret < 0)
#else
                if (ret == SOCKET_ERROR)
#endif
                {
                    throw std::runtime_error("Failed to connect to server!");
                }

                if (ssl)
                {
                    m_cSSL = SSL_new(m_sslctx);
                    SSL_set_fd(m_cSSL, m_sockFd);
                    if (SSL_connect(m_cSSL) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Failed to SSL connect to server");
                    }
                }
            }

            virtual ~TCPClient()
            {
#ifdef LINUX
                static_cast<void>(::shutdown(m_sockFd, SHUT_RDWR));
                static_cast<void>(::close(m_sockFd));
#else
                static_cast<void>(::shutdown(m_sockFd, SD_BOTH));
                static_cast<void>(::closesocket(m_sockFd));
#endif

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

            /**
             * @brief Perform a socket read
             * 
             * @param buffer Buffer to read the data into
             * @param len Length of the receive buffer
             * @return ssize_t The length of data received
             */
            [[nodiscard]] auto read(void* buffer, size_t len) noexcept -> ssize_t
            {
                auto retval = 0;
                if (m_cSSL != nullptr)
                {
                    int length = static_cast<int>(len);
                    retval = SSL_read(m_cSSL, buffer, length);
                }
                else
                {
#ifdef LINUX
                    retval = ::read(m_sockFd, buffer, len);
#else
                    retval ::recv(m_sockFd, reinterpret_cast<char*>(buffer), len, 0);
#endif
                }

                return retval;
            }

            /**
             * @brief Send buffer data on the socket
             * 
             * @param buffer Buffer of data to send
             * @param len Length of the data to send
             * @return ssize_t Length of data sent on the socket
             */
            [[nodiscard]] auto send(const void* buffer, size_t len) noexcept -> ssize_t
            {
                auto retval = 0;
                if (m_cSSL != nullptr)
                {
                    int length = static_cast<int>(len);
                    retval = SSL_write(m_cSSL, buffer, length);
                }
                else
                {
#ifdef LINUX
                    retval = ::send(m_sockFd, buffer, len, 0);
#else
                    retval = ::send(m_sockFd, reinterpret_cast<const char*>(buffer), len, 0);
#endif
                }

                return retval;
            }

        protected:

            /// @brief socket file descriptor
#ifdef LINUX
            int m_sockFd;
#else
            SOCKET m_sockFd;
            WSADATA m_wsaData;
#endif
            /// @brief SSL/TLS instance
            SSL* m_cSSL;
            /// @brief SSL/TLS context
            SSL_CTX* m_sslctx;
            
            /**
             * @brief Initialize the TCP client to not use the Nagle algorithm
             * 
             */
            void init() const noexcept(false)
            {
                int flag = 1;
#ifdef LINUX
                if (::setsockopt(m_sockFd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) != 0)
#else
                if (::setsockopt(m_sockFd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag)) == SOCKET_ERROR)
#endif
                {
                    throw std::runtime_error("Failed to setup socket!");
                }
            }
        };

        class TCPServer
        {
        public:

            TCPServer& operator=(TCPServer&) = delete;
            TCPServer& operator=(TCPServer&&) = delete;
            TCPServer(TCPServer&) = delete;

            /**
             * @brief Construct a new TCPServer object
             * 
             */
            TCPServer() noexcept(false)
                : TCPServer("", "")
            {
            }

            /**
             * @brief Construct a new secure SSL/TLS TCPServer object
             * 
             * @param keyFile Key file to use for communication
             * @param certFile Certifaction file for provided key
             */
            TCPServer(const std::string& keyFile, const std::string& certFile) noexcept(false)
#ifdef LINUX
                : m_sockFd(-1)
#else
                : m_sockFd(INVALID_SOCKET)
                , m_wsaData()
#endif
                , m_serverAddr()
                , m_sslctx(nullptr)
                , m_keyFile(keyFile)
                , m_certFile(certFile)
            {
#ifdef WINDOWS
                {
                    std::lock_guard<std::mutex> lock(gWsaMutex);
                    if (!WinsockInitialized()) 
                    {
                        if (::WSAStartup(MAKEWORD(2, 2), &m_wsaData) != 0) 
                        {
                            throw std::runtime_error("Could not start-up Windows sockets");
                        }
                    }
                }
#endif

                if (m_keyFile.length() > 0 && m_certFile.length() > 0)
                {
                    SSL_load_error_strings();
                    OpenSSL_add_all_algorithms();
                    const auto* method = SSLv23_server_method();
                    m_sslctx = SSL_CTX_new(method);
                    if (m_sslctx == nullptr)
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Failed to create server SSL context");
                    }
                }

                m_sockFd = ::socket(AF_INET, SOCK_STREAM, 0);
#ifdef LINUX
                if (m_sockFd < 0)
#else
                if (m_sockFd == INVALID_SOCKET)
#endif
                {
                    throw std::runtime_error("Failed to create Socket FD");
                }

                init();
            }

            /**
             * @brief Construct a new unsecure TCPServer object
             * 
             * @param port Port on which to bind TCP server
             * @param ipAddr IP address on which to bind TCP server
             * @param backlog Backlog for TCP accept calls
             */
            explicit TCPServer(const uint16_t port, const std::string& ipAddr = "0.0.0.0", const int backlog = 3) noexcept(false)
                : TCPServer()
            {
                bindAndListen(port, ipAddr, backlog);
            }

            /**
             * @brief Construct a new TCPServer object
             * 
             * @param port Port on which to bind TCP server
             * @param ip IP address on which to bind TCP server
             * @param keyFile Key file to use for communication
             * @param certFile Certifaction file for provided key
             * @param backlog Backlog for TCP accept calls
             */
            TCPServer(const uint16_t port, const std::string& ip, const std::string& keyFile, const std::string& certFile, const int backlog = 3) noexcept(false)
                : TCPServer(keyFile, certFile)
            {
                bindAndListen(port, ip, backlog);
            }

            virtual ~TCPServer()
            {
#ifdef LINUX
                static_cast<void>(::shutdown(m_sockFd, SHUT_RDWR));
                static_cast<void>(::close(m_sockFd));
#else
                static_cast<void>(::shutdown(m_sockFd, SD_BOTH));
                static_cast<void>(::closesocket(m_sockFd));
#endif

                if (m_sslctx)
                {
                    SSL_CTX_free(m_sslctx);
                }
            }

            /**
             * @brief Accept a new TCP connection either secure or unsecure
             * 
             * @return TCPClient Newly accepted TCP connection
             */
            [[nodiscard]] TCPClient accept() noexcept(false)
            {
                sockaddr_in client = {};
                socklen_t clientLen = sizeof(client);
                auto fd = ::accept(m_sockFd, reinterpret_cast<sockaddr*>(&client), &clientLen);
#ifdef LINUX
                if (fd < 0)
#else
                if (fd == INVALID_SOCKET)
#endif
                {
                    throw std::runtime_error("Failed to accept client!");
                }

                if (m_certFile.length() > 0 && m_keyFile.length() > 0)
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
                    if (!SSL_CTX_check_private_key(m_sslctx))
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Keys do not match!");
                    }
                }

                return TCPClient(fd, m_sslctx);
            }

            /**
             * @brief TCP server bind and listen
             * 
             * @param port Port on which to bind TCP server
             * @param ip IP address on which to bind TCP server
             * @param backlog Backlog for TCP accept calls
             */
            void bindAndListen(const uint16_t port, const std::string& ipAddr = "", const int backlog = 3) noexcept(false)
            {
                initAddr(port, ipAddr, m_serverAddr);

                auto ret = ::bind(m_sockFd, reinterpret_cast<sockaddr*>(&m_serverAddr), sizeof(m_serverAddr));
#ifdef LINUX
                if (ret < 0)
#else
                if (ret == SOCKET_ERROR)
#endif
                {
                    std::cout << errno << ":" << strerror(errno) << std::endl;
                    throw std::runtime_error("Failed to bind server!");
                }

                ret = ::listen(m_sockFd, backlog);
#ifdef LINUX
                if (ret != 0)
#else
                if (ret == SOCKET_ERROR)
#endif
                {
                    throw std::runtime_error("Failed to listen on server socket.");
                }
            }

        protected:

            /// @brief TCP server socket file descriptor
#ifdef LINUX
            int m_sockFd;
#else
            SOCKET m_sockFd;
            WSADATA m_wsaData;
#endif
            /// @brief TCP server address on which to bind
            sockaddr_in m_serverAddr;

            /// @brief SSL/TLS context
            SSL_CTX* m_sslctx;
            /// @brief Key file to use for communication
            const std::string m_keyFile;
            /// @brief Certificate file for key file
            const std::string m_certFile;

            /**
             * @brief Initialize the TCP server for IP and port reusability 
             * 
             */
            void init() const noexcept(false)
            {
                int opt = 1;
#ifdef LINUX
                if (::setsockopt(m_sockFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) != 0)
#else
                if (::setsockopt(m_sockFd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
#endif
                {
                    throw std::runtime_error("Failed to setup socket!");
                }
            }
        };

        class UDPClient
        {
        public:

            UDPClient& operator=(UDPClient&) = delete;
            UDPClient& operator=(UDPClient&&) = delete;
            UDPClient(UDPClient&) = delete;

            /**
             * @brief UDPClient default constructor
             * 
             */
            UDPClient() noexcept(false)
#ifdef LINUX
                : m_sockFd(-1)
#else
                : m_sockFd(INVALID_SOCKET)
                , m_wsaData()
#endif
                , m_cSSL(nullptr)
                , m_sslctx(nullptr)
                , m_serverAddr()
                , m_keyFile()
                , m_certFile()
            {
                init();
            }

            /**
             * @brief Construct a new UDPClient object for normal or SSL/TLS connections
             * 
             * @param ipAddr IP address of the UDP server
             * @param port Port of the UDP server
             */
            UDPClient(const std::string& ipAddr, const uint16_t port) noexcept(false)
                : UDPClient()
            {
                if (!connect(ipAddr, port))
                {
                    throw std::runtime_error("Failed to connect to server!");
                }
            }

            /**
             * @brief Construct a DTLS UDPClient object
             * 
             * @param keyFile SSL key file to use
             * @param certFile SSL certificate file to use
             */
            UDPClient(const std::string& keyFile, const std::string& certFile) noexcept(false)
#ifdef LINUX
                : m_sockFd(-1)
#else
                : m_sockFd(INVALID_SOCKET)
                , m_wsaData()
#endif
                , m_cSSL(nullptr)
                , m_sslctx(nullptr)
                , m_serverAddr()
                , m_keyFile(keyFile)
                , m_certFile(certFile)
            {
                init();
            }

            /**
             * @brief Construct a DTLS UDPClient object
             * 
             * @param ipAddr IP address of the UDP server
             * @param port Port of the UDP server
             * @param keyFile SSL key file to use
             * @param certFile SSL certificate file to use
             */
            UDPClient(const std::string& ipAddr, const uint16_t port, const std::string& keyFile, const std::string& certFile) noexcept(false)
#ifdef LINUX
                : m_sockFd(-1)
#else
                : m_sockFd(INVALID_SOCKET)
                , m_wsaData()
#endif
                , m_cSSL(nullptr)
                , m_sslctx(nullptr)
                , m_serverAddr()
                , m_keyFile(keyFile)
                , m_certFile(certFile)
            {
                init();
                if (!connect(ipAddr, port))
                {
                    throw std::runtime_error("Failed to connect SSL");
                }
            }

            virtual ~UDPClient()
            {
#ifdef LINUX
                static_cast<void>(::shutdown(m_sockFd, SHUT_RDWR));
                static_cast<void>(::close(m_sockFd));
#else
                static_cast<void>(::shutdown(m_sockFd, SD_BOTH));
                static_cast<void>(::closesocket(m_sockFd));
#endif

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

            /**
             * @brief Connect to the given IP and port UDP server
             * 
             * @param ip IP of UDP server
             * @param port Port of UDP server
             * 
             * @return true UDP connection successful
             * @return false UDP connection unsuccessful
             */
            [[nodiscard]] auto connect(const std::string& ip, const int port) noexcept(false) -> bool
            {
                initAddr(port, ip, m_serverAddr);

                return connect();
            }

            /**
             * @brief Connect to the previously provided UDP server
             * 
             * @return true UDP connection successful
             * @return false UDP connection unsuccessful
             */
            [[nodiscard]] bool connect() noexcept
            {
                auto ret = ::connect(m_sockFd, reinterpret_cast<sockaddr*>(&m_serverAddr), sizeof(m_serverAddr));

                if (!m_keyFile.empty() && !m_certFile.empty())
                {
                    BIO_ctrl(m_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &m_serverAddr);
                    SSL_set_bio(m_cSSL, m_bio, m_bio);

                    if (SSL_connect(m_cSSL) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        return false;
                    }

                    return true;
                }
                else
                {
#ifdef LINUX
                    return (ret == 0);
#else
                    return (ret != SOCKET_ERROR);
#endif
                }
            }

             /**
             * @brief Perform a socket read
             * 
             * @param buffer Buffer to read the data into
             * @param len Length of the receive buffer
             * @return ssize_t The length of data received
             */
            [[nodiscard]] ssize_t read(void* buffer, size_t len) noexcept
            {
                auto retval = 0;
                if (m_cSSL != nullptr)
                {
                    int length = static_cast<int>(len);
                    retval = SSL_read(m_cSSL, buffer, length);
                }
                else
                {
                    socklen_t socklen = sizeof(m_clientAddr);
#ifdef LINUX
                    retval = ::recvfrom(m_sockFd, buffer, len, 0, reinterpret_cast<sockaddr*>(&m_clientAddr), &socklen);
#else
                    retval = ::recvfrom(m_sockFd, reinterpret_cast<char *>(buffer), len, 0, reinterpret_cast<sockaddr *>(&m_clientAddr), &socklen);
#endif
                }

                return retval;
            }

            /**
             * @brief Send buffer data on the socket
             * 
             * @param buffer Buffer of data to send
             * @param len Length of the data to send
             * @return ssize_t Length of data sent on the socket
             */
            [[nodiscard]] ssize_t send(const void* buffer, size_t len) noexcept
            {
                auto retval = 0;
                if (m_cSSL != nullptr)
                {
                    int length = static_cast<int>(len);
                    retval = SSL_write(m_cSSL, buffer, length);
                }
                else
                {
#ifdef LINUX
                    retval = ::sendto(m_sockFd, buffer, len, 0, reinterpret_cast<sockaddr *>(&m_serverAddr), sizeof(m_serverAddr));
#else
                    retval = ::sendto(m_sockFd, reinterpret_cast<const char*>(buffer), len, 0, reinterpret_cast<sockaddr*>(&m_serverAddr), sizeof(m_serverAddr));
#endif
                }

                return retval;
            }

        protected:
 
            /// @brief socket file descriptor
#ifdef LINUX
            int m_sockFd;
#else
            SOCKET m_sockFd;
            WSADATA m_wsaData;
#endif
            /// @brief SSL/TLS instance
            SSL* m_cSSL;
            /// @brief SSL/TLS context
            SSL_CTX* m_sslctx;
            /// @brief SSL BIO instance
            BIO* m_bio;
             /// @brief UDP server address on which to bind
            sockaddr_in m_serverAddr;
            /// @brief client address last received data from
            sockaddr_in m_clientAddr;
            /// @brief Key file to use for communication
            const std::string m_keyFile;
            /// @brief Certificate file for key file
            const std::string m_certFile;

            /**
             * @brief Initialize the UDP client
             * 
             */
            void init() noexcept(false)
            {
#ifdef WINDOWS
                {
                    std::lock_guard<std::mutex> lock(gWsaMutex);
                    if (!WinsockInitialized()) 
                    {
                        if (::WSAStartup(MAKEWORD(2, 2), &m_wsaData) != 0) 
                        {
                            throw std::runtime_error("Could not start-up Windows sockets");
                        }
                    }
                }
#endif

                m_sockFd = ::socket(AF_INET, SOCK_DGRAM, 0);
#ifdef LINUX
                if (m_sockFd < 0)
#else
                if (m_sockFd == INVALID_SOCKET)
#endif
                {
                    throw std::runtime_error("Failed to create socket!");
                }

                if (!m_keyFile.empty() && !m_certFile.empty())
                {
                    OpenSSL_add_ssl_algorithms();
                    SSL_load_error_strings();
                    m_sslctx = SSL_CTX_new(DTLS_client_method());
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
                    if (!SSL_CTX_check_private_key(m_sslctx))
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Keys do not match!");
                    }

                    SSL_CTX_set_verify_depth(m_sslctx, 2);
                    SSL_CTX_set_read_ahead(m_sslctx, 1);

                    m_cSSL = SSL_new(m_sslctx);

                    m_bio = BIO_new_dgram(m_sockFd, BIO_CLOSE);
                }
            }
       };

        class UDPServer
        {
        public:

            UDPServer& operator=(UDPServer&) = delete;
            UDPServer& operator=(UDPServer&&) = delete;
            UDPServer(UDPServer&) = delete;

             /**
             * @brief Construct a new secure SSL/DLS UDPServer object
             * 
             * @param keyFile Key file to use for communication
             * @param certFile Certifaction file for provided key
             */
            UDPServer(const std::string& keyFile, const std::string& certFile) noexcept(false)
#ifdef LINUX
                : m_sockFd(-1)
#else
                : m_sockFd(INVALID_SOCKET)
                , m_wsaData()
#endif
                , m_cSSL(nullptr)
                , m_sslctx(nullptr)
                , m_bio(nullptr)
                , m_serverAddr()
                , m_clientAddr()
                , m_keyFile(keyFile)
                , m_certFile(certFile)
            {
#ifdef WINDOWS
                {
                    std::lock_guard<std::mutex> lock(gWsaMutex);
                    if (!WinsockInitialized()) 
                    {
                        if (::WSAStartup(MAKEWORD(2, 2), &m_wsaData) != 0) 
                        {
                            throw std::runtime_error("Could not start-up Windows sockets");
                        }
                    }
                }
#endif

                if (!m_keyFile.empty() && !m_certFile.empty())
                {
                    OpenSSL_add_ssl_algorithms();
                    SSL_load_error_strings();
                    m_sslctx = SSL_CTX_new(DTLS_server_method());
                    SSL_CTX_set_session_cache_mode(m_sslctx, SSL_SESS_CACHE_OFF);

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
                    if (!SSL_CTX_check_private_key(m_sslctx))
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Keys do not match!");
                    }

                    SSL_CTX_set_verify(m_sslctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verifyCallback);

                    SSL_CTX_set_read_ahead(m_sslctx, 1);
                    SSL_CTX_set_cookie_generate_cb(m_sslctx, genCookie);
                    SSL_CTX_set_cookie_verify_cb(m_sslctx, &verifyCookie);
                }

                m_sockFd = ::socket(AF_INET, SOCK_DGRAM, 0);
#ifdef LINUX
                if (m_sockFd < 0)
#else
                if (m_sockFd == INVALID_SOCKET)
#endif
                {
                    throw std::runtime_error("Failed to create socket!");
                }

                int opt = 1;
#ifdef LINUX
                if (::setsockopt(m_sockFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) != 0)
#else
                if (::setsockopt(m_sockFd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) == SOCKET_ERROR)
#endif
                {
                    throw std::runtime_error("Failed to setup socket!");
                }
            }

            /**
             * @brief Construct a new unsecure UDPServer object
             * 
             * @param port Port on which to bind TCP server
             * @param ipAddr IP address on which to bind TCP server
             */
            explicit UDPServer(const uint16_t port, const std::string& ipAddr = "0.0.0.0") noexcept(false)
                : UDPServer("", "")
            {
                bind(port, ipAddr);
            }

            /**
             * @brief Construct a new UDPServer object
             * 
             * @param port Port on which to bind UDP server
             * @param ipAddr IP address on which to bind UDP server
             * @param keyFile Key file to use for communication
             * @param certFile Certifaction file for provided key
             */
            UDPServer(const uint16_t port, const std::string& ipAddr, const std::string& keyFile, const std::string& certFile) noexcept(false)
                : UDPServer(keyFile, certFile)
            {
                bind(port, ipAddr);

                if (!m_keyFile.empty() && !m_certFile.empty())
                {
                    m_bio = BIO_new_dgram(m_sockFd, BIO_NOCLOSE);
                    timeval tval{.tv_sec = FIVE_SECONDS, .tv_usec = 0};
                    BIO_ctrl(m_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tval);
                    m_cSSL = SSL_new(m_sslctx);
                    SSL_set_bio(m_cSSL, m_bio, m_bio);
                    SSL_set_options(m_cSSL, SSL_OP_COOKIE_EXCHANGE);
                }
            }

            virtual ~UDPServer()
            {
#ifdef LINUX
                static_cast<void>(::shutdown(m_sockFd, SHUT_RDWR));
                static_cast<void>(::close(m_sockFd));
#else
                static_cast<void>(::shutdown(m_sockFd, SD_BOTH));
                static_cast<void>(::closesocket(m_sockFd));
#endif

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

            /**
             * @brief Accept a UDP connection either secure or unsecure. 
             * 
             * NOTE: Unsecure does nothing and this call is not needed
             * 
             */
            void accept() noexcept
            {
                if (m_certFile.length() > 0 && m_keyFile.length() > 0)
                {
                    std::cout << "listening" << std::endl;
                    while (DTLSv1_listen(m_cSSL, reinterpret_cast<BIO_ADDR*>(&m_clientAddr)) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        // wait a bit to allow other things to run
                        std::this_thread::sleep_for(std::chrono::milliseconds(ONE_HUNDRED_MILLISEC));
                    }

                    SSL_accept(m_cSSL);
                }
            }

             /**
             * @brief Perform a socket read
             * 
             * @param buffer Buffer to read the data into
             * @param len Length of the receive buffer
             * 
             * @return ssize_t The length of data received
             */
            [[nodiscard]] auto read(void* buffer, size_t len) noexcept -> ssize_t
            {
                auto retval = 0;
                if (m_cSSL != nullptr)
                {
                    int length = static_cast<int>(len);
                    retval =  SSL_read(m_cSSL, buffer, length);
                }
                else
                {
                    socklen_t socklen = sizeof(m_clientAddr);
#ifdef LINUX
                    retval =  ::recvfrom(m_sockFd, buffer, len, 0, reinterpret_cast<sockaddr*>(&m_clientAddr), &socklen);
#else
                    retval =  ::recvfrom(m_sockFd, reinterpret_cast<char*>(buffer), len, 0, reinterpret_cast<sockaddr*>(&m_clientAddr), &socklen);
#endif
                }

                return retval;
            }

            /**
             * @brief Send buffer data on the socket
             * 
             * @param buffer Buffer of data to send
             * @param len Length of the data to send
             * 
             * @return ssize_t Length of data sent on the socket
             */
            [[nodiscard]] auto send(const void* buffer, size_t len) noexcept -> ssize_t
            {
                auto retval = 0;
                if (m_cSSL != nullptr)
                {
                    int length = static_cast<int>(len);
                    retval = SSL_write(m_cSSL, buffer, length);
                }
                else
                {
#ifdef LINUX
                    retval =  ::sendto(m_sockFd, buffer, len, 0, reinterpret_cast<sockaddr *>(&m_clientAddr), sizeof(m_clientAddr));
#else
                    retval =  ::sendto(m_sockFd, reinterpret_cast<const char *>(buffer), len, 0, reinterpret_cast<sockaddr *>(&m_clientAddr), sizeof(m_clientAddr));
#endif
                }

                return retval;
            }

            /**
             * @brief Bind on the port and IP interface
             * 
             * @param port Port on which to bind
             * @param ipAddr IP interface to use
             */
            void bind(const int port, const std::string& ipAddr = "0.0.0.0") noexcept(false)
            {
                initAddr(port, ipAddr, m_serverAddr);

                auto ret = ::bind(m_sockFd, reinterpret_cast<sockaddr*>(&m_serverAddr), sizeof(m_serverAddr));
#ifdef LINUX
                if (ret < 0)
#else
                if (ret == SOCKET_ERROR)
#endif
                {
                    throw std::runtime_error("Failed to bind server!");
                }
            }

        protected:
 
             /// @brief UDP server socket file descriptor
#ifdef LINUX
            int m_sockFd;
#else
            SOCKET m_sockFd;
            WSADATA m_wsaData;
#endif
            /// @brief SSL/TLS instance
            SSL* m_cSSL;
            /// @brief SSL/TLS context
            SSL_CTX* m_sslctx;
            /// @brief SSL BIO instance
            BIO* m_bio;
            /// @brief UDP server address on which to bind
            sockaddr_in m_serverAddr;
            /// @brief UDP client address to send data
            sockaddr_in m_clientAddr;
            /// @brief Key file to use for communication
            const std::string m_keyFile;
            /// @brief Certificate file for key file
            const std::string m_certFile;
       };
    }
}
