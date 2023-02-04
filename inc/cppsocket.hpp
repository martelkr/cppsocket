
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cstdlib>
#include <string>
#include <cstring>
#include <stdexcept>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include <iostream>

namespace com
{
    namespace socket
    {
        class TCPClient
        {
        public:

            /**
             * @brief Construct a new TCPClient object for normal or SSL/TLS connections
             * 
             * @param fd Previously created socket file descriptor
             * @param sslctx Previously created SSL context or default null pointer for non secure connection
             */
            explicit TCPClient(const int fd, SSL_CTX* sslctx = nullptr)
                : m_clientFd(fd)
                , m_cSSL(nullptr)
                , m_sslctx(nullptr) // we don't need to save this on the server side client
            {
                if (sslctx != nullptr)
                {
                    m_cSSL = SSL_new(sslctx);
                    if (m_cSSL == nullptr)
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Unable to create new SSL client");
                    }

                    SSL_set_fd(m_cSSL, m_clientFd);

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
            TCPClient(const std::string& ip, const uint16_t port, const bool ssl = false)
                : m_clientFd(-1)
                , m_cSSL(nullptr)
                , m_sslctx(nullptr)
            {
                if (ip.empty())
                {
                    throw std::runtime_error("IP address is empty! Cannot connect to empty server!");
                }

                if (ssl)
                {
                    OpenSSL_add_ssl_algorithms();
                    auto* m = SSLv23_client_method();
                    SSL_load_error_strings();
                    m_sslctx = SSL_CTX_new(m);
                }

                m_clientFd = ::socket(AF_INET, SOCK_STREAM, 0);
                if (m_clientFd < 0)
                {
                    throw std::runtime_error("Failed to create Socket FD");
                }

                init();

                sockaddr_in addr;
                std::memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = ::htons(port);

                if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0)
                {
                    throw std::runtime_error("Failed to convert IP address!");
                }

                if (::connect(m_clientFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
                {
                    throw std::runtime_error("Failed to connect to server!");
                }

                if (ssl)
                {
                    m_cSSL = SSL_new(m_sslctx);
                    SSL_set_fd(m_cSSL, m_clientFd);
                    if (SSL_connect(m_cSSL) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Failed to SSL connect to server");
                    }
                }
            }

            /**
             * @brief Destroy the TCPClient object
             * 
             */
            ~TCPClient(void)
            {
                static_cast<void>(::shutdown(m_clientFd, SHUT_RDWR));
                static_cast<void>(::close(m_clientFd));

                if (m_cSSL)
                {
                    SSL_shutdown(m_cSSL);
                    SSL_free(m_cSSL);
                }
                if (m_sslctx)
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
            [[nodiscard]] ssize_t read(void* buffer, size_t len)
            {
                if (m_cSSL)
                {
                    int l = static_cast<int>(len);
                    return SSL_read(m_cSSL, buffer, l);
                }
                else
                {
                    return ::read(m_clientFd, buffer, len);
                }
            }

            /**
             * @brief Send buffer data on the socket
             * 
             * @param buffer Buffer of data to send
             * @param len Length of the data to send
             * @return ssize_t Length of data sent on the socket
             */
            [[nodiscard]] ssize_t send(const void* buffer, size_t len)
            {
                if (m_cSSL)
                {
                    int l = static_cast<int>(len);
                    return SSL_write(m_cSSL, buffer, l);
                }
                else
                {
                    return ::send(m_clientFd, buffer, len, 0);
                }
            }

        protected:

            /// @brief socket file descriptor
            int m_clientFd;
            /// @brief SSL/TLS instance
            SSL* m_cSSL;
            /// @brief SSL/TLS context
            SSL_CTX* m_sslctx;

            /**
             * @brief Initialize the TCP client to not use the Nagle algorithm
             * 
             */
            void init(void) const
            {
                int flag = 1;
                if (::setsockopt(m_clientFd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) != 0)
                {
                    throw std::runtime_error("Failed to setup socket!");
                }
            }
        };

        class TCPServer
        {
        public:

            /**
             * @brief Construct a new default TCPServer object without a bound port and not secure
             * 
             */
            TCPServer(void)
                : TCPServer(std::string(""), std::string(""))
            {
            }

            /**
             * @brief Construct a new secure SSL/TLS TCPServer object
             * 
             * @param keyFile Key file to use for communication
             * @param certFile Certifaction file for provided key
             */
            TCPServer(const std::string& keyFile, const std::string& certFile)
                : m_socketFd(-1)
                , m_serverAddr()
                , m_sslctx(nullptr)
                , m_keyFile(keyFile)
                , m_certFile(certFile)
            {
                std::memset(&m_serverAddr, 0, sizeof(m_serverAddr));

                if (m_keyFile.length() > 0 && m_certFile.length() > 0)
                {
                    SSL_load_error_strings();
                    OpenSSL_add_all_algorithms();
                    auto* m = SSLv23_server_method();
                    m_sslctx = SSL_CTX_new(m);
                    if (m_sslctx == nullptr)
                    {
                        ERR_print_errors_fp(stderr);
                        throw std::runtime_error("Failed to create server SSL context");
                    }
                }

                m_socketFd = ::socket(AF_INET, SOCK_STREAM, 0);
                if (m_socketFd < 0)
                {
                    throw std::runtime_error("Failed to create Socket FD");
                }

                init();
            }

            /**
             * @brief Construct a new unsecure TCPServer object
             * 
             * @param port Port on which to bind TCP server
             * @param ip IP address on which to bind TCP server
             * @param backlog Backlog for TCP accept calls
             */
            explicit TCPServer(const uint16_t port, const std::string& ip = "", const int backlog = 3)
                : TCPServer()
            {
                bindAndListen(port, ip, backlog);
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
            TCPServer(const uint16_t port, const std::string& ip, const std::string& keyFile, const std::string& certFile, const int backlog = 3)
                : TCPServer(keyFile, certFile)
            {
                bindAndListen(port, ip, backlog);
            }

            /**
             * @brief Destroy the TCPServer object
             * 
             */
            ~TCPServer(void)
            {
                static_cast<void>(::shutdown(m_socketFd, SHUT_RDWR));
                static_cast<void>(::close(m_socketFd));

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
            [[nodiscard]] TCPClient accept(void)
            {
                sockaddr_in client;
                socklen_t clientLen = sizeof(client);
                int fd = ::accept(m_socketFd, reinterpret_cast<sockaddr*>(&client), &clientLen);
                if (fd < 0)
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
            void bindAndListen(const uint16_t port, const std::string& ip = "", const int backlog = 3)
            {
                m_serverAddr.sin_family = AF_INET;
                if (ip.length() == 0)
                {
                    m_serverAddr.sin_addr.s_addr = INADDR_ANY;
                }
                else
                {
                    if (::inet_pton(AF_INET, ip.c_str(), &m_serverAddr.sin_addr) != 1)
                    {
                        throw std::runtime_error("Failed to convert IP address.");
                    }
                }
                m_serverAddr.sin_port = ::htons(port);

                if (::bind(m_socketFd, reinterpret_cast<sockaddr*>(&m_serverAddr), sizeof(m_serverAddr)) < 0)
                {
                    throw std::runtime_error("Failed to bind server!");
                }

                if (::listen(m_socketFd, backlog) != 0)
                {
                    throw std::runtime_error("Failed to listen on server socket.");
                }
            }

        protected:

            /// @brief TCP server socket file descriptor
            int m_socketFd;
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
            void init(void) const
            {
                int opt = 1;
                if (::setsockopt(m_socketFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) != 0)
                {
                    throw std::runtime_error("Failed to setup socket!");
                }
            }
        };
    }
}