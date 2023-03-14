
#include "cppsocket.hpp"

#include <thread>
#include <iostream>
#include <assert.h>
#include <sys/types.h>

#ifdef LINUX
#include <unistd.h>
#include <sys/wait.h>

// @TODO: replace with your test key and certificate file
static const std::string KEY_FILE("/usr/share/ca-certificates/extra/key.pem");
static const std::string CERT_FILE("/usr/share/ca-certificates/extra/scert.crt");
#else
#include <tchar.h>
#include <locale>

#include <openssl/applink.c>

// @TODO: replace with your test key and certificate file
static const std::string KEY_FILE("C:\\Users\\marte\\privatekey.key");
static const std::string CERT_FILE("C:\\Users\\marte\\certificate.crt");
#endif

using com::socket::TCPServer;
using com::socket::TCPClient;
using com::socket::UDPServer;
using com::socket::UDPClient;

constexpr int TCP_TEST1_SERVER_PORT = 54321;
constexpr int TCP_TEST2_SERVER_PORT = 54322;
constexpr int UDP_TEST1_SERVER_PORT = 54323;
constexpr int UDP_TEST2_SERVER_PORT = 54324;
static const std::string IP_ADDR("127.0.0.1");
static const std::string TEST_STRING("This is my testing string.");

static void tcpClientThread(void);
static void tcpSslClient(void);
static void udpSslClient(void);

static void TCP_TEST1(void)
{
    std::cout << "Start TCP Test 1" << std::endl;
    TCPServer s(TCP_TEST1_SERVER_PORT);

    auto t = std::jthread(&tcpClientThread);
    static_cast<void>(t);

    std::cout << "Accepting" << std::endl;
    TCPClient c = s.accept();

    std::cout << "Server accepted" << std::endl;

    char buffer[100];
    const auto ret = c.read(buffer, sizeof(buffer));
    if (ret != static_cast<int>(TEST_STRING.length()))
    {
        assert(false);
    }

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer << std::endl;

    if (TEST_STRING.compare(buffer) != 0)
    {
        assert(false);
    }

    std::cout << "********************** TCP Test 1 PASSED *******************" << std::endl;
}

static void tcpClientThread(void)
{
    std::cout << __FUNCTION__ << std::endl;
    TCPClient c(IP_ADDR, TCP_TEST1_SERVER_PORT);

    std::cout << "Client connected" << std::endl;

    const auto ret = c.send(TEST_STRING.c_str(), TEST_STRING.length());
    if (ret != static_cast<int>(TEST_STRING.length()))
    {
        assert(false);
    }

    std::cout << "Client sent: " << TEST_STRING << std::endl;
}

static void udpClientThread(void)
{
    std::cout << __FUNCTION__ << std::endl;
    UDPClient c(IP_ADDR, UDP_TEST1_SERVER_PORT);

    std::cout << "Client connected" << std::endl;

    const auto ret = c.send(TEST_STRING.c_str(), TEST_STRING.length());
    if (ret != static_cast<int>(TEST_STRING.length()))
    {
        assert(false);
    }

    std::cout << "Client sent: " << TEST_STRING << std::endl;
}

static void UDP_TEST1(void)
{
    std::cout << "Start UDP Test 1" << std::endl;

    UDPServer s(UDP_TEST1_SERVER_PORT, IP_ADDR);

    auto t = std::jthread(&udpClientThread);
    static_cast<void>(t);

    std::cout << "Accepting" << std::endl;
    s.accept();

    std::cout << "Server accepted" << std::endl;
    // wait for client to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    char buffer[100];
    const auto ret = s.read(buffer, sizeof(buffer));
    if (ret != static_cast<int>(TEST_STRING.length()))
    {
        std::cout << ret << ":" << strerror(errno) << std::endl;
        assert(false);
    }

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer << std::endl;

    if (TEST_STRING.compare(buffer) != 0)
    {
        assert(false);
    }

    std::cout << "********************** UDP Test 1 PASSED *******************" << std::endl;
}

#ifdef LINUX
static void TCP_TEST2(void) 
{
    std::cout << "Start TCP Test 2" << std::endl;

    pid_t p = fork();
    if (p == -1)
    {
        std::cout << "Failed to fork!" << std::endl;
        assert(false);
    }
    else if (p != 0)
    {
        TCPServer s(KEY_FILE, CERT_FILE);

        s.bindAndListen(TCP_TEST2_SERVER_PORT);
        std::cout << "Accepting" << std::endl;
        TCPClient c = s.accept();

        std::cout << "Server accepted" << std::endl;

        char buffer[TEST_STRING.length() + 1];
        const auto ret = c.read(buffer, sizeof(buffer));
        if (ret != static_cast<int>(TEST_STRING.length()))
        {
            assert(false);
        }

        buffer[ret] = '\0';

        std::cout << "Server received: " << buffer << std::endl;

        if (TEST_STRING.compare(buffer) != 0)
        {
            assert(false);
        }

        std::cout << "Received correct data!" << std::endl;

        int waitVal = 0;
        pid_t pchild = -1;
        do
        {
            std::cout << "Waiting for child" << std::endl;
            pchild = ::wait(&waitVal);
        } while (pchild != p);

        std::cout << "****************** TCP SSL Test 2 PASSED *************************" << std::endl;
    }
    else
    {
        // wait for server to set itself up
        std::this_thread::sleep_for(std::chrono::seconds(1));
        tcpSslClient();
        // wait for message to flow thru
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Child is done" << std::endl;
        _exit(0);
    }
}

static void UDP_TEST2(void) 
{
    std::cout << "Start UDP Test 2" << std::endl;

    pid_t p = fork();
    if (p == -1)
    {
        std::cout << "Failed to fork!" << std::endl;
        assert(false);
    }
    else if (p != 0)
    {
        UDPServer s(UDP_TEST2_SERVER_PORT, IP_ADDR, KEY_FILE, CERT_FILE);

        s.accept();

        std::cout << "Accepted!" << std::endl;

        char buffer[TEST_STRING.length() + 1];
        const auto ret = s.read(buffer, sizeof(buffer));
        if (ret != static_cast<int>(TEST_STRING.length()))
        {
            assert(false);
        }

        buffer[ret] = '\0';

        std::cout << "Server received: " << buffer << std::endl;

        if (TEST_STRING.compare(buffer) != 0)
        {
            assert(false);
        }

        std::cout << "Received correct data!" << std::endl;

        int waitVal = 0;
        pid_t pchild = -1;
        do
        {
            std::cout << "Waiting for child" << std::endl;
            pchild = ::wait(&waitVal);
        } while (pchild != p);

        std::cout << "****************** UDP SSL Test 2 PASSED *************************" << std::endl;
    }
    else
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        udpSslClient();
        std::cout << "Child is done" << std::endl;
        _exit(0);
    }
}

auto main() -> int 
{
    TCP_TEST1();

    // let previous test finish
    std::this_thread::sleep_for(std::chrono::seconds(1));
    TCP_TEST2();

    // let previous test finish
    std::this_thread::sleep_for(std::chrono::seconds(1));
    UDP_TEST1();

    // let previous test finish
    std::this_thread::sleep_for(std::chrono::seconds(1));
    UDP_TEST2();

    return 0;
}

#else

static void TCP_TEST2(int argc, char *argv[]) 
{
    // check if this is the server or client process running
    // server process has 1 command line argument
    // client process has 2 command line arguments
    if (argc == 1) 
    {
        PROCESS_INFORMATION pi = {};
        STARTUPINFO si = {};

        std::string a(argv[0]);
        a.append(" -c");
        std::cout << a << std::endl;
        LPSTR args = const_cast<LPSTR>(a.c_str());
        // respawn the test process to run the SSL client connection
        if (!::CreateProcess(argv[0], args, nullptr, nullptr, false, 0, nullptr, ".", &si, &pi))
        {
            std::cout << "Error = " << GetLastError() << std::endl;
            assert(false);
        }

        TCPServer s(KEY_FILE, CERT_FILE);

        s.bindAndListen(TCP_TEST2_SERVER_PORT);
        std::cout << "Accepting" << std::endl;
        TCPClient c = s.accept();

        std::cout << "Server accepted" << std::endl;

        char buffer[100];
        const auto ret = c.read(buffer, sizeof(buffer));
        if (ret != static_cast<int>(TEST_STRING.length())) {
            assert(false);
        }

        buffer[ret] = '\0';

        std::cout << "Server received: " << buffer << std::endl;

        if (TEST_STRING.compare(buffer) != 0) {
            assert(false);
        }

        std::cout << "Received correct data!" << std::endl;

        // wait for client process to exit
        static_cast<void>(::WaitForSingleObject(pi.hProcess, INFINITE));
        static_cast<void>(::CloseHandle(pi.hThread));
        static_cast<void>(::CloseHandle(pi.hProcess));

        std::cout << "****************** Test 2 PASSED *************************" << std::endl;
    }
    else 
    {
        // this is the child process!
        tcpSslClient();
    }
}

auto main(int argc, char *argv[]) -> int 
{
    if (argc == 1) 
    {
        TEST1();
    }

    TEST2(argc, argv);

    return 0;
}

#endif

static void tcpSslClient(void)
{
    TCPClient c(IP_ADDR, TCP_TEST2_SERVER_PORT, true);

    std::cout << "Client connected" << std::endl;
    // wait for server to accept SSL connection
    std::this_thread::sleep_for(std::chrono::seconds(1));

    const auto ret = c.send(TEST_STRING.c_str(), TEST_STRING.length());
    if (ret != static_cast<int>(TEST_STRING.length()))
    {
        assert(false);
    }

    std::cout << "Client sent: " << TEST_STRING << std::endl;
}

static void udpSslClient(void)
{
    // wait for server to start accepting
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << __FUNCTION__ << std::endl;
    UDPClient c(IP_ADDR, UDP_TEST2_SERVER_PORT, KEY_FILE, CERT_FILE);

    std::cout << "Client connected" << std::endl;
    // wait for server to accept SSL connection
    std::this_thread::sleep_for(std::chrono::seconds(1));

    const auto ret = c.send(TEST_STRING.c_str(), TEST_STRING.length());
    if (ret != static_cast<int>(TEST_STRING.length()))
    {
        assert(false);
    }

    std::cout << "Client sent: " << TEST_STRING << std::endl;
}
