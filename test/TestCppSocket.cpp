#include <gtest/gtest.h>
#include "cppsocket.hpp"

#include <thread>
#include <iostream>
#include <sys/types.h>
#include <array>

#ifdef LINUX
#include <unistd.h>
#include <sys/wait.h>

// @TODO: replace with your test key and certificate file
static const std::string KEY_FILE{std::getenv("HOME") + std::string("/key.pem")};
static const std::string CERT_FILE{std::getenv("HOME") + std::string("/scert.crt")};
#else
#include <tchar.h>
#include <locale>

#include <openssl/applink.c>

// @TODO: replace with your test key and certificate file
static const std::string KEY_FILE{getenv("USERPROFILE") + std::string("\\privatekey.key")};
static const std::string CERT_FILE{getenv("USERPROFILE") + std::string("\\certificate.crt")};

static int gargc{0};
static char** gargv = nullptr;
#endif

using com::socket::TCPServer;
using com::socket::TCPClient;
using com::socket::UDPServer;
using com::socket::UDPClient;

constexpr int BUFFER_LEN = 100;
constexpr int TCP_TEST1_SERVER_PORT = 54321;
constexpr int TCP_TEST2_SERVER_PORT = 54322;
constexpr int UDP_TEST1_SERVER_PORT = 54323;
constexpr int UDP_TEST2_SERVER_PORT = 54324;
static const std::string IP_ADDR("127.0.0.1");
static const std::string TEST_STRING1("This is my testing string 1.");
static const std::string TEST_STRING2("This is my testing string 2.");

static void tcpSslClient();
static void udpSslClient();

TEST(TCP, Unsecure)
{
    std::cout << "Start TCP Test 1" << std::endl;
    TCPServer s(TCP_TEST1_SERVER_PORT);

    auto t = std::jthread([]{
        TCPClient c(IP_ADDR, TCP_TEST1_SERVER_PORT);

        std::cout << "Client connected" << std::endl;

        auto ret = c.send(TEST_STRING1.c_str(), TEST_STRING1.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        ret = c.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);
    });
    static_cast<void>(t);

    std::cout << "Accepting" << std::endl;
    TCPClient c = s.accept();

    std::cout << "Server accepted" << std::endl;

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = c.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    ret = c.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    t.join();

    std::cout << "********************** TCP Test 1 PASSED *******************" << std::endl;
}

TEST(UDP, UnsecureTest)
{
    std::cout << "Start UDP Test 1" << std::endl;

    UDPServer s(UDP_TEST1_SERVER_PORT, IP_ADDR);

    auto t = std::jthread([]{
        UDPClient c(IP_ADDR, UDP_TEST1_SERVER_PORT);

        std::cout << "Client connected" << std::endl;

        auto ret = c.send(TEST_STRING1.c_str(), TEST_STRING1.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        ret = c.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);
    });

    std::cout << "Accepting" << std::endl;
    s.accept();

    std::cout << "Server accepted" << std::endl;
    // wait for client to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = s.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    ret = s.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    t.join();

    std::cout << "********************** UDP Test 1 PASSED *******************" << std::endl;
}

#ifdef LINUX
TEST(TCP, Secure)
{
    std::cout << "Start TCP Test 2" << std::endl;

    pid_t p = fork();
    if (p == -1)
    {
        std::cout << "Failed to fork!" << std::endl;
        ASSERT_TRUE(false);
    }
    else if (p != 0)
    {
        TCPServer s(KEY_FILE, CERT_FILE);

        s.bindAndListen(TCP_TEST2_SERVER_PORT);
        std::cout << "Accepting" << std::endl;
        TCPClient c = s.accept();

        std::cout << "Server accepted" << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        auto ret = c.read(buffer.data(), buffer.size());
        if (ret != static_cast<int>(TEST_STRING1.length()))
        {
            assert(false);
        }

        buffer[ret] = '\0';

        std::cout << "Server received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

        std::cout << "Received correct data!" << std::endl;

        ret = c.send(TEST_STRING2.c_str(), TEST_STRING2.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        std::cout << "Server sent: " << TEST_STRING2 << std::endl;

        int waitVal = 0;
        pid_t pchild = -1;
        do
        {
            std::cout << "Waiting for child" << std::endl;
            pchild = ::waitpid(0, &waitVal, WUNTRACED);
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
        _exit(testing::Test::HasFailure());
    }
}

TEST(UDP, SecureTest)
{
    std::cout << "Start UDP Test 2" << std::endl;

    pid_t p = fork();
    if (p == -1)
    {
        std::cout << "Failed to fork!" << std::endl;
        ASSERT_TRUE(false);
    }
    else if (p != 0)
    {
        UDPServer s(UDP_TEST2_SERVER_PORT, IP_ADDR, KEY_FILE, CERT_FILE);

        std::cout << "Accepting client" << std::endl;

        s.accept();

        std::cout << "Accepted!" << std::endl;

        if (testing::Test::HasFailure())
        {
            return;
        }

        std::array<char, BUFFER_LEN> buffer = {};
        auto ret = s.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        buffer[ret] = '\0';

        std::cout << "Server received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

        std::cout << "Received correct data!" << std::endl;

        ret = s.send(TEST_STRING2.c_str(), TEST_STRING2.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        std::cout << "Server sent: " << TEST_STRING2 << std::endl;

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
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Child is done" << std::endl;
        _exit(testing::Test::HasFailure());
    }
}

auto main(int argc, char* argv[]) -> int 
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

#else

TEST(TCP, Secure_Test)
{
    PROCESS_INFORMATION pi = {};
    STARTUPINFO si = {};

    std::string a(gargv[0]);
    a.append(" -tcp");
    std::cout << a << std::endl;
    LPSTR args = const_cast<LPSTR>(a.c_str());
    // respawn the test process to run the SSL client connection
    if (!::CreateProcess(gargv[0], args, nullptr, nullptr, false, 0, nullptr, ".", &si, &pi))
    {
        std::cout << "Error = " << GetLastError() << std::endl;
        ASSERT_TRUE(false);
    }

    TCPServer s(KEY_FILE, CERT_FILE);

    s.bindAndListen(TCP_TEST2_SERVER_PORT);
    std::cout << "Accepting" << std::endl;
    TCPClient c = s.accept();

    std::cout << "Server accepted" << std::endl;

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = c.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    std::cout << "Received correct data!" << std::endl;

    ret = c.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Client sent: " << TEST_STRING2 << std::endl;

    // wait for client process to exit
    static_cast<void>(::WaitForSingleObject(pi.hProcess, INFINITE));
    static_cast<void>(::CloseHandle(pi.hThread));
    static_cast<void>(::CloseHandle(pi.hProcess));

    std::cout << "****************** TCP Test 2 PASSED *************************" << std::endl;
}

TEST(UDP, Secure_Test)
{
    PROCESS_INFORMATION pi = {};
    STARTUPINFO si = {};

    std::string a(gargv[0]);
    a.append(" -udp");
    std::cout << a << std::endl;
    LPSTR args = const_cast<LPSTR>(a.c_str());
    // respawn the test process to run the SSL client connection
    if (!::CreateProcess(gargv[0], args, nullptr, nullptr, false, 0, nullptr, ".", &si, &pi))
    {
        std::cout << "Error = " << GetLastError() << std::endl;
        ASSERT_TRUE(false);
    }

    UDPServer s(UDP_TEST2_SERVER_PORT, IP_ADDR, KEY_FILE, CERT_FILE);

    s.accept();

    std::cout << "Accepted!" << std::endl;

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = s.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    std::cout << "Received correct data!" << std::endl;

    ret = s.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Client sent: " << TEST_STRING2 << std::endl;

    // wait for client process to exit
    static_cast<void>(::WaitForSingleObject(pi.hProcess, INFINITE));
    static_cast<void>(::CloseHandle(pi.hThread));
    static_cast<void>(::CloseHandle(pi.hProcess));

    std::cout << "****************** UDP Test 2 PASSED *************************" << std::endl;
}

static void TCP_TEST2() 
{
    // this is the child process!
    tcpSslClient();
}

static void UDP_TEST2() 
{ 
    udpSslClient(); 
}

auto main(int argc, char *argv[]) -> int 
{
    int ret = 0;
    if (argc == 1) 
    {
        gargc = argc;
        gargv = argv;
        testing::InitGoogleTest(&argc, argv);
        ret = RUN_ALL_TESTS();
    }
    else if (std::strcmp(argv[1], "-tcp") == 0)
    {
        TCP_TEST2();
    }
    else if (std::strcmp(argv[1], "-udp") == 0)
    {
        UDP_TEST2();
    }

    return ret;
}
#endif

static void tcpSslClient()
{
    TCPClient c(IP_ADDR, TCP_TEST2_SERVER_PORT, true);

    std::cout << "Client connected" << std::endl;
    // wait for server to accept SSL connection
    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto ret = c.send(TEST_STRING1.c_str(), TEST_STRING1.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    std::cout << "Client sent: " << TEST_STRING1 << std::endl;

    std::array<char, BUFFER_LEN> buffer = {};
    ret = c.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    buffer[ret] = '\0';

    std::cout << "Client received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);

    std::cout << "Received correct data!" << std::endl;
}

static void udpSslClient()
{
    // wait for server to start accepting
    UDPClient c(IP_ADDR, UDP_TEST2_SERVER_PORT, KEY_FILE, CERT_FILE);

    std::cout << "Client connected" << std::endl;
    // wait for server to accept SSL connection
    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto ret = c.send(TEST_STRING1.c_str(), TEST_STRING1.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    std::cout << "Client sent: " << TEST_STRING1 << std::endl;

    std::array<char, BUFFER_LEN> buffer = {};
    ret = c.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    buffer[ret] = '\0';

    std::cout << "Client received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);

    std::cout << "Received correct data!" << std::endl;
}
