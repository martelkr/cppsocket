#include <gtest/gtest.h>
#include "cppsocket.hpp"

#include <thread>
#include <iostream>
#include <sys/types.h>
#include <array>

#ifdef __GNUC__
#include <unistd.h>
#include <sys/wait.h>

// @TODO: replace with your test key and certificate file
static const std::string KEY_FILE{std::getenv("HOME") + std::string("/key.pem")}; // NOLINT
static const std::string CERT_FILE{std::getenv("HOME") + std::string("/scert.crt")}; // NOLINT
#else
#include <tchar.h>
#include <locale>

#include <openssl/applink.c>

// @TODO: replace with your test key and certificate file
static const std::string KEY_FILE{getenv("USERPROFILE") + std::string("\\privatekey.key")}; // NOLINT
static const std::string CERT_FILE{getenv("USERPROFILE") + std::string("\\certificate.crt")}; // NOLINT

static int gargc{0};
static char** gargv = nullptr;
#endif

using com::github::socket::Socket;
using com::github::socket::TcpClient;
using com::github::socket::TcpServer;
using com::github::socket::UdpClient;
using com::github::socket::UdpServer;
using com::github::socket::SecureTcpClient;
using com::github::socket::SecureTcpServer;
using com::github::socket::SecureUdpClient;
using com::github::socket::SecureUdpServer;

constexpr unsigned int ONE_HUNDRED_MSECS = 100;
constexpr int BUFFER_LEN = 100;
constexpr int TCP_TEST1_SERVER_PORT = 54321;
constexpr int TCP_TEST2_SERVER_PORT = 54322;
constexpr int UDP_TEST1_SERVER_PORT = 54323;
constexpr int UDP_TEST2_SERVER_PORT = 54324;
static const std::string IP_ADDR("127.0.0.1");
static const std::string TEST_STRING1 = "This is my testing string 1.";
static const std::string TEST_STRING2 = "This is my testing string 2.";

// NOLINTNEXTLINE
TEST(Unsecure, TCP)
{
    std::cout << "Start TCP Test 1" << std::endl;
    TcpServer server(TCP_TEST1_SERVER_PORT, IP_ADDR);
    ASSERT_EQ(server.listen(1), 0);

    auto testThread = std::jthread([]{
        TcpClient client(IP_ADDR, TCP_TEST1_SERVER_PORT);

        int flag = 0;
        socklen_t len = sizeof(flag);
        ASSERT_EQ(client.getsockopt(IPPROTO_TCP, TCP_NODELAY, &flag, &len), 0);
        ASSERT_EQ(flag, 1);

        std::cout << "Client connected" << std::endl;

        auto ret = client.send(TEST_STRING1.c_str(), TEST_STRING1.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        ret = client.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);
    });

    std::string clientIp;
    uint16_t clientPort = 0;
    std::cout << "Accepting" << std::endl;
    Socket& serverSocket = static_cast<Socket&>(server);
    auto acceptSocket = serverSocket.accept(clientIp, clientPort);
    ASSERT_GT(acceptSocket, 0);
    TcpClient client(acceptSocket);

    ASSERT_STREQ(clientIp.c_str(), IP_ADDR.c_str());
    ASSERT_GT(clientPort, 0);

    std::cout << "Server accepted" << std::endl;

    timeval timeout {.tv_sec = 1, .tv_usec = 0};
    ASSERT_TRUE(client.selectRead(timeout));

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = client.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    ASSERT_TRUE(client.selectWrite(timeout));

    ret = client.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    std::cout << "********************** TCP Unsecure Test PASSED *******************" << std::endl;
}

// NOLINTNEXTLINE
TEST(Unsecure2, TCP)
{
    std::cout << "Start TCP Test 1" << std::endl;
    TcpServer server("0.0.0.0", TCP_TEST1_SERVER_PORT, 5);
    ASSERT_EQ(server.listen(1), 0);

    auto testThread = std::jthread([]{
        TcpClient client(IP_ADDR, TCP_TEST1_SERVER_PORT);

        std::cout << "Client connected" << std::endl;

        auto ret = client.send(TEST_STRING1.c_str(), TEST_STRING1.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        ret = client.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);
    });

    std::cout << "Accepting" << std::endl;
    TcpClient client = server.accept();

    std::cout << "Server accepted" << std::endl;

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = client.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    ret = client.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    std::cout << "********************** TCP Unsecure Test 2 PASSED *******************" << std::endl;
}

// NOLINTNEXTLINE
TEST(Unsecure, UDP)
{
    std::cout << "Start UDP Test 1" << std::endl;

    UdpServer server(UDP_TEST1_SERVER_PORT, IP_ADDR);

    auto testThread = std::jthread([]{
        UdpClient client(IP_ADDR, UDP_TEST1_SERVER_PORT);

        std::cout << "Client connected" << std::endl;

        auto ret = client.send(TEST_STRING1.c_str(), TEST_STRING1.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        ret = client.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);
    });

    // wait for client to start
    std::this_thread::sleep_for(std::chrono::milliseconds(ONE_HUNDRED_MSECS));

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = server.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    ret = server.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    testThread.join();

    std::cout << "********************** UDP Unsecure Test PASSED *******************" << std::endl;
}

// NOLINTNEXTLINE
TEST(Unsecure2, UDP)
{
    std::cout << "Start UDP Test 2" << std::endl;

    UdpServer server(UDP_TEST1_SERVER_PORT, IP_ADDR);

    auto testThread = std::jthread([]{
        UdpClient client;

        std::cout << "Client connected" << std::endl;

        auto ret = client.sendto(TEST_STRING1.c_str(), TEST_STRING1.length(), IP_ADDR, UDP_TEST1_SERVER_PORT);
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::string readfromIp;
        uint16_t readfromPort;
        std::array<char, BUFFER_LEN> buffer = {};
        ret = client.readfrom(buffer.data(), buffer.size(), readfromIp, readfromPort);
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));
        ASSERT_STREQ(readfromIp.c_str(), IP_ADDR.c_str());
        ASSERT_GT(readfromPort, 0);

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);
    });

    // wait for client to start
    std::this_thread::sleep_for(std::chrono::milliseconds(ONE_HUNDRED_MSECS));

    sockaddr_in readAddr = {};
    socklen_t len = sizeof(readAddr);
    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = server.readfrom(buffer.data(), buffer.size(), reinterpret_cast<sockaddr*>(&readAddr), &len);
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    ret = server.sendto(TEST_STRING2.c_str(), TEST_STRING2.length(), reinterpret_cast<sockaddr*>(&readAddr), len);
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    testThread.join();

    std::cout << "********************** UDP Unsecure Test 2 PASSED *******************" << std::endl;
}

// NOLINTNEXTLINE
TEST(Unsecure3, UDP)
{
    std::cout << "Start UDP Test 3" << std::endl;

    UdpServer server(UDP_TEST1_SERVER_PORT, IP_ADDR);

    auto testThread = std::jthread([]{
        UdpClient client; //(IP_ADDR, UDP_TEST1_SERVER_PORT);
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        ASSERT_GT(::inet_pton(AF_INET, IP_ADDR.c_str(), &addr.sin_addr),  0);
        addr.sin_port = ::htons(UDP_TEST1_SERVER_PORT);

        ASSERT_EQ(client.connect(reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

        std::cout << "Client connected" << std::endl;

        auto ret = client.send(TEST_STRING1.c_str(), TEST_STRING1.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        ret = client.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);
    });

    // wait for client to start
    std::this_thread::sleep_for(std::chrono::milliseconds(ONE_HUNDRED_MSECS));

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = server.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    ret = server.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    testThread.join();

    std::cout << "********************** UDP Unsecure Test 3 PASSED *******************" << std::endl;
}

// NOLINTNEXTLINE
TEST(Secure, TCP)
{
    std::cout << "Start TCP Test 2" << std::endl;

    ASSERT_THROW(SecureTcpServer("", ""), std::runtime_error);

    SecureTcpServer server(KEY_FILE, CERT_FILE);

    ASSERT_EQ(server.bind(IP_ADDR, TCP_TEST2_SERVER_PORT), true);
    ASSERT_EQ(server.listen(1), 0);

    auto testThread = std::jthread([]{
        SecureTcpClient client(IP_ADDR, TCP_TEST2_SERVER_PORT);

        std::cout << "Client connected" << std::endl;
        // wait for server to accept SSL connection
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto ret = client.send(TEST_STRING1.c_str(), TEST_STRING1.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        ret = client.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);

        std::cout << "Client received correct data!" << std::endl;
        // wait for message to flow thru
        std::this_thread::sleep_for(std::chrono::seconds(1));
    });
    
    // wait for server to set itself up
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << "Accepting" << std::endl;
    std::string acceptIp;
    uint16_t acceptPort;
    SecureTcpClient client = server.accept(acceptIp, acceptPort);
    ASSERT_STREQ(acceptIp.c_str(), IP_ADDR.c_str());
    ASSERT_GT(acceptPort, 0);

    std::cout << "Server accepted" << std::endl;

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = client.read(buffer.data(), buffer.size());
    if (ret != static_cast<int>(TEST_STRING1.length()))
    {
        assert(false);
    }

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    std::cout << "Server received correct data!" << std::endl;

    ret = client.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    std::cout << "****************** TCP SSL Test PASSED *************************" << std::endl;
}

// NOLINTNEXTLINE
TEST(Secure2, TCP)
{
    std::cout << "Start TCP Test 2" << std::endl;

    ASSERT_THROW(SecureTcpServer("", ""), std::runtime_error);

    SecureTcpServer server(KEY_FILE, CERT_FILE, TCP_TEST2_SERVER_PORT, IP_ADDR);

    ASSERT_EQ(server.listen(1), 0);

    auto testThread = std::jthread([]{
        SecureTcpClient client(IP_ADDR, TCP_TEST2_SERVER_PORT);

        std::cout << "Client connected" << std::endl;
        // wait for server to accept SSL connection
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto ret = client.send(TEST_STRING1.c_str(), TEST_STRING1.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        ret = client.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);

        std::cout << "Client received correct data!" << std::endl;
        // wait for message to flow thru
        std::this_thread::sleep_for(std::chrono::seconds(1));
    });
    
    // wait for server to set itself up
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << "Accepting" << std::endl;
    SecureTcpClient client = server.accept();

    std::cout << "Server accepted" << std::endl;

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = client.read(buffer.data(), buffer.size());
    if (ret != static_cast<int>(TEST_STRING1.length()))
    {
        assert(false);
    }

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    std::cout << "Server received correct data!" << std::endl;

    ret = client.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    std::cout << "****************** TCP SSL Test 2 PASSED *************************" << std::endl;
}

// NOLINTNEXTLINE
TEST(Secure, UDP)
{
    std::cout << "Start UDP SSL Test" << std::endl;

    SecureUdpServer server(KEY_FILE, CERT_FILE, UDP_TEST2_SERVER_PORT, IP_ADDR);

    auto testThread = std::jthread([]{
        std::this_thread::sleep_for(std::chrono::seconds(1));
        // wait for server to start accepting
        SecureUdpClient client(IP_ADDR, UDP_TEST2_SERVER_PORT, KEY_FILE, CERT_FILE);

        std::cout << "Client connected" << std::endl;
        // wait for server to accept SSL connection
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto ret = client.send(TEST_STRING1.c_str(), TEST_STRING1.length());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

        std::cout << "Client sent: " << TEST_STRING1 << std::endl;

        std::array<char, BUFFER_LEN> buffer = {};
        ret = client.read(buffer.data(), buffer.size());
        ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

        buffer[ret] = '\0';

        std::cout << "Client received: " << buffer.data() << std::endl;

        ASSERT_EQ(TEST_STRING2.compare(buffer.data()), 0);

        std::cout << "Received correct data!" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Child is done" << std::endl;
    });

    std::cout << "Accepting client" << std::endl;

    server.accept();

    std::cout << "Accepted!" << std::endl;

    std::array<char, BUFFER_LEN> buffer = {};
    auto ret = server.read(buffer.data(), buffer.size());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING1.length()));

    buffer[ret] = '\0';

    std::cout << "Server received: " << buffer.data() << std::endl;

    ASSERT_EQ(TEST_STRING1.compare(buffer.data()), 0);

    std::cout << "Received correct data!" << std::endl;

    ret = server.send(TEST_STRING2.c_str(), TEST_STRING2.length());
    ASSERT_EQ(ret, static_cast<int>(TEST_STRING2.length()));

    std::cout << "Server sent: " << TEST_STRING2 << std::endl;

    std::cout << "****************** UDP SSL Test PASSED *************************" << std::endl;
}

auto main(int argc, char* argv[]) -> int 
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
