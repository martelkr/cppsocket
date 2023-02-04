
#include "cppsocket.hpp"

#include <thread>
#include <iostream>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

using com::socket::TCPServer;
using com::socket::TCPClient;

constexpr int TEST1_SERVER_PORT = 54321;
constexpr int TEST2_SERVER_PORT = 54322;
static const std::string IP_ADDR("127.0.0.1");
static std::string TEST_STRING("This is my testing string.");
static std::string KEY_FILE("/usr/share/ca-certificates/extra/key.pem");
static std::string CERT_FILE("/usr/share/ca-certificates/extra/scert.crt");

static void clientThread(void);
static void sslClientThread(void);

static void TEST1(void)
{
    TCPServer s;

    s.bindAndListen(TEST1_SERVER_PORT);

    auto t = std::jthread(&clientThread);

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

    t.join();

    std::cout << "********************** Test 1 PASSED *******************" << std::endl;
}

static void clientThread(void)
{
    TCPClient c(IP_ADDR, TEST1_SERVER_PORT);

    std::cout << "Client connected" << std::endl;

    const auto ret = c.send(TEST_STRING.c_str(), TEST_STRING.length());
    if (ret != static_cast<int>(TEST_STRING.length()))
    {
        assert(false);
    }

    std::cout << "Client sent: " << TEST_STRING << std::endl;
}

static void TEST2(void)
{
    pid_t p = fork();
    if (p == -1)
    {
        std::cout << "Failed to fork!" << std::endl;
        assert(false);
    }
    else if (p != 0)
    {
        TCPServer s(KEY_FILE, CERT_FILE);

        s.bindAndListen(TEST2_SERVER_PORT);
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

        std::cout << "****************** Test 2 PASSED *************************" << std::endl;
    }
    else
    {
        // wait for server to set itself up
        std::this_thread::sleep_for(std::chrono::seconds(1));
        sslClientThread();
        // wait for message to flow thru
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Child is done" << std::endl;
    }
}

static void sslClientThread(void)
{
    TCPClient c(IP_ADDR, TEST2_SERVER_PORT, true);

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

auto main() -> int
{
    TEST1();

    TEST2();

    return 0;
}