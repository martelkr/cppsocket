# C++ client/server with SSL/TLS support (header file only)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](http://opensource.org/licenses/MIT)
![Linux Build](https://github.com/martelkr/cppsocket/actions/workflows/linux.yml/badge.svg)
![Windows Build](https://github.com/martelkr/cppsocket/actions/workflows/windows.yml/badge.svg)
![clang Build](https://github.com/martelkr/cppsocket/actions/workflows/clang.yml/badge.svg)
![profile Build](https://github.com/martelkr/cppsocket/actions/workflows/profile.yml/badge.svg)
![cppcheck Build](https://github.com/martelkr/cppsocket/actions/workflows/cppcheck.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/martelkr/cppsocket/badge.svg?branch=main)](https://coveralls.io/github/martelkr/cppsocket?branch=main)
![cpp-linter](https://github.com/martelkr/cppsocket/actions/workflows/linter.yml/badge.svg)
![Address Sanitization](https://github.com/martelkr/cppsocket/actions/workflows/addressSanitization.yml/badge.svg)
![Code QL](https://github.com/martelkr/cppsocket/actions/workflows/codeql.yml/badge.svg)
![Clang Tidy](https://github.com/martelkr/cppsocket/actions/workflows/clang-tidy.yml/badge.svg)

## About
This is a header file only implementation of a C++ client/server with or without SSL/TLS/DTLS.
The implementation uses OpenSSL and BSD API to implement the underlying socket interfaces.

Compilation has been tested with:
- GCC 11.3.0 (GNU/Linux Ubuntu 22.04.1 LTS)
	- cmake 3.22.1
	- googletest 1.11.0-3
	- clang 14.0.0-1ubuntu1
- Visual Studio Community 2022 17.4.4 (64-bit) (Windows 11)
	- cmake 3.26.0-rc1
	- googletest 1.13.0

## Usage

### Socket

Base sockect class for BSD API class methods. 

```cpp
// default constructor - no socket created because type is unknown
Socket();
Socket::initSocket(domain, type, protocol); // creates socket

// create socket from previously created file descriptor
Socket(int);

// create socket of the given type
Socket(domain, type, protocol);


```

### TCP server/client

Create a TCP server object for accepting TCP connections. 

```cpp
// default no IP/port bound but TCP socket created
TcpServer(); 

// TCP socket created, IP/port bound, but not listening
TcpServer(const uint16_t port, const std::string& ipAddr = "0.0.0.0");

// TCP socket created, IP/port bound, and listening for clients
TcpServer(const std::string& ipAddr, const uint16_t port, const int backlog);
```

Create a TCP client object to connect to a known TCP server.

```cpp
// default TCP socket created but no server connection
TcpClient();

// create TcpClient with given TCP socket file descriptor
TcpClient(const int filedescriptor);

// TcpClient connected to a TcpServer IP/port
TcpClient(const std::string& ipAddr, const uint16_t port);
```

Create a SSL TCP Server for accepting SSL TCP clients.

```cpp
// Create a SSL TCP Server not bound to IP/port
SecureTcpServer(const std::string& keyFile, const std::string& certFile);

// Create a SSL TCP Server bound to a given port and IP or default IP
SecureTcpServer(const std::string& keyFile, const std::string& certFile, const uint16_t port, const std::string& ipAddr = "0.0.0.0");
```

Create a SSL TCP client for connecting to SSL TCP servers.

```cpp
// create a SSL TCP client with a given SSL context - used with SecureTcpServer::accept return
SecureTcpClient(const int filedescriptor, SSL_CTX *sslctx);

// create a SSL TCP client connected to a SSL TCP server
SecureTcpClient(const std::string& ipAddr, const uint16_t port);
```

For a BSD-like approach, the following sequence can be followed:

```cpp
// Server

// create server socket
TcpServer server; // add key file and cert file here for secure connection

// bind to port 54321 on IP 0.0.0.0
server.bindAndListen(54321); 

TcpClient client = server.accept();
```

```cpp
// Client

// Connect to TCP server on IP 127.0.0.1 and port 54321
TcpClient client("127.0.0.1", 54321); // add key file and cert file here for secure connection
```

### UDP server/client

Create a UDP server object for accepting UDP connections. 

```cpp
// default constructor creates unbound unsecure UDP server socket
UdpServer();

// default DTLS constructor create unbound UDP server socket ready for DTLS
// NOTE: UdpServer s("", ""); results in unbound unsecure UDP server socket
UdpServer(const std::string& keyFile, const std::string& certFile);

// creates unsecure UDP server socket bound to specific port and IP address (default all host IP)
explicit UdpServer(const uint16_t port, const std::string& ip = "0.0.0.0");

// creates bound UDP server socket ready for DTLS
// NOTE: UdpServer s("", ""); results in unbound unsecure UDP server socket
UdpServer(const uint16_t port, const std::string& ip, const std::string& keyFile, const std::string& certFile);
```

Create a UDP client object to connect to a known UDP server.

```cpp

// default constructor creates unconnected UDP client socket
UDPClient();

// creates UDP client socket connected to UDP server
UDPClient(const std::string& remoteIp, const uint16_t remotePort);

// creates unconnected UDP client socket for DTLS communication
UDPClient(const std::string& keyFile, const std::string& certFile);

// created UDP client socket connected to UDP server using DTLS
UDPClient(const std::string& remoteIp, const uint16_t remotePort, const std::string& keyFile, const std::string& certFile);
```

For a BSD-like approach, the following sequence can be followed:

```cpp
// Server

// create server socket
UdpServer server; // add key file and cert file here for secure connection

// bind to port 54321 on IP 0.0.0.0
server.bind(54321); 

// following not needed for unsecure connection but is needed for DTLS connection
server.accept();
```

```cpp
// Client

// Connect to UDP server on IP 127.0.0.1 and port 54321
UDPClient client("127.0.0.1", 54321); // add key file and cert file here for secure connection
```

## Thread Safety

Do not share TcpServer, TcpClient, UDPClient or UdpServer objects across threads unless you provide your own thread safety on the send/read and accept calls.

## Installation

Use the `cppsocket.hpp` file in your source tree and include it in the file that need to use it.

## Run Unit Tests

Unit tests run with ctest:
```
ctest -C debug
```

## Contribute
All contributions are highly appreciated.
