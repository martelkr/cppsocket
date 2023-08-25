# C++ client/server with SSL/TLS support (header file only)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](http://opensource.org/licenses/MIT)
![cmake Build](https://github.com/martelkr/cppsocket/actions/workflows/cmake.yml/badge.svg)
![clang Build](https://github.com/martelkr/cppsocket/actions/workflows/clang.yml/badge.svg)
![profile Build](https://github.com/martelkr/cppsocket/actions/workflows/profile.yml/badge.svg)
![cppcheck Build](https://github.com/martelkr/cppsocket/actions/workflows/cppcheck.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/martelkr/cppsocket/badge.svg?branch=main)](https://coveralls.io/github/martelkr/cppsocket?branch=main)
![cpp-linter](https://github.com/martelkr/cppsocket/actions/workflows/linter.yml/badge.svg)

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

### TCP server/client

Create a TCP server object for accepting TCP connections. 

```cpp
// default no SSL and not IP/port bound
TCPServer(); 

// default SSL and not IP/port bound
TCPServer(const std::string& keyFile, const std::string& certFile); 

// No SSL and IP/port bound
explicit TCPServer(const uint16_t port, const std::string& ip = "0.0.0.0", const int backlog = 3); 

/// SSL and IP/port bound
TCPServer(const uint16_t port, const std::string& ip, const std::string& keyFile, const std::string& certFile, const int backlog = 3);
```

Create a TCP client object to connect to a known TCP server.

```cpp
TCPClient(const std::string& ip, const uint16_t port, const bool ssl = false);
explicit TCPClient(const int fd, SSL_CTX* sslctx = nullptr);
```

For a BSD-like approach, the following sequence can be followed:

```cpp
// Server

// create server socket
TCPServer s; // add key file and cert file here for secure connection

// bind to port 54321 on IP 0.0.0.0
s.bindAndListen(54321); 

TCPClient c = s.accept();
```

```cpp
// Client

// Connect to TCP server on IP 127.0.0.1 and port 54321
TCPClient c("127.0.0.1", 54321); // add key file and cert file here for secure connection
```

### UDP server/client

Create a UDP server object for accepting UDP connections. 

```cpp
// default constructor creates unbound unsecure UDP server socket
UDPServer();

// default DTLS constructor create unbound UDP server socket ready for DTLS
// NOTE: UDPServer s("", ""); results in unbound unsecure UDP server socket
UDPServer(const std::string& keyFile, const std::string& certFile);

// creates unsecure UDP server socket bound to specific port and IP address (default all host IP)
explicit UDPServer(const uint16_t port, const std::string& ip = "0.0.0.0");

// creates bound UDP server socket ready for DTLS
// NOTE: UDPServer s("", ""); results in unbound unsecure UDP server socket
UDPServer(const uint16_t port, const std::string& ip, const std::string& keyFile, const std::string& certFile);
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
UDPServer s; // add key file and cert file here for secure connection

// bind to port 54321 on IP 0.0.0.0
s.bind(54321); 

// following not needed for unsecure connection but is needed for DTLS connection
s.accept();
```

```cpp
// Client

// Connect to UDP server on IP 127.0.0.1 and port 54321
UDPClient c("127.0.0.1", 54321); // add key file and cert file here for secure connection
```

## Thread Safety

Do not share TCPServer, TCPClient, UDPClient or UDPServer objects across threads unless you provide your own thread safety on the send/read and accept calls.

## Installation

Use the `cppsocket.hpp` file in your source tree and include it in the file that need to use it.

## Run Unit Tests

Unit tests run with ctest:
```
ctest -C debug
```

## Contribute
All contributions are highly appreciated.
