# TCP C++ client/server with SSL/TLS support (header file only)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](http://opensource.org/licenses/MIT)
![Cmake Build](https://github.com/martelkr/cppsocket/actions/workflows/cmake.yml/badge.svg)

## About
This is a header file only implementation of a C++ TCP client/server with or without SSL/TLS for Linux only.
The implementation uses OpenSSL and BSD API to implement the underlying socket interfaces.

Compilation has been tested with:
- GCC 11.3.0 (GNU/Linux Ubuntu 22.04.1 LTS)

## Usage
Create a TCP server object for accepting TCP connections. 

```cpp
// default no SSL and not IP/port bound
TCPServer(void); 

// default SSL and not IP/port bound
TCPServer(const std::string& keyFile, const std::string& certFile); 

// No SSL and IP/port bound
explicit TCPServer(const uint16_t port, const std::string& ip = "", const int backlog = 3); 

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
TCPServer s;

// bind to port 54321 on IP 0.0.0.0
s.bindAndListen(54321); 

TCPClient c = s.accept();
```

```cpp
// Client

// Connect to TCP server on IP 127.0.0.1 and port 54321
TCPClient c("127.0.0.1", 54321);
```

## Thread Safety

Do not share TCPClient objects across threads unless you provide your own thread safety on the send/read calls.

## Installation

Use the `cppsocket.hpp` file in your source tree and include it in the file that need to use it.

## Run Unit Tests

There are two basic unit tests included in `test/TestCppSocket.cpp` to test basic data passing for secure and unsecure TCP sockets.

## CppCheck Compliancy

The C++ code of the Socket C++ API classes is Cppcheck compliant.

## Contribute
All contributions are highly appreciated.
