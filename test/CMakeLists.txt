SET(CMAKE_CXX_FLAGS "-g -O3 -Wall -Werror")

if(NOT MSVC)
    find_package(OpenSSL)
else()
    find_package(OpenSSL REQUIRED)
    include_directories("${OPENSSL_INCLUDE_DIR}")
endif()

include_directories(../inc)

add_executable(testcppsocket TestCppSocket.cpp)

target_include_directories(testcppsocket PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(testcppsocket ${OPENSSL_LIBRARIES})
