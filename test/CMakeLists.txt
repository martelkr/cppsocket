if(CMAKE_COMPILER_IS_GNUCXX)
    #SET(CMAKE_CXX_FLAGS "-O3 -Wall -Werror")
    SET(CMAKE_CXX_FLAGS "-O3 -Wall")
    find_package(OpenSSL)
else()
    SET(CMAKE_CXX_FLAGS "-O3 -Wall")
    find_package(OpenSSL REQUIRED)
    include_directories("${OPENSSL_INCLUDE_DIR}")
endif()

include_directories(../inc)

add_executable(testcppsocket TestCppSocket.cpp)

target_include_directories(testcppsocket PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(testcppsocket ${OPENSSL_LIBRARIES})
