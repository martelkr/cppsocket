if(CMAKE_COMPILER_IS_GNUCXX)
    SET(CMAKE_CXX_FLAGS "-O3 -Wall -Werror")
    find_package(OpenSSL REQUIRED)
    find_package(GTest REQUIRED)
else()
    SET(CMAKE_CXX_FLAGS "-O3 -Wall")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebug")
    set(OPENSSL_INCLUDE_DIR $ENV{OPENSSL_INCLUDE_DIR})
    set(OPENSSL_LIBRARIES $ENV{OPENSSL_LIBRARIES})
    find_package(OpenSSL REQUIRED)
    link_directories("D:/gtest/lib")
    include_directories("D:/gtest/include")
    set(GTEST_LIBRARY $ENV{GTEST_LIBRARY})
    set(GTEST_INCLUDE_DIR $ENV{GTEST_INCLUDE_DIR})
    set(GTEST_MAIN_LIBRARY $ENV{GTEST_LIBRARY})
    find_package(GTest REQUIRED)
endif()

include_directories(../inc)

add_executable(testcppsocket TestCppSocket.cpp)

target_include_directories(testcppsocket PRIVATE ${GTEST_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

target_link_libraries(testcppsocket ${GTEST_LIBRARIES} ${OPENSSL_LIBRARIES})

add_test(
    NAME gtestcppsocket
    COMMAND testcppsocket
)
