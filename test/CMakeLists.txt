if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "-O3 -Wall -Werror")
    find_package(OpenSSL REQUIRED)
    find_package(GTest REQUIRED)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    set(CMAKE_CXX_FLAGS "-Wall /O2")
    if(DEFINED ENV{CI})
        # github action CI needs
        set(GTEST_LIBRARY "D:/gtest/lib/gtest.lib")
        set(GTEST_INCLUDE_DIR "D:/gtest/include")
        set(GTEST_MAIN_LIBRARY "D:/gtest/lib/gtest_main.lib")
        set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL/include")
        set(OPENSSL_LIBRARIES "C:/Program Files/OpenSSL/lib")
    else()
        # this may not be needed or need changing but I needed it
        # this requires setting Windows environment settings for this user with these correct values
        set(GTEST_LIBRARY $ENV{GTEST_LIBRARY})
        set(GTEST_INCLUDE_DIR $ENV{GTEST_INCLUDE_DIR})
        set(GTEST_MAIN_LIBRARY $ENV{GTEST_LIBRARY})
        set(OPENSSL_INCLUDE_DIR $ENV{OPENSSL_INCLUDE_DIR})
        set(OPENSSL_LIBRARIES $ENV{OPENSSL_LIBRARIES})
    endif()
    find_package(OpenSSL REQUIRED)
    find_package(GTest REQUIRED)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "-O3 -Wall -Werror")
    find_package(OpenSSL REQUIRED)
    find_package(GTest REQUIRED)
else()
    message(FATAL_ERROR "Failed to find correct compiler")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "PROFILE")
    set(CMAKE_C_FLAGS_PROFILE --coverage)
    set(CMAKE_CXX_FLAGS_PROFILE --coverage)
    add_link_options("--coverage")
endif()

include_directories(../inc)

add_executable(testcppsocket TestCppSocket.cpp)

target_include_directories(testcppsocket PRIVATE ${GTEST_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

target_link_libraries(testcppsocket ${GTEST_LIBRARIES} ${OPENSSL_LIBRARIES})

add_test(
    NAME gtestcppsocket
    COMMAND testcppsocket
)
