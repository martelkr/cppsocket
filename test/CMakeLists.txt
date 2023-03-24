if(CMAKE_COMPILER_IS_GNUCXX)
    SET(CMAKE_CXX_FLAGS "-O3 -Wall -Werror")
    find_package(OpenSSL REQUIRED)
    find_package(GTest REQUIRED)
else()
    SET(CMAKE_CXX_FLAGS "-O3 -Wall")
    if(DEFINED ENV{CI})
        # github action CI needs
        set(OPENSSL_USE_STATIC_LIBS TRUE)
        set(GTEST_LIBRARY "/usr/lib/libgtest.a")
        set(GTEST_INCLUDE_DIR "/usr/include")
        set(GTEST_MAIN_LIBRARY "/usr/lib/libgtest_main.a")
    else()
        # this may not be needed or need changing but I needed it
        # this requires setting Windows environment settings for this user with these correct values
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebug")
        set(GTEST_LIBRARY $ENV{GTEST_LIBRARY})
        set(GTEST_INCLUDE_DIR $ENV{GTEST_INCLUDE_DIR})
        set(GTEST_MAIN_LIBRARY $ENV{GTEST_LIBRARY})
        set(OPENSSL_INCLUDE_DIR $ENV{OPENSSL_INCLUDE_DIR})
        set(OPENSSL_LIBRARIES $ENV{OPENSSL_LIBRARIES})
    endif()
    find_package(OpenSSL REQUIRED)
    find_package(GTest REQUIRED)
endif()

include_directories(../inc ${GTEST_INCLUDE_DIR})

add_executable(testcppsocket TestCppSocket.cpp)

target_include_directories(testcppsocket PRIVATE ${GTEST_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

target_link_libraries(testcppsocket ${GTEST_LIBRARIES} ${OPENSSL_LIBRARIES})

add_test(
    NAME gtestcppsocket
    COMMAND testcppsocket
)
