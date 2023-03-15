if(CMAKE_COMPILER_IS_GNUCXX)
    SET(CMAKE_CXX_FLAGS "-O3 -Wall -Werror")
    find_package(OpenSSL)
    find_package(GTest REQUIRED)
else()
    SET(CMAKE_CXX_FLAGS "-O3 -Wall")
    find_package(OpenSSL REQUIRED)
    find_package(GTest REQUIRED)
endif()

include_directories(../inc)

add_executable(testcppsocket TestCppSocket.cpp)

target_include_directories(testcppsocket PRIVATE ${GTEST_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

target_link_libraries(testcppsocket ${GTEST_LIBRARIES} ${OPENSSL_LIBRARIES})

add_test(
    NAME gtestcppsocket
    COMMAND testcppsocket
    WORKING_DIRECTORY ${pwd}/${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
)
