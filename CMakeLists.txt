cmake_minimum_required (VERSION 3.22.1)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}/bin)

FILE(READ "VERSION" project_version)
STRING(STRIP "${project_version}" project_version)

SET(LICENSE "MTI")

project(cppsocket VERSION ${project_version} LANGUAGES CXX)

if (NOT MSVC)
    add_definitions(-DLINUX)
else()
    add_definitions(-DWINDOWS)
endif()

include_directories(inc)

add_subdirectory(test)