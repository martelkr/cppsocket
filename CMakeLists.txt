cmake_minimum_required (VERSION 3.22.1)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

FILE(READ "VERSION" project_version)
STRING(STRIP "${project_version}" project_version)

SET(LICENSE "MIT")

project(cppsocket VERSION ${project_version} LANGUAGES CXX)

if (CMAKE_GNU_COMPILER_ID)
    add_definitions(-DLINUX)
else()
    add_definitions(-DWINDOWS)
endif()

include_directories(inc)

enable_testing()
add_subdirectory(test)