cmake_minimum_required (VERSION 3.16)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

FILE(READ "VERSION" project_version)
STRING(STRIP "${project_version}" project_version)

SET(LICENSE "MIT")

project(cppsocket VERSION ${project_version} LANGUAGES CXX)

include_directories(inc)

enable_testing()
add_subdirectory(test)