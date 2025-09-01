cmake_minimum_required (VERSION 3.16)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/inc/cppsocket.hpp" _CPPSOCKET_H_CONTENTS)
string(REGEX REPLACE ".*#define CPPSOCKET_VERSION_MAJOR ([0-9]+).*" "\\1" DETECTED_CPPSOCKET_VERSION_MAJOR "${_CPPSOCKET_H_CONTENTS}")
string(REGEX REPLACE ".*#define CPPSOCKET_VERSION_MINOR ([0-9]+).*" "\\1" DETECTED_CPPSOCKET_VERSION_MINOR "${_CPPSOCKET_H_CONTENTS}")
string(REGEX REPLACE ".*#define CPPSOCKET_VERSION_PATCH ([0-9]+).*" "\\1" DETECTED_CPPSOCKET_VERSION_PATCH "${_CPPSOCKET_H_CONTENTS}")
set(DETECTED_CPPSOCKET_VERSION "${DETECTED_CPPSOCKET_VERSION_MAJOR}.${DETECTED_CPPSOCKET_VERSION_MINOR}.${DETECTED_CPPSOCKET_VERSION_PATCH}")

message(STATUS "Detected CPPSOCKET Version - ${DETECTED_CPPSOCKET_VERSION}")

SET(LICENSE "MIT")

project(cppsocket VERSION ${DETECTED_CPPSOCKET_VERSION} LANGUAGES CXX)

include_directories(inc)

add_library(cppsocket INTERFACE)
target_include_directories(cppsocket INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                                                $<INSTALL_INTERFACE:include>)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS cppsocket EXPORT ${PROJECT_NAME}-targets)

install(FILES inc/cppsocket.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(CPPSOCKET_CMAKECONFIG_INSTALL_DIR "share/cmake/${PROJECT_NAME}" CACHE STRING "install path for cppsocketConfig.cmake")

message(STATUS "CPPSOCKET CMAKE Install directory =${CPPSOCKET_CMAKE_CONFIG_INSTALL_DIR}")

export(EXPORT ${PROJECT_NAME}-targets
     FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Targets.cmake")
configure_package_config_file(${PROJECT_NAME}Config.cmake.in
                              "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
                              INSTALL_DESTINATION ${CPPSOCKET_CMAKECONFIG_INSTALL_DIR})

write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
                                 VERSION ${DETECTED_CPPSOCKET_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cppsocket.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/cppsocket.pc @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cppsocket.pc
              DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

install(EXPORT ${PROJECT_NAME}-targets
        FILE ${PROJECT_NAME}Targets.cmake
        DESTINATION ${CPPSOCKET_CMAKECONFIG_INSTALL_DIR})

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
              DESTINATION ${CPPSOCKET_CMAKECONFIG_INSTALL_DIR})

option(BUILD_TESTS "Whether or not to build the tests" ON)

if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
