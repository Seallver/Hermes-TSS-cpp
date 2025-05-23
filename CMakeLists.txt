cmake_minimum_required(VERSION 3.10)

project("MultiPartySig" VERSION 1.0.1)

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=/safeheron")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=/safeheron")

option(ENABLE_SNAP_SCOPE "Enable Snap Scope" OFF)
if (${ENABLE_SNAP_SCOPE})
    message(STATUS "Notice: ******************* Enable Snap Scope ******************* ")
endif()

option(TEST_STARK_CURVE "Use Stark Curve" OFF)
if (TEST_STARK_CURVE)
    add_definitions(-DTEST_STARK_CURVE)
endif()

include_directories(src)

cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0079 NEW)
add_library(${CMAKE_PROJECT_NAME} SHARED "")
add_subdirectory(src)

option(ENABLE_TESTS "Enable tests" ON)
if (${ENABLE_TESTS})
    enable_testing()
    add_subdirectory(test)
endif()

include("cmake/setup_installation.cmake")