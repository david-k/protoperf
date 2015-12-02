cmake_minimum_required(VERSION 2.8)

project(protoperf)

include_directories(${CMAKE_SOURCE_DIR}/src)
file(GLOB_RECURSE SOURCE_FILES "src/*.cpp")

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra -Wpedantic -pthread")

set(LIBS ${LIBS} "udt")

add_executable(protoperf ${SOURCE_FILES})
target_link_libraries(protoperf ${LIBS})

