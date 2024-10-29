cmake_minimum_required(VERSION 3.5...3.21 FATAL_ERROR)
project(example)

set(CMAKE_CXX_STANDARD 17)

include_directories(${HEAD_PATH})

set(EXECUTABLE_OUTPUT_PATH ${EXEC_PATH})
add_executable(example main.cpp)

link_directories(${LIB_PATH})
target_link_libraries(example ${GEEK_LIB})
