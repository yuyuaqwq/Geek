cmake_minimum_required(VERSION 3.5...3.21 FATAL_ERROR)
project(geek_example)

set(CMAKE_CXX_STANDARD 17)

include_directories(${HEAD_PATH})
include_directories(${ASMJIT_HEAD_PATH})

set(EXECUTABLE_OUTPUT_PATH ${EXEC_PATH})

add_executable(geek_example main.cpp)

set_property(
    TARGET geek_example
    APPEND_STRING 
    PROPERTY 
        LINK_FLAGS_DEBUG " /INCREMENTAL:NO"
)

link_directories(${LIB_PATH})
target_link_libraries(geek_example PRIVATE geek::geek)
