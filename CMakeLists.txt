cmake_minimum_required(VERSION 3.5...3.21 FATAL_ERROR)
project(geek)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set(LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(EXEC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(HEAD_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(DEFINED GEEK_LIB_ALIAS)
    message(GEEK_LIB_ALIAS defined: ${GEEK_LIB_ALIAS})
    set(GEEK_LIB ${GEEK_LIB_ALIAS})
else()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(GEEK_LIB geek_d)
    else()
        set(GEEK_LIB geek)
    endif()
endif()

set(SRC_HEAD_PATH ${PROJECT_SOURCE_DIR})
set(THIRD_PARTY_DIR ${PROJECT_SOURCE_DIR}/third-party)

set(ASMJIT_HEAD_PATH ${THIRD_PARTY_DIR}/asmjit/src)

set(ASMJIT_STATIC TRUE)
add_subdirectory(${THIRD_PARTY_DIR}/asmjit)

add_subdirectory(geek)
add_subdirectory(example)