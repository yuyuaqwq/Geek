cmake_minimum_required(VERSION 3.5...3.21 FATAL_ERROR)
project(miniwin)

set(CMAKE_CXX_STANDARD 17)

include_directories(${HEAD_PATH})
include_directories(${SRC_HEAD_PATH})

aux_source_directory(./ SRC)
aux_source_directory(./hook SRC)
aux_source_directory(./pe SRC)
aux_source_directory(./process SRC)
aux_source_directory(./utils SRC)
aux_source_directory(./wow64ext SRC)

add_library(${GEEK_LIB} STATIC ${SRC})