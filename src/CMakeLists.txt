cmake_minimum_required(VERSION 3.5...3.21 FATAL_ERROR)
project(geek)

set(CMAKE_CXX_STANDARD 17)

include_directories(${HEAD_PATH})
include_directories(${SRC_HEAD_PATH})
include_directories(${ASMJIT_HEAD_PATH})
include_directories(${ZYDIS_HEAD_PATH})

aux_source_directory(./ SRC)
aux_source_directory(./hook SRC)
aux_source_directory(./pe SRC)
aux_source_directory(./pe/data_directory SRC)
aux_source_directory(./process SRC)
aux_source_directory(./utils SRC)
aux_source_directory(./wow64ext SRC)
aux_source_directory(./asm SRC)
aux_source_directory(./asm/assembler SRC)

add_library(${GEEK_LIB} STATIC ${SRC})

target_link_libraries(${GEEK_LIB} PRIVATE asmjit::asmjit Zydis::Zydis)


include(GNUInstallDirs)

# 安装库
install(TARGETS ${GEEK_LIB}
        EXPORT geekTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})


# 安装导出文件
install(EXPORT geekTargets
        FILE geekTargets.cmake
        NAMESPACE geek::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/geek)

# 安装配置文件
configure_file(geekConfig.cmake.in
               "${CMAKE_CURRENT_BINARY_DIR}/geekConfig.cmake" @ONLY)
install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/geekConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/geekConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/geek)

# 版本文件
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/geekConfigVersion.cmake"
"set(geek_VERSION 1.0.0)\n"
"set(geek_VERSION_MAJOR 1)\n"
"set(geek_VERSION_MINOR 0)\n"
"set(geek_VERSION_PATCH 0)\n")