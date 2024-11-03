cmake_minimum_required(VERSION 3.5...3.21 FATAL_ERROR)
project(geek)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set(LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(EXEC_PATH ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(HEAD_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
set(GEEK_LIB geek_d)
else()
set(GEEK_LIB geek)
endif()

set(SRC_HEAD_PATH ${PROJECT_SOURCE_DIR})
set(THIRD_PARTY_DIR ${PROJECT_SOURCE_DIR}/third-party)

add_subdirectory(geek)
add_subdirectory(example)

# 假设你的静态库在 geek/lib 中构建
# 设置安装路径
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