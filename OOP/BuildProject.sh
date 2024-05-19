#!/bin/bash

# Set the compiler paths
# 设置编译器路径
C_COMPILER_PATH="/usr/bin/gcc"
CXX_COMPILER_PATH="/usr/bin/g++"

# Set default build paths
# 设置默认构建路径
DEBUG_BUILD_PATH="${DEBUG_BUILD_PATH:-./project-build/debug}"
RELEASE_BUILD_PATH="${RELEASE_BUILD_PATH:-./project-build/release}"

# Create build directories if they do not exist
# 创建构建目录（如果不存在）
[ ! -d "$DEBUG_BUILD_PATH" ] && mkdir -p "$DEBUG_BUILD_PATH"
[ ! -d "$RELEASE_BUILD_PATH" ] && mkdir -p "$RELEASE_BUILD_PATH"

# Clean previous builds
# 清理之前的构建
cmake --build "$DEBUG_BUILD_PATH" --target clean -j 18
cmake --build "$RELEASE_BUILD_PATH" --target clean -j 18

# Build debug version
# 构建调试版本
cmake -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_COMPILER="$C_COMPILER_PATH" \
      -DCMAKE_CXX_COMPILER="$CXX_COMPILER_PATH" \
      -DCMAKE_CXX_STANDARD=20 \
      -DCMAKE_CXX_STANDARD_REQUIRED=ON \
      -DCMAKE_CXX_EXTENSIONS=OFF \
      -DCMAKE_CXX_FLAGS="-std=c++20 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" \
      -S . -B "$DEBUG_BUILD_PATH" -G "Unix Makefiles"

# Check if Makefile exists and use it to build, otherwise use Ninja
# 检查 Makefile 是否存在并使用其构建，否则使用 Ninja
if [ -f "$DEBUG_BUILD_PATH/Makefile" ]; then
    cd "$DEBUG_BUILD_PATH"
    make --help
    make --makefile="Makefile"
    cd -
else
    cmake -DCMAKE_BUILD_TYPE=Debug -S . -B "$DEBUG_BUILD_PATH" -G "Ninja"
fi

# Build release version
# 构建发布版本
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER="$C_COMPILER_PATH" \
      -DCMAKE_CXX_COMPILER="$CXX_COMPILER_PATH" \
      -DCMAKE_CXX_STANDARD=20 \
      -DCMAKE_CXX_STANDARD_REQUIRED=ON \
      -DCMAKE_CXX_EXTENSIONS=OFF \
      -DCMAKE_CXX_FLAGS="-std=c++20 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" \
      -S . -B "$RELEASE_BUILD_PATH" -G "Unix Makefiles"

# Check if Makefile exists and use it to build, otherwise use Ninja
# 检查 Makefile 是否存在并使用其构建，否则使用 Ninja
if [ -f "$RELEASE_BUILD_PATH/Makefile" ]; then
    cd "$RELEASE_BUILD_PATH"
    make --help
    make --makefile="Makefile"
    cd -
else
    cmake -DCMAKE_BUILD_TYPE=Release -S . -B "$RELEASE_BUILD_PATH" -G "Ninja"
fi
