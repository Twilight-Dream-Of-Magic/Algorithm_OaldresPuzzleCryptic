#!/bin/bash
C_COMPILER_PATH="/usr/bin/gcc"
CXX_COMPILER_PATH="/usr/bin/g++"

[ ! -d "./project-build/debug" ] && mkdir "./project-build/debug" -p
[ ! -d "./project-build/release" ] && mkdir "./project-build/release"

cmake --build cmake-build-debug-gcc --target clean -j 18
cmake --build cmake-build-release-gcc --target clean -j 18

cd "./project-build/debug"
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=$C_COMPILER_PATH -DCMAKE_CXX_COMPILER=$CXX_COMPILER_PATH -D CMAKE_CXX_STANDARD=20 -D CMAKE_CXX_STANDARD_REQUIRED=ON -D CMAKE_CXX_EXTENSIONS=OFF -D CMAKE_CXX_FLAGS="-std=c++20 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" -S .. -B . -G "Unix Makefiles"

if [ -f "Makefile" ]; then
	make --help
	make --makefile="/Makefile"
else
	cmake -DCMAKE_BUILD_TYPE=Debug -S .. -B . -G "Ninja"
fi

cd "../release"
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=$C_COMPILER_PATH -DCMAKE_CXX_COMPILER=$CXX_COMPILER_PATH -D CMAKE_CXX_STANDARD=20 -D CMAKE_CXX_STANDARD_REQUIRED=ON -D CMAKE_CXX_EXTENSIONS=OFF -D CMAKE_CXX_FLAGS="-std=c++20 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" -S .. -B . -G "Unix Makefiles"

if [ -f "Makefile" ]; then
	make --help
	make --makefile="/Makefile"
else
	cmake -DCMAKE_BUILD_TYPE=Release -S .. -B . -G "Ninja"
fi

cd ..
