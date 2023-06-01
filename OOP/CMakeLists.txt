cmake_minimum_required(VERSION 3.26)
project(Algorithm_OaldresPuzzleCryptic)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_COMPILER "E:\\[About Programming]\\WindowsLibsGCC\\mingw64\\bin\\gcc")
set(CMAKE_CXX_COMPILER "E:\\[About Programming]\\WindowsLibsGCC\\mingw64\\bin\\g++")

message(STATUS "CMAKE_CXX_FLAGS = ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_DEBUG = ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_RELEASE = ${CMAKE_CXX_FLAGS_DEBUG}")

# Detect the compiler
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "11")
		message(FATAL_ERROR "GNU CXX compiler version is too small !")
	endif ()
	set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" CACHE STRING "Flags used by the C++ compiler during debug builds." FORCE)
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" CACHE STRING "Flags used by the C++ compiler during release builds." FORCE)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	set(CMAKE_CXX_FLAGS_DEBUG "/std:c++20 /Zi /Od /EHsc /MTd /Zc:__cplusplus /utf-8 /bigobj /W4 /D_ITERATOR_DEBUG_LEVEL=2")
	set(CMAKE_CXX_FLAGS_RELEASE "/std:c++20 /O2 /EHsc /MT /Zc:__cplusplus /utf-8 /bigobj /W4 /D_ITERATOR_DEBUG_LEVEL=0")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" CACHE STRING "Flags used by the C++ compiler during debug builds." FORCE)
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -fsigned-char -finput-charset=UTF-8 -fexec-charset=UTF-8" CACHE STRING "Flags used by the C++ compiler during release builds." FORCE)
else()
	message(WARNING "Unknown compiler: ${CMAKE_CXX_COMPILER_ID}")
endif()

message(STATUS "CMAKE_CXX_FLAGS = ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_DEBUG = ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_RELEASE = ${CMAKE_CXX_FLAGS_DEBUG}")

# Add main.cpp file of project root directory as source file
set(SOURCE_FILES ${PROJECT_SOURCE_DIR}/main.cpp
        	${PROJECT_SOURCE_DIR}/BitRotation.hpp
	${PROJECT_SOURCE_DIR}/RandomNumberDistribution.hpp
	${PROJECT_SOURCE_DIR}/CommonSecurity.hpp
	${PROJECT_SOURCE_DIR}/SupportBaseFunctions.hpp
	${PROJECT_SOURCE_DIR}/DataFormating.hpp
	${PROJECT_SOURCE_DIR}/SecureSeedGenerator.hpp
	${PROJECT_SOURCE_DIR}/StreamCipher/LittleOaldresPuzzle_Cryptic.h
	${PROJECT_SOURCE_DIR}/StreamCipher/LittleOaldresPuzzle_Cryptic.cpp
	${PROJECT_SOURCE_DIR}/StreamCipher/XorConstantRotation.cpp
	${PROJECT_SOURCE_DIR}/StreamCipher/XorConstantRotation.h
	${PROJECT_SOURCE_DIR}/Test/Test_LittleOaldresPuzzle_Cryptic.cpp
	${PROJECT_SOURCE_DIR}/Test/Test_LittleOaldresPuzzle_Cryptic.h
	${PROJECT_SOURCE_DIR}/C_API/Wrapper_LittleOaldresPuzzle_Cryptic.h
	${PROJECT_SOURCE_DIR}/C_API/Wrapper_LittleOaldresPuzzle_Cryptic.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Includes/PRNGs.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Modules_OaldresPuzzle_Cryptic.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Module_MixTransformationUtil.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Module_MixTransformationUtil.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Module_SubkeyMatrixOperation.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Module_SubkeyMatrixOperation.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/CustomSecureHash.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Module_SecureSubkeyGeneratation.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Module_SecureSubkeyGeneratation.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Module_SecureRoundSubkeyGeneratation.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Module_SecureRoundSubkeyGeneratation.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/OaldresPuzzle_Cryptic.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/OaldresPuzzle_Cryptic.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Includes/SecureHashProvider/SHA2_512.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Includes/SecureHashProvider/SHA2_512.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Includes/SecureHashProvider/HMAC_Worker.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Includes/SecureHashProvider/HMAC_Worker.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Includes/KeyDerivationFunction/PBKDF2.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Includes/KeyDerivationFunction/PBKDF2.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Includes/KeyDerivationFunction/Scrypt.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/Includes/KeyDerivationFunction/Scrypt.hpp
	${PROJECT_SOURCE_DIR}/BlockCipher/OPC_MainAlgorithm_Worker.cpp
	${PROJECT_SOURCE_DIR}/BlockCipher/OPC_MainAlgorithm_Worker.hpp
	${PROJECT_SOURCE_DIR}/Test/Test_OaldresPuzzle_Cryptic.cpp
	${PROJECT_SOURCE_DIR}/Test/Test_OaldresPuzzle_Cryptic.h
	${PROJECT_SOURCE_DIR}/C_API/Wrapper_OaldresPuzzle_Cryptic.cpp
	${PROJECT_SOURCE_DIR}/C_API/Wrapper_OaldresPuzzle_Cryptic.h
)

# Add library target with source files listed in SOURCE_FILES variable
add_library(Algorithm_OaldresPuzzleCryptic STATIC ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME}
        PRIVATE ${PROJECT_SOURCE_DIR}/BlockCipher/ExtraIncludes
)