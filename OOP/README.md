# Twilight-Dream-Of-Magic/Algorithm_OaldresPuzzleCryptic

# English

This is a symmetric encryption and decryption library based on C++. It provides two types of algorithms, namely stream/cipher algorithms (Type 1) and block/group cipher algorithms (Type 2). The project evolved from a previous C++ template project and has now adopted an object-oriented programming paradigm, with non-essential elements trimmed away. In addition, it also accommodates a C_API for ease of use with other languages.

## Features and Technical Details

- ** Type 1**: Stream/cipher algorithms XCR CSPRNG, offering exceptionally high speed and catering to modern needs. The algorithm has passed randomness tests like [NIST](%5BType%201%5D%20NIST/NIST%20Test%20Result%20Data%20And%20Experiment.md), China GM/T 0005-2021, and PractRand.


It utilizes a structure similar to Addition-Rotation-Bitwise Exclusive-Or, and blends various mathematical irrational numbers, generating constants with a wide range of variations for each round. This makes for an extremely nonlinear boolean function, $f(x) = (e^x - \cos(\pi x)) \times (\phi x^2 - \phi x - 1) \times (\sqrt[2]{2x} - \lfloor \sqrt[2]{2x} \rfloor) \times (\sqrt[2]{3x} - \lfloor \sqrt[2]{3x} \rfloor) \times \ln(1 + x) \times (x\delta - \lfloor x\delta \rfloor) \times (x\rho - \lfloor x\rho \rfloor)$. LittleOaldresPuzzle_Cryptic(Type 1 lightweight cryptography block cipher) relies on the Cryptographically Secure Pseudorandom Number Generator (CSPRNG) XCR - XorConstantRotation.

- ** Type 2**: Block/group cipher algorithms, slower in speed but incredibly secure, capable of withstanding future demands. They are impervious to any brute force attack methods, whether it's quantum computing, exhaustive search, or differential cryptanalysis.

The encryption/decryption part of block ciphers adopts the Lai–Massey scheme structure, similar to the Byte Substitution Box of Rijndael algorithm (AES), but with a different polynomial ($x^8 + x^5 + x^4 + x^3 + x^2 + x + 1$) as modulus number. The key generation part is a massive module involving linear algebra's Kronecker product, multiplication, and addition; akin to Ajtai's one-way function. It uses a custom sponge structure hash function (internally uses CSPRNG ISAAC64+ algorithm at initialization, seed is 1946379852749613 --- 0110111010100011100011011111101110001001101100101101). The project features a self-designed Non-Linear Feedback Shift Register (NLFSR), a Linear Feedback Shift Register (LFSR) built using a polynomial of at least 128 bits ($x^{128} + x^{41} + x^{39} + x + 1$), and a secure pseudorandom number generator constructed using a simulated chaotic system of double pendulum oscillations (SDP). It also modifies the Chinese ZUC stream cipher algorithm (initialization function uses LFSR, NLFSR, SDP, then Byte Substitution Box becomes dynamically generated, will use LineSegmentTree); and a self-designed bit reorganization function. Overall, the block cipher's key generation algorithm can be divided into two abstract functions, one for generating subkeys, and the other for generating round subkeys. The former is a massive confusion layer, and the latter is a massive diffusion layer.

More technical details can be found in the `TechnicalDetailPapers` folder.

## How to Modify `main.cpp` Before Compilation

Before compiling the project, you may need to adjust the `main.cpp` file based on the specific tests or features you want to enable. Here's how you can do it:

### Step 1: Open `main.cpp`
Open the `main.cpp` file in your preferred text editor or IDE.

### Step 2: Choose Your Compilation Mode

The project supports multiple compilation modes, controlled by specific macro definitions. Depending on what you want to test or use, uncomment one of the following lines at the top of `main.cpp`:

1. **Library Test Mode**:
   - This mode compiles the program with C API wrappers, making it suitable for testing or exposing functions to other projects.
   - Uncomment the following line:
     ```cpp
     #define IS_LIBRARY_TEST
     ```

2. **Binary Test Mode for `LittleOaldresPuzzle_Cryptic`**:
   - Use this mode if you want to run unit tests specific to the `LittleOaldresPuzzle_Cryptic` implementation.
   - Uncomment the following line:
     ```cpp
     #define IS_BINARY_TEST_LITTLEOPC
     ```

3. **Binary Test Mode for `OaldresPuzzle_Cryptic`**:
   - This mode runs unit tests for the `OaldresPuzzle_Cryptic` implementation, focusing on cryptographic functions with random data.
   - Uncomment the following line:
     ```cpp
     #define IS_BINARY_TEST_OPC
     ```

### Step 3: Save Your Changes

After uncommenting the desired line, save the `main.cpp` file.

### Step 4: Compile the Project

Now you can proceed to compile the project. The compilation will be based on the mode you selected in `main.cpp`.

### Example:

If you want to run the binary tests for `LittleOaldresPuzzle_Cryptic`, your `main.cpp` should look something like this at the top:

```cpp
#include "SupportBaseFunctions.hpp" //C++ STL Wrapper and Custom Utils

#define IS_BINARY_TEST_LITTLEOPC

#if defined(IS_LIBRARY_TEST)
// ... other code
```

## Compilation Environment

This project supports three compilers: Clang, G++, and MSVC. It uses CMake as a build tool and requires the C++ standard version to be at least C++20. These compilers can compile the project into a C++20 static library.

Here are the general steps to build the project with CMake (a CMakeLists.txt script file must be present):

1. Create and enter the build directory (for example: mkdir build && cd build).
Run CMake to generate the build system (for example: cmake ..).
2. Compile according to the generated build system (for example: for Unix systems, you can directly use the make command).
3. Please note that this project uses the C++20 standard, so the compiler must support C++20. If the compiler version you are using does not support C++20, then the compilation will fail.

Although all implementations of this project are in C++ .hpp and .cpp files, the C_API remains unchanged. If you are a C language user, you only need to take the compiled library and use the pure C language .h header files.

## Notes
After each encryption or decryption operation using this C API, the internal state will change, much like executing the RunUnit function used in main.cpp. Therefore, we need to destroy the current instance and rebuild, then replace that instance. The C++ class implementation of the Type 1 algorithm automatically performs this operation, no manual action is required from the user. The C API function's C++ implementation of the Type 2 algorithm has also automatically performed this operation, no manual action is required from the user.

# Chinese

这是一个基于C++的对称加密和解密算法库。
它提供了两种类型的算法，即流/序列密码算法（Type 1）和块/分组密码算法（Type 2）。
这个项目是从以前的C++模板项目改造而来，现在已经采用了面向对象的编程范式，并且去掉了和算法设计不相关的东西。同时，也适配了C_API，方便其他语言调用。

## 特性和技术细节

- **Type 1**：流/序列的密码算法 XCR CSPRNG，具有极高速度，适应现代需求，通过了[NIST](%5BType%201%5D%20NIST/NIST%20Test%20Result%20Data%20And%20Experiment.md)，GM/T 0005-2021，PractRand的随机性测试。

采用了类似于Addition-Rotation-Bitwise Exclusive-Or的结构，并混合各种数学无理数，生成的大范围幅度变化的常数，每一轮获取不同的常数。使得构造了一个极高非线性的布尔函数。
$f(x) = (e^x - \cos(\pi x)) \times (\phi x^2 - \phi x - 1) \times (\sqrt[2]{2x} - \lfloor \sqrt[2]{2x} \rfloor) \times (\sqrt[2]{3x} - \lfloor \sqrt[2]{3x} \rfloor) \times \ln(1 + x) \times (x\delta - \lfloor x\delta \rfloor) \times (x\rho - \lfloor x\rho \rfloor)$
制作了XCR - XorConstantRotation 密码学安全伪随机数生成器(CSPRNG)，LittleOaldresPuzzle_Cryptic(Type 1 轻量级密码学块密码器)算法依赖了它。

- **Type 2**：块/分组密码算法，速度较慢，但是安全性极高，适应未来需求，无论使用何种暴力破解方法，如量子计算机，穷举搜索或差分，都无法破解。

分组密码的加密解密算法部分采用Lai–Massey scheme架构，并类似于Rijndael算法(AES)同样原理的字节替换盒，但我选择了不同多项式($x^8 + x^5 + x^4 + x^3 + x^2 + x + 1$)作为模数。密钥生成算法部分是一个非常巨大的模块，涉及到了线性代数的Kronecker product，乘法和加法；类似于Ajtai's 的单向函数，使用了自主设计的海绵结构的哈希函数(初始化时内部使用CSPRNG ISAAC64+算法，种子是1946379852749613 --- 0110111010100011100011011111101110001001101100101101)。自主设计的非线性反馈移位寄存器(NLFSR)；使用了一个至少为128比特的多项式($x^{128} + x^{41} + x^{39} + x + 1$)构建的线性反馈移位寄存器(LFSR)；使用了双段摆锤的现象模拟的混沌系统(SDP)，构造的安全伪随机数生成器；修改了中国的ZUC流密码算法(初始化函数使用LFSR、我的NLFSR、SDP然后字节替换盒变成了动态生成，会使用LineSegmentTree)；自主设计的比特重组函数；模拟伽罗瓦(2^64)有限域非线性乘法的Bitwise-XOR扩散层。总体而言，分组密码的密钥生成算法可以分为两个抽象的函数，一个是生成子密钥，一个是生成子轮密钥，前一个函数是巨大的混淆层，后一个函数是巨大的扩散层。

更多技术细节见`TechnicalDetailPapers`文件夹的内容。

## 编译环境

这个项目支持三种编译器：Clang, G++, MSVC。它使用CMake作为构建工具，要求C++标准版本不低于C++20。使用这些编译器可以将项目编译为C++20的静态库。

以下是使用CMake构建项目的通用步骤(必须存在CMakeLists.txt脚本文件)：

1. 创建并进入构建目录（例如：`mkdir build && cd build`）。
2. 运行CMake生成构建系统（例如：`cmake ..`）。
3. 根据生成的构建系统进行编译（例如：对于Unix系统，可以直接使用`make`命令）。

注意，由于这个项目使用的是C++20标准，所以编译器必须支持C++20。如果使用的编译器版本不支持C++20，那么编译将会失败。

虽然这个项目的所有实现都是C++的hpp和cpp文件，但是C API不会改变。如果你是C语言的用户，只需要把编译好的库拿过来，并使用纯C语言的h头文件就可以了。

## 注意事项

在使用这个C API每次进行加密或解密操作之后，因为内部状态会发生改变，就像执行main.cpp使用的`RunUnit`函数一样，所以我们需要销毁当前的实例并重新构建，然后替换掉那个实例。
Type 1算法我们的C++ 类的实现自动执行了这个操作，无需用户手动进行
Type 2算法我们的C API函数的C++ 实现已经自动执行了这个操作，无需用户手动进行。

# English and Chinese

PractRand Test Result (Type 1 algorithm):
```
 # ./my-prng-xcr_test.exe | ./RNG_test.exe stdin64 -tlmin 1TB -tlmax 16TB -tf 2 -te 1 -multithreaded
RNG_test using PractRand version 0.95
RNG = RNG_stdin64, seed = unknown
test set = expanded, folding = extra

rng=RNG_stdin64, seed=unknown
length= 1 terabyte (2^40 bytes), time= 15000 seconds
  no anomalies in 2456 test result(s)

rng=RNG_stdin64, seed=unknown
length= 2 terabytes (2^41 bytes), time= 28208 seconds
  no anomalies in 2528 test result(s)

rng=RNG_stdin64, seed=unknown
length= 4 terabytes (2^42 bytes), time= 44274 seconds
  no anomalies in 2600 test result(s)

rng=RNG_stdin64, seed=unknown
length= 8 terabytes (2^43 bytes), time= 75955 seconds
  no anomalies in 2670 test result(s)

rng=RNG_stdin64, seed=unknown
length= 16 terabytes (2^44 bytes), time= 158507 seconds
  no anomalies in 2731 test result(s)
```

China GM/T 0005-2021 Test Result (Type 1 algorithm):
Significant alpha level is 0.01, distribution uniformity beta level is 0.0001
中国GM/T 0005-2021测试结果（Type 1 算法）：
显著性α水平为0.01，分布均匀性β水平为0.0001
| 采样的二进制数据文件 | 单比特频数检测 | 块内频数检测 m=10000 | 扑克检测 m=4 | 扑克检测 m=8 | 重叠子序列检测 m=3 P1 | 重叠子序列检测 m=3 P2 | 重叠子序列检测 m=5 P1 | 重叠子序列检测 m=5 P2 | 游程总数检测 | 游程分布检测 | 块内最大1游程检测 m=10000 | 块内最大0游程检测 m=10000 | 二元推导检测 k=3 | 二元推导检测 k=7 | 自相关检测 d=1 | 自相关检测 d=2 | 自相关检测 d=8 | 自相关检测 d=16 | 矩阵秩检测 | 累加和前向检测 | 累加和后向检测 | 近似熵检测 m=2 | 近似熵检测 m=5 | 线性复杂度检测 m=500 | 线性复杂度检测 m=1000 | Maurer通用统计检测 L=7 Q=1280 | 离散傅里叶检测 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| sampled binary data file | MonoBitFrequencyTest | FrequencyWithinBlockTest m=10000 | PokerTest m=4 | PokerTest m=8 | OverlappingTemplateMatchingTest m=3 P1 | OverlappingTemplateMatchingTest m=3 P2 | OverlappingTemplateMatchingTest m=5 P1 | OverlappingTemplateMatchingTest m=5 P2 |OverlappingTemplateMatchingTest | RunsDistributionTest | LongestRunOfOnesInABlockTest m=10000 | LongestRunOfZerosInABlockTest m=10000 | BinaryDerivativeTest k=3 | BinaryDerivativeTest k=7 | AutocorrelationTest d=1 | AutocorrelationTest d=2 | AutocorrelationTest d=8 | AutocorrelationTest d=16 | MatrixRankTest | CumulativeTest(Forward) | CumulativeTest(Backward) | ApproximateEntropyTest m=2 | ApproximateEntropyTestm=5 | LinearComplexityTest m=500 | LinearComplexityTest m=1000 | MaurerUniversalTest L=7 Q=1280 | DiscreteFourierTransformTest |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| XorConstantRotation_DataSequence.bin | 0.373130\|0.186565 | 0.288458\|0.288458 | 0.675829\|0.675829 | 0.801236\|0.801236 | 0.300015\|0.300015 | 0.132839\|0.132839 | 0.856208\|0.856208 | 0.975438\|0.975438 | 0.827448\|0.586276 | 0.582497\|0.582497 | 0.201710\|0.201710 | 0.997897\|0.997897 | 0.555950\|0.277975 | 0.338057\|0.169029 | 0.826084\|0.586958 | 0.456791\|0.771605 | 0.179660\|0.910170 | 0.087451\|0.956274 | 0.721874\|0.721874 | 0.442430\|0.442430 | 0.305578\|0.305578 | 0.299772\|0.299772 | 0.820013\|0.820013 | 0.428425\|0.428425 | 0.785520\|0.785520 | 0.585073\|0.292537 | 0.823063\|0.588468 |
| Tested distribution uniformity | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 | 0.437274 |
| Whether the passes the test (boolean) | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |

---

Generate sample file with c++ 2020 code (Type 1 algorithm):
生成带有c++ 2020代码的样本文件 (Type 1 算法)：
```c++
int main()
{
	/*
		seed 1
		seed 1234
		seed 741258963
		seed 741258963963147852
	*/
	XorConstantRotation xcr_prng(1234);

	const std::size_t number = 1048576 / 8 / 8; //Sample binary file size is 128 KB
	const std::size_t bits_per_line = 100;
	const std::string output_file = "XorConstantRotation_DataSequence.bin";

	for ( std::size_t i = 0, random_number = 0; i < number; i++ )
	{
		random_number = xcr_prng( i );
		std::cout << std::to_string(random_number) + ", ";
		if((i % 4) == 0)
			std::cout << std::endl;
	}

	//I used c IO
	FILE* file = freopen( output_file.c_str(), "wb", stdout );
	if ( !file )
	{
		perror( "Failed to open output file" );
		return 1;
	}

	for ( std::size_t i = 0, random_number = 0; i < number; i++ )
	{
		random_number = xcr_prng( i );

		fwrite( &random_number, 1, sizeof( &random_number ), file );
	}

	fclose(file);
}
```

---

***Sample C language usage***
***C语言使用样例***

Here are 2 examples of encryption and decryption in C using Type 1 and Type 2 algorithms (Visual C++):
以下是2个C语言使用Type 1和Type 2算法进行加密和解密的例子 (Visual C++):
```c
#include "Wrapper_LittleOaldresPuzzle_Cryptic.h" //This c header file is in the repository (这个c头文件在仓库)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

// I provide c++ code that can be compiled cross-platform, and then you compile your own static libraries
// 我提供了可以跨平台编译的c++代码，然后你自己编译的静态库
#pragma comment(lib, "Algorithm_OaldresPuzzleCryptic.lib")

void TestLittleOPC()
{
	// Create LittleOPC Instance
	// 创建 LittleOPC 实例
	LittleOPC_Instance cryptic = New_LittleOPC(12345);

	// Perform a single round of encryption and decryption tests
	// 进行单轮加密和解密测试
	uint64_t data = 0x123456789abcdef0;
	uint64_t key = 0xdeadbeef;
	uint64_t round = 1;

	uint64_t encrypted = LittleOPC_SingleRoundEncryption(cryptic, data, key, round);
	uint64_t decrypted = LittleOPC_SingleRoundDecryption(cryptic, encrypted, key, round);

	printf("Original Data: 0x%llx\n", data);
	printf("Encrypted Data: 0x%llx\n", encrypted);
	printf("Decrypted Data: 0x%llx\n", decrypted);
	printf("\n");

	// Perform multiple rounds of encryption and decryption tests
	// 进行多轮加密和解密测试
	static const size_t size = 3;
	uint64_t data_array[] = {0x123456789abcdef0, 0xdeadbeefdeadbeef, 0xfacefacefaceface};
	uint64_t keys[] = {0x1111111111111111, 0x2222222222222222, 0x3333333333333333};
	uint64_t result_data_array[3];

	LittleOPC_MultipleRoundsEncryption(cryptic, data_array, size, keys, result_data_array);

	printf("Original Data Array:\n");
	for (int i = 0; i < size; i++) {
		printf("0x%llx ", data_array[i]);
	}
	printf("\n");

	printf("Encrypted Data Array:\n");
	for (int i = 0; i < size; i++) {
		printf("0x%llx ", result_data_array[i]);
	}
	printf("\n");

	LittleOPC_MultipleRoundsDecryption(cryptic, result_data_array, size, keys, result_data_array);

	printf("Decrypted Data Array:\n");
	for (int i = 0; i < size; i++) {
		printf("0x%llx ", result_data_array[i]);
	}
	printf("\n");

	// Generate subkey test
	// 生成子密钥测试
	uint64_t* subkey_encryption = LittleOPC_GenerateSubkeyWithEncryption(cryptic, key, 10);
	uint64_t* subkey_decryption = LittleOPC_GenerateSubkeyWithDecryption(cryptic, key, 10);

	printf("Encryption Subkeys:\n");
	for (int i = 0; i < 10; i++) {
		printf("0x%llx ", subkey_encryption[i]);
	}
	printf("\n");

	printf("Decryption Subkeys:\n");
	for (int i = 0; i < 10; i++) {
		printf("0x%llx ", subkey_decryption[i]);
	}
	printf("\n");

	// Reset PRNG state
	// 重置 PRNG 状态
	LittleOPC_ResetPRNG(cryptic);

	// Delete LittleOPC Instance
	// 删除 LittleOPC 实例
	Delete_LittleOPC(cryptic);
}

int main()
{
	TestLittleOPC();
	return 0;
}
```

```c
#include "Wrapper_LittleOaldresPuzzle_Cryptic.h" //This c header file is in the repository (这个c头文件在仓库)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

// I provide c++ code that can be compiled cross-platform, and then you compile your own static libraries
// 我提供了可以跨平台编译的c++代码，然后你自己编译的静态库
#pragma comment(lib, "Algorithm_OaldresPuzzleCryptic.lib")

// Helper function: prints a hexadecimal form of a byte array
// 辅助函数: 打印一个字节数组的16进制形式
void PrintByteArrayWithHexadecimal(const uint8_t* data, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		if((i % 32) == 0)
			printf("\n");
		printf("%02X ", data[i]);

	}
	printf("\n");
}

void TestOPC()
{
	/*
		A.
		If your parameters do not satisfy the various condition checks in the New_OPC function, this function will print an error message and return NULL POINTER. to avoid these errors, you need to set your parameters correctly.

		First, you need to make sure that data_block_size is a multiple of 2 and not less than 2. Here we can use 16.

		Second, key_block_size must be a multiple of 4 and not less than 4, and must be an integer multiple of data_block_size. So we can choose 32, which satisfies both being a multiple of 4 and 2 times of 16.

		The initial_vector_size should be a multiple of (data_block_size * sizeof(uint64_t)). Here, data_block_size is 16 and sizeof(uint64_t) is 8, so initial_vector_size should be a multiple of 128. We can choose 128.

		LFSR_Seed and NLFSR_Seed cannot be 0, so we can choose a non-zero value, such as 1.

		SDP_Seed must be greater than or equal to 0x2540BE400, so we can choose a larger value, such as 0x2540BE401.

		As for keys, initial_vector and plaintext, you can set them according to your own needs.

		B.
		The data block size must be a multiple of 2 and at least 2, the key block size must be a multiple of 4 and at least 4, and the key block size must be a multiple of the data block size.
		The initial vector size must be a multiple of the product of the data block size and sizeof(uint64_t).
		LFSR_Seed and NLFSR_Seed cannot be 0, and SDP_Seed cannot be less than 0x2540BE400.
		
		--------------------------------------------------
		
		A:
		如果你的参数不满足New_OPC函数中的各种条件检查，这个函数就会打印出错误信息并返回NULL。为了避开这些错误，你需要正确地设置你的参数。

		首先，你需要确保data_block_size是2的倍数且不小于2。这里我们可以使用16。

		其次，key_block_size必须是4的倍数且不小于4，并且必须是data_block_size的整数倍。所以我们可以选择32，它既满足是4的倍数，又是16的2倍。

		initial_vector_size应该是(data_block_size * sizeof(uint64_t))的倍数。这里，data_block_size是16，sizeof(uint64_t)是8，所以initial_vector_size应该是128的倍数。我们可以选择128。

		LFSR_Seed和NLFSR_Seed不能为0，所以我们可以选择非0的值，比如1。

		SDP_Seed必须大于或等于0x2540BE400，所以我们可以选择一个更大的值，比如0x2540BE401。

		至于keys，initial_vector和plaintext，你可以根据你自己的需要进行设置。

		B:
		数据块大小必须为2的倍数且至少为2，密钥块大小必须为4的倍数且至少为4，而且密钥块大小必须是数据块大小的倍数。
		初始向量大小必须为数据块大小与sizeof(uint64_t)的乘积的倍数。
		LFSR_Seed和NLFSR_Seed不能为0，SDP_Seed不能小于0x2540BE400。
	*/
	
	// Encryption and decryption tests with the tested data
	// 使用测试的数据进行加密和解密测试
	uint8_t keys[256] = {0};
	for(uint32_t number = 0; number < sizeof(keys); ++number)
		keys[number] = number;

	uint8_t initial_vector[128] = {0};
	for(uint32_t number = 0; number < sizeof(initial_vector); ++number)
		initial_vector[number] = number;

	uint8_t plaintext[128] = {0};
	for(uint32_t number = 0; number < sizeof(plaintext); ++number)
		plaintext[number] = number;

	uint64_t data_block_size = 16;
	uint64_t key_block_size = 32;
	uint64_t initial_vector_size = sizeof(initial_vector);
	uint64_t LFSR_Seed = 1;
	uint64_t NLFSR_Seed = 1;
	uint64_t SDP_Seed = 0x2540BE400;

	// Create an instance of OaldresPuzzle_CrypticContext
	// 创建一个OaldresPuzzle_CrypticContext实例
	OaldresPuzzle_CrypticContext* context = New_OPC(data_block_size, key_block_size, initial_vector, initial_vector_size, LFSR_Seed, NLFSR_Seed, SDP_Seed);
	assert(context != NULL, "Failed to create OaldresPuzzle_CrypticContext\n");
	
	// Print the original data
	// 打印原有的数据
	printf("Original data: ");
	PrintByteArrayWithHexadecimal(plaintext, sizeof(plaintext));

	// Calling the encryption function
	// 调用加密函数
	uint8_t encrypted[128] = {0x00};
	OPC_Encryption(context, keys, sizeof(keys), plaintext, sizeof(plaintext), encrypted);

	// Print encrypted data
	// 打印加密的数据
	printf("Encrypted data: ");
	PrintByteArrayWithHexadecimal(encrypted, sizeof(encrypted));

	// Calling the decryption function
	// 调用解密函数
	uint8_t decrypted[128] = {0x00};
	OPC_Decryption(context, keys, sizeof(keys), encrypted, sizeof(encrypted), decrypted);

	// Print decrypted data
	// 打印解密的数据
	printf("Decrypted data: ");
	PrintByteArrayWithHexadecimal(decrypted, sizeof(decrypted));

	// Ensure that the decrypted data is the same as the original data
	// 确保解密后的数据和原始数据相同
	assert(memcmp(plaintext, decrypted, sizeof(plaintext)) == 0);

	// Delete the OaldresPuzzle_CrypticContext instance
	// 删除 OaldresPuzzle_CrypticContext 实例
	Delete_OPC(context);
}

int main()
{
	TestOPC();
	return 0;
}
```

---

本项目 CMakeLists.txt 内容
This item CMakeLists.txt content
```cmake
cmake_minimum_required(VERSION 3.26)
project(Algorithm_OaldresPuzzleCryptic)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_COMPILER "Your/Path/gcc")
set(CMAKE_CXX_COMPILER "Your/Path/g++")

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
```

要编译为可执行程序替换`add_library`语句到`add_executable`
```cmake
# Add executable target with source files listed in SOURCE_FILES variable
add_executable(Algorithm_OaldresPuzzleCryptic ${SOURCE_FILES})
```

---

Project main directory structure:
项目主要目录结构:
```
│  .clang-format
│  BitRotation.hpp
│  BuildProject.sh
│  CMakeLists.txt
│  CMakeSettings.json
│  CommonSecurity.hpp
│  COPYRIGHT
│  DataFormating.hpp
│  main.cpp
│  RandomNumberDistribution.hpp
│  README.md
│  SecureSeedGenerator.hpp
│  SupportBaseFunctions.hpp
│
├─.idea
│  │  .gitignore
│  │  Algorithm_OaldresPuzzleCryptic.iml
│  │  encodings.xml
│  │  misc.xml
│  │  modules.xml
│  │  workspace.xml
│  │
│  └─codeStyles
│		  codeStyleConfig.xml
│
├─BlockCipher
│  │  CustomSecureHash.hpp
│  │  Modules_OaldresPuzzle_Cryptic.hpp
│  │  Module_MixTransformationUtil.cpp
│  │  Module_MixTransformationUtil.hpp
│  │  Module_SecureRoundSubkeyGeneratation.cpp
│  │  Module_SecureRoundSubkeyGeneratation.hpp
│  │  Module_SecureSubkeyGeneratation.cpp
│  │  Module_SecureSubkeyGeneratation.hpp
│  │  Module_SubkeyMatrixOperation.cpp
│  │  Module_SubkeyMatrixOperation.hpp
│  │  OaldresPuzzle_Cryptic.cpp
│  │  OaldresPuzzle_Cryptic.hpp
│  │  OPC_MainAlgorithm_Worker.cpp
│  │  OPC_MainAlgorithm_Worker.hpp
│  │  TDOM_HashModule --- SecureCustomHash.md
│  │
│  ├─ExtraIncludes
│  │  └─eigen
│  │	  │  .clang-format
│  │	  │  .gitignore
│  │	  │  .gitlab-ci.yml
│  │	  │  .hgeol
│  │	  │  CMakeLists.txt
│  │	  │  COPYING.APACHE
│  │	  │  COPYING.BSD
│  │	  │  COPYING.LGPL
│  │	  │  COPYING.MINPACK
│  │	  │  COPYING.MPL2
│  │	  │  COPYING.README
│  │	  │  CTestConfig.cmake
│  │	  │  CTestCustom.cmake.in
│  │	  │  eigen3.pc.in
│  │	  │  INSTALL
│  │	  │  README.md
│  │	  │  signature_of_eigen3_matrix_library
│  │   .......
│  │
│  └─Includes
│	  │  PRNGs.hpp
│	  │
│	  ├─KeyDerivationFunction
│	  │	  PBKDF2.cpp
│	  │	  PBKDF2.hpp
│	  │	  Scrypt.cpp
│	  │	  Scrypt.hpp
│	  │
│	  └─SecureHashProvider
│			  HMAC_Worker.cpp
│			  HMAC_Worker.hpp
│			  SHA2_512.cpp
│			  SHA2_512.hpp
│
├─C_API
│	  Wrapper_LittleOaldresPuzzle_Cryptic.cpp
│	  Wrapper_LittleOaldresPuzzle_Cryptic.h
│	  Wrapper_OaldresPuzzle_Cryptic.cpp
│	  Wrapper_OaldresPuzzle_Cryptic.h
│
├─StreamCipher
│	  GenerateAndDisplay_XorConstantRotation_RoundConstant.py
│	  LittleOaldresPuzzle_Cryptic.cpp
│	  LittleOaldresPuzzle_Cryptic.h
│	  XorConstantRotation.cpp
│	  XorConstantRotation.h
│
├─TechnicalDetailPapers
│	  (English) Algorithm OaldresPuzzle_Cryptic by Twilight-Dream.drawio.png
│	  Algorithm OaldresPuzzle_Cryptic by Twilight-Dream.drawio.png
│	  The Algorithm OaldresPuzzle_Cryptic Technical Details Paper (English Only).pdf
│	  The Algorithm OaldresPuzzle_Cryptic Technical Details Paper.pdf
│
└─Test
		Test_LittleOaldresPuzzle_Cryptic.cpp
		Test_LittleOaldresPuzzle_Cryptic.h
		Test_OaldresPuzzle_Cryptic.cpp
		Test_OaldresPuzzle_Cryptic.h
```