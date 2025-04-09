#include "SupportBaseFunctions.hpp" //C++ STL Wrapper and Custom Utils

#define IS_LIBRARY_TEST
//#define IS_BINARY_TEST_LITTLEOPC
//#define IS_BINARY_TEST_OPC

#if defined(IS_LIBRARY_TEST)

#include "C_API/Wrapper_LittleOaldresPuzzle_Cryptic.h"
#include "C_API/Wrapper_OaldresPuzzle_Cryptic.h"

#else

#if defined(IS_BINARY_TEST_LITTLEOPC)

#include "Test/Test_LittleOaldresPuzzle_Cryptic.h"

inline void Check_LittleOPC_UnitTest()
{
	TwilightDreamOfMagical::Test_LittleOaldresPuzzle_Cryptic::SingleRoundTest();
	TwilightDreamOfMagical::Test_LittleOaldresPuzzle_Cryptic::MultipleRoundsTest();
	TwilightDreamOfMagical::Test_LittleOaldresPuzzle_Cryptic::NumberOnce_CounterMode_Test();
}

#endif //IS_BINARY_TEST_LITTLEOPC

#if _DEBUG

#include "BlockCipher/OaldresPuzzle_Cryptic.hpp"

inline void Debug_OPC_LaiMasseyFrameworkTest()
{
	//using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::ImplementationDetails::CommonStateData;
	//using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::OaldresPuzzle_Cryptic;

	//std::vector<std::uint8_t> InitialVector(8192, 0x00);
	//CommonStateData CSD = CommonStateData(16, 32, InitialVector, 1, 1, 0xB7E151628AED2A6AULL);
	//OaldresPuzzle_Cryptic OPC_Algorithm = OaldresPuzzle_Cryptic(CSD);
	//OPC_Algorithm.LaiMasseyFrameworkTest();
}

#endif

#if defined(IS_BINARY_TEST_OPC)

#include "Test/Test_OaldresPuzzle_Cryptic.h"

inline void Check_OPC_UnitTest()
{

	auto GenerateRandomValueVector = [](std::size_t size) -> std::vector<std::uint8_t>
	{
		std::random_device random_device_object;
		std::mt19937_64 RandomGeneraterByReallyTime(TwilightDreamOfMagical::CommonSecurity::GenerateSecureRandomNumberSeed<std::uint32_t>(random_device_object));
		TwilightDreamOfMagical::CommonSecurity::RND::UniformIntegerDistribution<std::size_t> UniformNumberDistribution(0, 255);

		std::vector<std::uint8_t> byte_data(size);
		for (std::size_t index = 0; index < size; index++) {
			byte_data[index] = UniformNumberDistribution(RandomGeneraterByReallyTime);
		}
		return byte_data;
	};

	using TwilightDreamOfMagical::Test_OaldresPuzzle_Cryptic::RunUnit;

	std::vector<std::uint8_t> InitialVector(8192, 0x00);
	std::vector<std::uint8_t> InitialVector2(8192, 0x00);
	std::vector<std::uint8_t> PlainData(1048576, 0x00);
	std::vector<std::uint8_t> PlainData2(1048576, 0x00);
	std::vector<std::uint8_t> Keys = GenerateRandomValueVector(5120);
	//std::vector<std::uint8_t> Keys2 = Keys;
	std::vector<std::uint8_t> Keys2(5120, 0x00);
	Keys2[0] = 0x01;

	RunUnit(PlainData, Keys, InitialVector, (std::uint64_t)123456, (std::uint64_t)456789, 0xB7E151628AED2A6AULL);

}

#endif //IS_BINARY_TEST_OPC

#endif //IS_LIBRARY_TEST

/*
	Note: please look 'IS_LIBRARY_TEST' macro definition !!!!
	
	 These macros control the compilation flow:

	1. `IS_LIBRARY_TEST`: 
		- If defined, the program will compile with the C API wrappers (`Wrapper_LittleOaldresPuzzle_Cryptic.h` and `Wrapper_OaldresPuzzle_Cryptic.h`).
		- This mode is likely used to test or expose the library functions via a C API for integration with other projects or languages.
	
	2. `IS_BINARY_TEST_LITTLEOPC`: 
		- If defined, the program will compile and run unit tests specific to the `LittleOaldresPuzzle_Cryptic` implementation.
		- It includes functions for single-round tests, multiple-round tests, and counter mode tests.
	
	3. `IS_BINARY_TEST_OPC`: 
		- If defined, the program will compile and run unit tests for the `OaldresPuzzle_Cryptic` implementation.
		- This mode includes testing of the main cryptographic functions using randomly generated data and keys.
*/



int main()
{
	
	#if !defined(IS_LIBRARY_TEST)
	
	#if defined(IS_BINARY_TEST_LITTLEOPC)
	
	Check_LittleOPC_UnitTest();
	
	#endif
	
	#if defined(IS_BINARY_TEST_OPC)
	
	Check_OPC_UnitTest();
	
	#endif
	
	#else
	
	std::cout << "With the library test ready, let another program use the C API functions." << std::endl;
	
	#endif
	
	return 0;
}

#if defined(IS_LIBRARY_TEST)
#undef IS_LIBRARY_TEST
#endif

#if defined(IS_BINARY_TEST_LITTLEOPC)
#undef IS_BINARY_TEST_LITTLEOPC
#endif

#if defined(IS_BINARY_TEST_OPC)
#undef IS_BINARY_TEST_OPC
#endif
