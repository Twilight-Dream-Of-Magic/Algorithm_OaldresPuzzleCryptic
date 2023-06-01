#if 0

#include "SupportBaseFunctions.hpp"
#include "BlockCipher/OaldresPuzzle_Cryptic.hpp"
#include "Test/Test_OaldresPuzzle_Cryptic.h"

void CheckUnitTest()
{

	TwilightDreamOfMagical::Test_LittleOaldresPuzzle_Cryptic::SingleRoundTest();
	TwilightDreamOfMagical::Test_LittleOaldresPuzzle_Cryptic::MultipleRoundsTest();
	TwilightDreamOfMagical::Test_LittleOaldresPuzzle_Cryptic::NumberOnce_CounterMode_Test();

#if 0

	using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::ImplementationDetails::CommonStateData;
	using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::OaldresPuzzle_Cryptic;

	std::vector<std::uint8_t> InitialVector(8192, 0x00);
	CommonStateData CSD = CommonStateData(16, 32, InitialVector, 1, 1, 0xB7E151628AED2A6AULL);
	OaldresPuzzle_Cryptic OPC_Algorithm = OaldresPuzzle_Cryptic(CSD);
	OPC_Algorithm.LaiMasseyFrameworkTest();

#else

	auto GanerateRandomValueVector = [](std::size_t size) -> std::vector<std::uint8_t>
	{
		std::random_device random_device_object;
		std::mt19937_64 RandomGeneraterByReallyTime(TwilightDreamOfMagical::CommonSecurity::GenerateSecureRandomNumberSeed<std::uint32_t>(random_device_object));
		TwilightDreamOfMagical::CommonSecurity::RND::UniformIntegerDistribution<std::size_t> UniformNumberDistribution(0, 255);

		std::vector<std::uint8_t> byte_data(size);
		for (std::size_t index = 0; index < size; index++) {
			byte_data[index] = byte_data[index] = UniformNumberDistribution(RandomGeneraterByReallyTime);
		}
		return byte_data;
	};

	using TwilightDreamOfMagical::Test_OaldresPuzzle_Cryptic::RunUnit;

	std::vector<std::uint8_t> InitialVector(8192, 0x00);
	std::vector<std::uint8_t> InitialVector2(8192, 0x00);
	std::vector<std::uint8_t> PlainData(1048576, 0x00);
	std::vector<std::uint8_t> PlainData2(1048576, 0x00);
	std::vector<std::uint8_t> Keys = GanerateRandomValueVector(5120);
	//std::vector<std::uint8_t> Keys2 = Keys;
	std::vector<std::uint8_t> Keys2(5120, 0x00);
	Keys2[0] = 0x01;

	RunUnit(PlainData, Keys, InitialVector, (std::uint64_t)123456, (std::uint64_t)456789, 0xB7E151628AED2A6AULL);

#endif	// 0
}

#else

#include "C_API/Wrapper_LittleOaldresPuzzle_Cryptic.h"
#include "C_API/Wrapper_OaldresPuzzle_Cryptic.h"

#endif

int main()
{
	//CheckUnitTest();
	return 0;
}