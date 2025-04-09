/*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * 本文件是 TDOM-EncryptOrDecryptFile-Reborn 的一部分。
 *
 * TDOM-EncryptOrDecryptFile-Reborn 是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是（按你的决定）任何以后版都可以。
 *
 * 发布 TDOM-EncryptOrDecryptFile-Reborn 是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的复本。如果没有，请看 <https://www.gnu.org/licenses/>。
 */
 
 /*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * This document is part of TDOM-EncryptOrDecryptFile-Reborn.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
*	@file IsFor_EODF_Reborn.hpp
*
*	@brief 加密或解密文件重生版本 - 实用工具
*	@brief Encrypting or Decrypting File Reborn Versions - Utility tools
*
*	作者成员：
*	Author Members:
*
*	@author Project Owner and Module Designer: Twilight-Dream
*	@author Algorithm Designer: Spiritual-Fish
*	@author Tech Supporter : XiLiuFeng
* 
*	功能名：隐秘的奥尔德雷斯之谜
*	Function Name: OaldresPuzzle-Cryptic
*
*	@details
*	项目反馈URL (Github/GitLab):
*	Project Feedback URL (Github/GitLab):
*
*	联系方式:
*	Contact details:
*	
*		With by bilibili website personal space:
*		Twilight-Dream https://space.bilibili.com/21974189
*		Spiritual-Fish https://space.bilibili.com/1545018134
*		XiLiuFeng https://space.bilibili.com/4357220
*
*	All copyrights reserved from ©2021 year forward (Author Members)
*	保留所有权利，从@2021年开始 (作者成员)
*/

//#include <io.h>

/* Do not change this include file order!!! */

#include "../include/Support+Library/Support-Library.hpp"

#include "../include/CommonToolkit/CPP2020_Concept.hpp"
#include "../include/CommonToolkit/CommonToolkit.hpp"
#include "../include/CommonToolkit/BytesExchangeInteger.hpp"

#include "../include/UtilTools/UtilTools.hpp"

#include <eigen/Eigen/Dense>
#include <eigen/unsupported/Eigen/KroneckerProduct>
#include <eigen/unsupported/Eigen/FFT>

#include "../include/CommonSecurity/CommonSecurity.hpp"

#include "../include/CommonSecurity/SecureHashProvider/Hasher.hpp"
#include "../include/CommonSecurity/KeyDerivationFunction/AlgorithmScrypt.hpp"

#include "../include/CommonSecurity/SecureRandomUtilLibrary.hpp"
#include "../include/CommonSecurity/OPC_PRNGs.hpp"

#include "../include/CustomSecurity/CryptionWorker.hpp"

#include "./UnitTester.hpp"

auto main(int argument_cout, char* argument_vector[]) -> int
{
	system("chcp 65001");

	std::cout.tie(nullptr)->sync_with_stdio(false);

	//10485760 10MB
	//209715200 200MB
	#if 1
	std::vector<std::uint8_t> InitialVector(8192, 0x00);
	std::vector<std::uint8_t> InitialVector2(8192, 0x00);
	std::vector<std::uint8_t> PlainData(1048576, 0x00);
	std::vector<std::uint8_t> PlainData2(1048576, 0x00);
	std::vector<std::uint8_t> Keys = UnitTester::GanerateRandomValueVector(5120);
	//std::vector<std::uint8_t> Keys2 = Keys;
	std::vector<std::uint8_t> Keys2(5120, 0x00);
	Keys2[0] = 0x01;

	//UnitTester::Test_BlockCryptograph_CustomOaldresPuzzleCryptic_2(PlainData, Keys, InitialVector, (std::uint64_t)123456, (std::uint64_t)456789);
	
	//(Encryption,ResetState,Encryption,ResetState - Decryption,ResetState Decryption,ResetState)
	UnitTester::Test_BlockCryptograph_CustomOaldresPuzzleCryptic_2_CornerCases(PlainData2, Keys2, InitialVector2, (std::uint64_t)123456, (std::uint64_t)456789, (std::uint64_t)0x2540BE400);
	
	PlainData.clear();
	Keys.clear();
	Keys2.clear();
	PlainData.shrink_to_fit();
	Keys.shrink_to_fit();
	Keys2.clear();
	#endif	// 0

	//Cryptograph::OaldresPuzzle_Cryptic::Version1::SingleRoundTest();
	//Cryptograph::OaldresPuzzle_Cryptic::Version1::MultipleRoundsWithMoreDataTest();
	//Cryptograph::OaldresPuzzle_Cryptic::Version1::NunberOnce_CounterMode_Test();

	std::cout << std::endl;

	/*

	std::uint32_t LeftWordData = 123456789;
	std::uint32_t RightWordData = 987654321;

	//Pseudo-Hadamard Transformation (Forward)
	auto A = LeftWordData + RightWordData;
	auto B = LeftWordData + RightWordData * 2;

	B ^= std::rotl(A, 1);
	A ^= std::rotr(B, 63);

	A ^= std::rotr(B, 63);
	B ^= std::rotl(A, 1);
				
	//Pseudo-Hadamard Transformation (Backward)
	RightWordData = B - A;
	LeftWordData = 2 * A - B;

	std::cout << std::endl;

	*/

	#if 0
	
	CommonSecurity::RNG_FeedbackShiftRegister::NonlinearFeedbackShiftRegister NLFSR(1);

	std::bernoulli_distribution prng_distribution(0.5);
	
	std::vector<std::uint8_t> random_bits(std::numeric_limits<std::uint64_t>::max() / 10240000000ULL, 0);
	std::vector<std::uint64_t> random_numbers(random_bits.size() / std::numeric_limits<std::uint64_t>::digits, 0);

	for(auto& random_bit : random_bits)
	{
		random_bit = prng_distribution(NLFSR);
	}

	for(std::size_t random_number_index = 0, bit_index_offset = 0; random_number_index < random_numbers.size(); random_number_index++, bit_index_offset += std::numeric_limits<std::uint64_t>::digits)
	{		
		auto& random_number = random_numbers[random_number_index];

		for(std::size_t bit_index = 0; bit_index < std::numeric_limits<std::uint64_t>::digits; bit_index++)
		{
			if(random_bits[bit_index + bit_index_offset])
				random_number |= (static_cast<std::uint64_t>(random_bits[bit_index + bit_index_offset]) << bit_index);
			else
				bit_index++;
		}
		std::cout << "Now random number (NLFSR) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}

	std::cout << std::endl;

	#endif

	#if 0

	CommonSecurity::RNG_FeedbackShiftRegister::NonlinearFeedbackShiftRegister NLFSR(1);

	//CommonSecurity::RND::BernoulliDistribution prng_distribution(0.5);
	 
	for(std::size_t random_number_index = 0; random_number_index < std::numeric_limits<std::uint64_t>::max() / 10240000000ULL; random_number_index++)
	{		
		auto random_number = NLFSR();
		//auto random_number = NLFSR.unpredictable_bits(1, 64);

		/*for(std::size_t bit_index = 0; bit_index < std::numeric_limits<std::uint64_t>::digits; bit_index++)
		{
			auto random_bit = prng_distribution(NLFSR);

			if(random_bit)
				random_number |= (static_cast<std::uint64_t>(random_bit) << bit_index);
			else
				bit_index++;
		}*/

		std::cout << "Now random number (NLFSR) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(50));

		/*int result_status = _setmode( _fileno(stdin), _O_BINARY );
		if(result_status == -1)
		{
			throw std::runtime_error("can not set file mode");
		}
		else
		{
			#if defined(_WIN32)
			freopen(NULL, "wb", stdout);  // Only necessary on Windows, but harmless.
			#endif

			size_t bytes_written = fwrite(&random_number, 1, sizeof(&random_number), stdout);
			if (bytes_written < sizeof(random_number))
			{
				throw std::runtime_error("this is no data!");
			}
		}*/
	}

	std::cout << std::endl;

	#endif

	#if 0

	std::vector<std::uint64_t> random_numbers(std::numeric_limits<std::uint64_t>::max() / (sizeof(std::uint64_t) * 10240000000ULL), 0);

	CommonSecurity::RNG_FeedbackShiftRegister::LinearFeedbackShiftRegister LFSR(1);

	for(auto& random_number : random_numbers)
	{
		random_number = 0;

		for(std::size_t bit_index = 0; bit_index < std::numeric_limits<std::uint64_t>::digits; bit_index++)
		{
			auto random_bit = prng_distribution(LFSR);

			if(random_bit)
				random_number |= (static_cast<std::uint64_t>(random_bit) << bit_index);
			else
				bit_index++;
		}

		std::cout << "Now random number (LFSR) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
	}
	std::cout << std::endl;

	#endif

	#if 0

	std::vector<std::uint64_t> random_numbers(std::numeric_limits<std::uint64_t>::max() / (sizeof(std::uint64_t) * 10240000000ULL), 0);

	CommonSecurity::RNG_FeedbackShiftRegister::NonlinearFeedbackShiftRegister LFSR(1);

	for(auto& random_number :random_numbers)
	{
		random_number = LFSR_Object();
		std::cout << "Now random number (LFSR) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	std::cout << std::endl;

	#endif

	#if 0

	std::vector<std::uint64_t> random_numbers(std::numeric_limits<std::uint64_t>::max() / (sizeof(std::uint64_t) * 10240000000ULL), 0);

	CommonSecurity::RNG_ChaoticTheory::SimulateDoublePendulum SDP(std::string("10000000000000001000000000000100000000000000000000000000"));

	random_numbers = SDP(1048576, 0, 1048576);
	for(auto& random_number :random_numbers)
	{
		std::cout << "Now random number (SDP) is: " << UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(random_number, false) << "-----" << random_number << "\n";
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	std::cout << std::endl;

	#endif


	//UnitTester::Tester_BlockCryptograph_CustomOaldresPuzzleCryptic();
	
	//auto SecureRandomNumberSeedSequence = CommonSecurity::GenerateSecureRandomNumberSeedSequence<std::size_t>(256);

	/*
	auto random_seed_vector = CommonSecurity::GenerateSecureRandomNumberSeedSequence<std::uint64_t>(64);
	std::seed_seq random_seed_sequence_obejct(random_seed_vector.begin(), random_seed_vector.end());
	std::mt19937_64 pseudo_random_generator_object(random_seed_sequence_obejct);

	std::vector<std::uint64_t> random_numbers;

	for(std::size_t round = 1024; round > 0; --round)
	{
		random_numbers.push_back(pseudo_random_generator_object());
	}
	*/

	std::cout << std::endl;

	#ifdef _WIN32
	std::system("pause");
	#else
	std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
	#endif

	return 0;
}