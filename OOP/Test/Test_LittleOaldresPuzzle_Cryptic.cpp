#include "Test_LittleOaldresPuzzle_Cryptic.h"

namespace TwilightDreamOfMagical
{
	namespace Test_LittleOaldresPuzzle_Cryptic
	{
		using LittleOaldresPuzzle_Cryptic = CustomSecurity::SED::StreamCipher::LittleOaldresPuzzle_Cryptic;

		void SingleRoundTest()
		{
			std::uint64_t A = 1475;
			std::uint64_t B = 3695;

			std::uint64_t KeyA = 7532;
			std::uint64_t KeyB = 9512;

			std::uint64_t seed = 1;
			LittleOaldresPuzzle_Cryptic LittleOPC(seed);

			std::cout << "--------------------------------------------------" << std::endl;

			std::uint64_t C = LittleOPC.SingleRoundEncryption(A, KeyA, 1);
			std::uint64_t D = LittleOPC.SingleRoundEncryption(B, KeyB, 2);

			std::cout << "A' = " << C << std::endl;
			std::cout << "B' = " << D << std::endl;

			LittleOPC.ResetPRNG();

			C = LittleOPC.SingleRoundDecryption(C, KeyA, 1);
			D = LittleOPC.SingleRoundDecryption(D, KeyB, 2);

			std::cout << "A = " << C << std::endl;
			std::cout << "B = " << D << std::endl;

			if (A == C && B == D)
			{
				std::cout << "The decryption was successful." << std::endl;
			}
			else
			{
				std::cout << "The decryption failed." << std::endl;
			}

			std::cout << "--------------------------------------------------" << std::endl;
		}

		void MultipleRoundsTest()
		{
			std::vector<std::uint64_t> data = {1475, 3695, 1258, 7593};
			std::vector<std::uint64_t> keys = {7532, 9512, 6108, 8729};

			std::vector<std::uint64_t> encrypted_data(data.size());
			std::vector<std::uint64_t> decrypted_data(data.size());

			std::uint64_t seed = 1;
			LittleOaldresPuzzle_Cryptic LittleOPC(seed);

			LittleOPC.MultipleRoundsEncryption(data, keys, encrypted_data);
			LittleOPC.MultipleRoundsDecryption(encrypted_data, keys, decrypted_data);

			std::cout << "--------------------------------------------------" << std::endl;

			// Output
			for (size_t i = 0; i < data.size(); ++i)
			{
				std::cout << "Original data: " << data[i] << ", Encrypted data: " << encrypted_data[i] << ", Decrypted data: " << decrypted_data[i] << std::endl;

				if (data[i] == decrypted_data[i])
				{
					std::cout << "Decryption was successful for data " << i << "." << std::endl;
				}
				else
				{
					std::cout << "Decryption failed for data " << i << "." << std::endl;
				}
			}

			std::cout << "--------------------------------------------------" << std::endl;
		}

		void MultipleRoundsWithMoreDataTest()
		{
			std::size_t data_size = 10 * 1024 * 1024 / sizeof(std::uint64_t); // 10 MB of data
			std::vector<std::uint64_t> data(data_size);

			std::random_device rd;
			std::mt19937_64 generator(rd());
			std::uniform_int_distribution<std::uint64_t> distribution;

			// Generate random data
			for (size_t i = 0; i < data_size; ++i)
			{
				data[i] = distribution(generator);
			}

			std::size_t key_size = 5120 / sizeof(std::uint64_t); // 5120-byte keys
			std::vector<std::uint64_t> keys(key_size, 0);
			keys[0] = 1;

			std::vector<std::uint64_t> encrypted_data(data_size);
			std::vector<std::uint64_t> decrypted_data(data_size);

			std::uint64_t seed = 1;
			LittleOaldresPuzzle_Cryptic LittleOPC(seed);

			auto start_time = std::chrono::high_resolution_clock::now();

			// Encryption
			LittleOPC.MultipleRoundsEncryption(data, keys, encrypted_data);

			auto end_time = std::chrono::high_resolution_clock::now();
			auto encryption_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

			LittleOPC.ResetPRNG();

			start_time = std::chrono::high_resolution_clock::now();

			// Decryption
			LittleOPC.MultipleRoundsDecryption(encrypted_data, keys, decrypted_data);

			end_time = std::chrono::high_resolution_clock::now();
			auto decryption_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

			std::cout << "--------------------------------------------------" << std::endl;

			std::cout << "Encryption time: " << encryption_duration << " ms" << std::endl;
			std::cout << "Decryption time: " << decryption_duration << " ms" << std::endl;

			// Output and check for successful decryption
			size_t num_successful_decrypts = 0;
			for (size_t i = 0; i < data.size(); ++i)
			{
				if (data[i] == decrypted_data[i])
				{
					++num_successful_decrypts;
				}
			}

			std::cout << "Number of successful decrypts: " << num_successful_decrypts << " out of " << data.size() << std::endl;

			std::cout << "--------------------------------------------------" << std::endl;
		}

		void NumberOnce_CounterMode_Test()
		{
			std::uint64_t A = 1475;
			std::uint64_t B = 3695;
			std::uint64_t C = 0;
			std::uint64_t D = 0;

			std::uint64_t KeyA = 7532;
			std::uint64_t KeyB = 9512;

			std::uint64_t NumberRounds = 32;

			std::uint64_t seed = 1;
			LittleOaldresPuzzle_Cryptic LittleOPC(seed);

			std::cout << "--------------------------------------------------" << std::endl;

#if 1
			std::cout << "A = " << A << std::endl;
			std::cout << "B = " << B << std::endl;
			std::cout << "C = " << C << std::endl;
			std::cout << "D = " << D << std::endl;

			LittleOPC.ResetPRNG();
			auto SubKeysA = LittleOPC.GenerateSubkey_WithUseEncryption(KeyA, NumberRounds);
			LittleOPC.ResetPRNG();
			auto SubKeysB = LittleOPC.GenerateSubkey_WithUseEncryption(KeyB, NumberRounds);

			for(std::uint64_t round = 0; round < NumberRounds; ++round)
			{
				A ^= SubKeysA[round];
				B ^= SubKeysB[round];
				C ^= SubKeysA[round];
				D ^= SubKeysB[round];
			}

			std::cout << "A' = " << A << std::endl;
			std::cout << "B' = " << B << std::endl;
			std::cout << "C' = " << C << std::endl;
			std::cout << "D' = " << D << std::endl;

			for(std::uint64_t round = 0; round < NumberRounds; ++round)
			{
				A ^= SubKeysA[round];
				B ^= SubKeysB[round];
				C ^= SubKeysA[round];
				D ^= SubKeysB[round];
			}

			std::cout << "A = " << A << std::endl;
			std::cout << "B = " << B << std::endl;
			std::cout << "C = " << C << std::endl;
			std::cout << "D = " << D << std::endl;
#else
			std::cout << "A = " << A << std::endl;
			std::cout << "B = " << B << std::endl;
			std::cout << "C = " << C << std::endl;
			std::cout << "D = " << D << std::endl;

			LittleOPC.ResetPRNG();
			auto SubKeysA = LittleOPC.GenerateSubkey_WithUseDecryption(KeyA, NumberRounds);
			LittleOPC.ResetPRNG();
			auto SubKeysB = LittleOPC.GenerateSubkey_WithUseDecryption(KeyB, NumberRounds);

			for(std::uint64_t round = 0; round < NumberRounds; ++round)
			{
				A ^= SubKeysA[round];
				B ^= SubKeysB[round];
				C ^= SubKeysA[round];
				D ^= SubKeysB[round];
			}

			std::cout << "A' = " << A << std::endl;
			std::cout << "B' = " << B << std::endl;
			std::cout << "C' = " << C << std::endl;
			std::cout << "D' = " << D << std::endl;

			for(std::uint64_t round = 0; round < NumberRounds; ++round)
			{
				A ^= SubKeysA[round];
				B ^= SubKeysB[round];
				C ^= SubKeysA[round];
				D ^= SubKeysB[round];
			}

			std::cout << "A = " << A << std::endl;
			std::cout << "B = " << B << std::endl;
			std::cout << "C = " << C << std::endl;
			std::cout << "D = " << D << std::endl;
#endif

			std::cout << "--------------------------------------------------" << std::endl;
		}
	}

}
