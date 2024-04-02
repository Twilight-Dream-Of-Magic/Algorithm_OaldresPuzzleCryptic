/*
 * Copyright (C) 2023-2050 Twilight-Dream
 *
 * 本文件是 Algorithm_OaldresPuzzleCryptic 的一部分。
 *
 * Algorithm_OaldresPuzzleCryptic 是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是（按你的决定）任何以后版都可以。
 *
 * 发布 Algorithm_OaldresPuzzleCryptic 是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的复本。如果没有，请看 <https://www.gnu.org/licenses/>。
 */
 
 /*
 * Copyright (C) 2023-2050 Twilight-Dream
 *
 * This file is part of Algorithm_OaldresPuzzleCryptic.
 *
 * Algorithm_OaldresPuzzleCryptic is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef ALGORITHM_OALDRESPUZZLE_CRYPTIC_LITTLEOALDRESPUZZLE_CRYPTIC_HPP
#define ALGORITHM_OALDRESPUZZLE_CRYPTIC_LITTLEOALDRESPUZZLE_CRYPTIC_HPP

#include <vector>
#include <random>
#include "XorConstantRotation.h"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::StreamCipher
	{
		class LittleOaldresPuzzle_Cryptic
		{

		public:
			using XorConstantRotation = CSPRNG::XorConstantRotation;

			LittleOaldresPuzzle_Cryptic(const std::uint64_t seed, std::uint64_t rounds)
				: 
				seed(seed), prng(seed), rounds(rounds), KeyStates(std::vector<KeyState>(rounds, KeyState()))
			{
				
			}

			LittleOaldresPuzzle_Cryptic(const std::uint64_t seed)
				: 
				seed(seed), prng(seed), rounds(4), KeyStates(std::vector<KeyState>(rounds, KeyState()))
			{

			}

			LittleOaldresPuzzle_Cryptic()
				:
				seed(1), prng(seed), rounds(4), KeyStates(std::vector<KeyState>(rounds, KeyState()))
			{
				
			}

			std::uint64_t SingleRoundEncryption(const std::uint64_t data, const std::uint64_t key, const std::uint64_t number_once)
			{
				std::uint64_t result = EncryptionCoreFunction(data, key, number_once);
				prng.Seed(seed);
				return result;
			}

			std::uint64_t SingleRoundDecryption(const std::uint64_t data, const std::uint64_t key, const std::uint64_t number_once)
			{
				std::uint64_t result = DecryptionCoreFunction(data, key, number_once);
				prng.Seed(seed);
				return result;
			}

			void MultipleRoundsEncryption(const std::vector<std::uint64_t>& data_array, std::vector<std::uint64_t>& keys, std::vector<std::uint64_t>& result_data_array)
			{
				// Ensure result_data_array is of the same size as data_array
				if(data_array.empty())
					return;
				else if (result_data_array.size() < data_array.size())
					result_data_array.resize(data_array.size());

				auto start = std::chrono::high_resolution_clock::now();
				// Encryption
				for (size_t i = 0; i < data_array.size(); ++i)
				{
					result_data_array[i] = EncryptionCoreFunction(data_array[i], keys[i % keys.size()], i);
				}
				auto end = std::chrono::high_resolution_clock::now();
				encryptionTime = std::chrono::duration_cast<std::chrono::nanoseconds>( end - start );

				// Reset the PRNG state for the next encryption or decryption (Must be call this function)
				ResetPRNG();
			}

			void MultipleRoundsDecryption(const std::vector<std::uint64_t>& data_array, std::vector<std::uint64_t>& keys, std::vector<std::uint64_t>& result_data_array)
			{
				// Ensure result_data_array is of the same size as data_array
				if(data_array.empty())
					return;
				else if (result_data_array.size() < data_array.size())
					result_data_array.resize(data_array.size());

				auto start = std::chrono::high_resolution_clock::now();
				// Decryption
				for (size_t i = 0; i < data_array.size(); ++i)
				{
					result_data_array[i] = DecryptionCoreFunction(data_array[i], keys[i % keys.size()], i);
				}
				auto end = std::chrono::high_resolution_clock::now();
				decryptionTime = std::chrono::duration_cast<std::chrono::nanoseconds>( end - start );

				// Reset the PRNG state for the next encryption or decryption (Must be call this function)
				ResetPRNG();
			}

			std::vector<std::uint64_t> GenerateSubkey_WithUseEncryption(const std::uint64_t key, std::uint64_t loop_count)
			{
				std::uint64_t subkey = 0;
				std::vector<std::uint64_t> subkeys(loop_count, 0);

				std::mt19937_64 cpp_prng(key ^ loop_count);
				std::uint64_t number_once = 0;

				//NumberOnce/CounterMode
				for(std::uint64_t counter = 0; counter < loop_count; ++counter)
				{
					number_once = cpp_prng() + cpp_prng();
					subkey ^= EncryptionCoreFunction(number_once, key, counter);
					subkeys[counter] = subkey;
				}
				
				// Reset the PRNG state for the next encryption or decryption (Must be call this function)
				ResetPRNG();

				return subkeys;
			}

			std::vector<std::uint64_t> GenerateSubkey_WithUseDecryption(const std::uint64_t key, std::uint64_t loop_count)
			{
				std::uint64_t subkey = 0;
				std::vector<std::uint64_t> subkeys(loop_count, 0);

				std::mt19937_64 cpp_prng(key ^ loop_count);
				std::uint64_t number_once = 0;

				//NumberOnce/CounterMode
				for(std::uint64_t counter = 0; counter < loop_count; ++counter)
				{
					number_once = cpp_prng() + cpp_prng();
					subkey ^= DecryptionCoreFunction(number_once, key, counter);
					subkeys[counter] = subkey;
				}
				
				// Reset the PRNG state for the next encryption or decryption (Must be call this function)
				ResetPRNG();

				return subkeys;
			}

			void ResetPRNG()
			{
				prng.Seed(seed);
			}

			std::chrono::nanoseconds encryptionTime;
			std::chrono::nanoseconds decryptionTime;

		private:
			std::uint64_t seed = 0;
			XorConstantRotation prng;
			std::uint64_t rounds = 4;
			
			struct KeyState
			{
				std::uint64_t subkey = 0;
				std::uint64_t choice_function = 0;
				std::uint64_t bit_rotation_amount_a = 0;
				std::uint64_t bit_rotation_amount_b = 0;
				std::uint32_t round_constant_index = 0;
			};

			std::vector<KeyState> KeyStates;
			
			void GenerateAndStoreKeyStates(const std::uint64_t key, const std::uint64_t number_once);

			std::uint64_t EncryptionCoreFunction(const std::uint64_t data, const std::uint64_t key, const std::uint64_t round);
			std::uint64_t DecryptionCoreFunction(const std::uint64_t data, const std::uint64_t key, const std::uint64_t round);
		};
	}

} // TwilightDreamOfMagical

#endif //ALGORITHM_OALDRESPUZZLE_CRYPTIC_LITTLEOALDRESPUZZLE_CRYPTIC_HPP
