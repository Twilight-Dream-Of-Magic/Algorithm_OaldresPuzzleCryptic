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
#include <utility>
#include <random>
#include "XorConstantRotation.h"

#if _DEBUG
#include <chrono>
#endif

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::StreamCipher
	{
		using Key128   = std::pair<std::uint64_t, std::uint64_t>;   // 128-bit key
		using Block128 = std::pair<std::uint64_t, std::uint64_t>;   // 128-bit block

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

			Block128 SingleRoundEncryption(const Block128 data, const Key128 key, const std::uint64_t number_once)
			{
				Block128 result = EncryptionCoreFunction(data, key, number_once);
				prng.Seed(seed);
				return result;
			}

			Block128 SingleRoundDecryption(const Block128 data, const Key128 key, const std::uint64_t number_once)
			{
				Block128 result = DecryptionCoreFunction(data, key, number_once);
				prng.Seed(seed);
				return result;
			}

			void MultipleRoundsEncryption(const std::vector<Block128>& data_array, std::vector<Key128>& keys, std::vector<Block128>& result_data_array)
			{
				// Ensure result_data_array is of the same size as data_array
				if(data_array.empty())
					return;
				else if (result_data_array.size() < data_array.size())
					result_data_array.resize(data_array.size());

				#if _DEBUG
			
				auto start = std::chrono::high_resolution_clock::now();
				
				#endif
				
				// Encryption
				for (size_t i = 0; i < data_array.size(); ++i)
				{
					result_data_array[i] = EncryptionCoreFunction(data_array[i], keys[i % keys.size()], i);
				}
				
				#if _DEBUG
			
				auto end = std::chrono::high_resolution_clock::now();
				encryptionTime = std::chrono::duration_cast<std::chrono::nanoseconds>( end - start );
				
				#endif
				
				// Reset the PRNG state for the next encryption or decryption (Must be call this function)
				ResetPRNG();
			}

			void MultipleRoundsDecryption(const std::vector<Block128>& data_array, std::vector<Key128>& keys, std::vector<Block128>& result_data_array)
			{
				// Ensure result_data_array is of the same size as data_array
				if(data_array.empty())
					return;
				else if (result_data_array.size() < data_array.size())
					result_data_array.resize(data_array.size());
				
				#if _DEBUG
			
				auto start = std::chrono::high_resolution_clock::now();
				
				#endif
				
				// Decryption
				for (size_t i = 0; i < data_array.size(); ++i)
				{
					result_data_array[i] = DecryptionCoreFunction(data_array[i], keys[i % keys.size()], i);
				}
				
				#if _DEBUG
			
				auto end = std::chrono::high_resolution_clock::now();
				encryptionTime = std::chrono::duration_cast<std::chrono::nanoseconds>( end - start );
				
				#endif

				// Reset the PRNG state for the next encryption or decryption (Must be call this function)
				ResetPRNG();
			}

			std::vector<Block128> GenerateSubkey_WithUseEncryption(const Key128 key, std::uint64_t loop_count)
			{
				Key128 subkey {0,0};
				Key128 buffer {0,0};
				std::vector<Key128> subkeys(loop_count, {0,0});

				std::mt19937_64 cpp_prng(key.first ^ key.second ^ loop_count);
				Block128 number_once {0,0};

				//NumberOnce/CounterMode
				for(std::uint64_t counter = 0; counter < loop_count; ++counter)
				{
					number_once = {cpp_prng(), cpp_prng()};
					buffer = EncryptionCoreFunction(number_once, key, counter);
					subkeys[counter] = {subkey.first ^ buffer.first, subkey.second ^ buffer.second};
				}
				
				// Reset the PRNG state for the next encryption or decryption (Must be call this function)
				ResetPRNG();

				return subkeys;
			}

			std::vector<Block128> GenerateSubkey_WithUseDecryption(const Key128 key, std::uint64_t loop_count)
			{
				Key128 subkey {0,0};
				Key128 buffer {0,0};
				std::vector<Key128> subkeys(loop_count, {0,0});

				std::mt19937_64 cpp_prng(key.first ^ key.second ^ loop_count);
				Block128 number_once {0,0};

				//NumberOnce/CounterMode
				for(std::uint64_t counter = 0; counter < loop_count; ++counter)
				{
					number_once = {cpp_prng(), cpp_prng()};
					buffer = DecryptionCoreFunction(number_once, key, counter);
					subkeys[counter] = {subkey.first ^ buffer.first, subkey.second ^ buffer.second};
				}
				
				// Reset the PRNG state for the next encryption or decryption (Must be call this function)
				ResetPRNG();

				return subkeys;
			}

			void ResetPRNG()
			{
				prng.Seed(seed);
			}
			
			#if _DEBUG
			
			std::chrono::nanoseconds encryptionTime;
			std::chrono::nanoseconds decryptionTime;
			
			#endif

		private:
			std::uint64_t seed = 0;
			XorConstantRotation prng;
			std::uint64_t rounds = 4;
			
			struct KeyState
			{
				Key128 subkey{0,0};
				std::uint64_t choice_function = 0;
				std::uint64_t bit_rotation_amount_a = 0;
				std::uint64_t bit_rotation_amount_b = 0;
				std::uint32_t round_constant_index = 0;
			};

			std::vector<KeyState> KeyStates;
			
			void GenerateAndStoreKeyStates(const Key128 key_128bit, const std::uint64_t number_once);

			Block128 EncryptionCoreFunction(const Block128 data, const Key128 key_128bit, const std::uint64_t round);
			Block128 DecryptionCoreFunction(const Block128 data, const Key128 key_128bit, const std::uint64_t round);
		};
	}

} // TwilightDreamOfMagical

#endif //ALGORITHM_OALDRESPUZZLE_CRYPTIC_LITTLEOALDRESPUZZLE_CRYPTIC_HPP
