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

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_XORCONSTANTROTATION_H
#define ALGORITHM_OALDRESPUZZLECRYPTIC_XORCONSTANTROTATION_H

#include <iostream>
#include <cstdint>
#include <bit>
#include <array>

#if __cplusplus < 202002L
#include "../BitRotation.hpp"
#endif

namespace TwilightDreamOfMagical::CustomSecurity
{
	namespace CSPRNG
	{
		static bool show_special_notice_message = true;

		class XorConstantRotation
		{

		public:
			using result_type = uint64_t;
		
			XorConstantRotation()
					:
					x(0), y(0), state(1), counter(0)
			{
				if(show_special_notice_message)
				{
					std::cout << "\nSpecial Notice\n";
					std::cout << "The symmetric encryption and decryption algorithm (Type 1 StreamCipher) of the OaldresPuzzle_Cryptic (OPC) designed by Twilight-Dream.\n";
					std::cout << "After calling the encryption function or decryption function, the key state inside the algorithm will change; This design is to deal with any possible brute force guess (including use quantum computer attack).\n";
					std::cout << "If you have called the encryption function or decryption function, but want to restore your 'forward' operation.\n";
					std::cout << "Please destroy the current instance and rebuild, then you can call the 'backward' operation function.\n";
				}
				show_special_notice_message = false;

				this->StateInitialize();
			}

			explicit XorConstantRotation(const std::uint64_t seed)
					:
					x(0), y(0), state(seed), counter(0)
			{
				if(show_special_notice_message)
				{
					std::cout << "\nSpecial Notice\n";
					std::cout << "The symmetric encryption and decryption algorithm (Type 1 StreamCipher) of the OaldresPuzzle_Cryptic (OPC) designed by Twilight-Dream.\n";
					std::cout << "After calling the encryption function or decryption function, the key state inside the algorithm will change; This design is to deal with any possible brute force guess (including use quantum computer attack).\n";
					std::cout << "If you have called the encryption function or decryption function, but want to restore your 'forward' operation.\n";
					std::cout << "Please destroy the current instance and rebuild, then you can call the 'backward' operation function.\n";
				}
				show_special_notice_message = false;

				this->StateInitialize();
			}

			XorConstantRotation(const XorConstantRotation& other)
				: x(other.x), y(other.y), state(other.state), counter(other.counter)
			{
				
			};
			XorConstantRotation(XorConstantRotation&& other) = default;

			void Seed(const std::uint64_t seed)
			{
				x = 0;
				y = 0;
				state = seed;

				this->StateInitialize();
			}

			void ChangeCondition(const std::uint64_t value)
			{
				x = value;
				y = 0;

				this->StateInitialize();
			}

			result_type operator()(std::size_t number_once)
			{
				return this->StateIteration(number_once);
			}

			//std::uniform_random_bit_generator
			//The concept must meet the following requirements
			//1.Have `static constexpr` min and max function
			//2.constexpr bool isPRNG = (min() < max());
			//https://en.cppreference.com/w/cpp/numeric/random/uniform_random_bit_generator
			static constexpr result_type min()
			{
				return 0ULL;
			}

			static constexpr result_type max()
			{
				return 0xFFFFFFFFFFFFFFFFULL;
			}

		private:
			std::uint64_t x = 0;
			std::uint64_t y = 0;
			std::uint64_t state = 0;
			std::uint64_t counter = 0;

			void StateInitialize();
			result_type StateIteration(std::size_t round);
		};
	} // TwilightDreamOfMagical
} // CustomSecurity

#endif //ALGORITHM_OALDRESPUZZLECRYPTIC_XORCONSTANTROTATION_H
