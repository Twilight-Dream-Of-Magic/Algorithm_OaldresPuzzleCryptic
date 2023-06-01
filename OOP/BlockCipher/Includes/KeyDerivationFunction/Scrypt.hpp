/*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * 本文件是 Algorithm_OaldresPuzzleCryptic 的一部分。
 *
 * Algorithm_OaldresPuzzleCryptic 是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是（按你的决定）任何以后版都可以。
 *
 * 发布 Algorithm_OaldresPuzzleCryptic 是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的复本。如果没有，请看 <https://www.gnu.org/licenses/>。
 */
 
 /*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * This file is part of Algorithm_OaldresPuzzleCryptic.
 *
 * Algorithm_OaldresPuzzleCryptic is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_SCRYPT_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_SCRYPT_HPP

#include "PBKDF2.hpp"

namespace TwilightDreamOfMagical::CommonSecurity
{	namespace KeyDerivationFunction
	{
		class Scrypt
		{

		public:

			Scrypt() = default;
			~Scrypt() = default;

			std::vector<std::uint8_t> GenerateKeys
			(
				std::span<std::uint8_t> secret_passsword_or_key_byte,
				std::span<std::uint8_t> salt_data,
				std::uint64_t result_byte_size,
				std::uint64_t resource_cost = DefaultResourceCost,
				std::uint64_t block_size = DefaultBlockSize,
				std::uint64_t parallelization_count = DefaultParallelizationCount
			)
			{
				my_cpp2020_assert
				(
					(resource_cost != 0 && (resource_cost & (resource_cost - 1)) == 0) == true,
					"When using Scrypt, the memory and cpu resource cost must be a power of 2!",
					std::source_location::current()
				);

				my_cpp2020_assert
				(
					parallelization_count > 0,
					"When using Scrypt, providing parallelized counts is cannot be zero!",
					std::source_location::current()
				);

				my_cpp2020_assert
				(
					parallelization_count <= static_cast<std::uint64_t>(std::numeric_limits<int>::max()),
					"When using Scrypt, providing parallelized counts is over the limit!",
					std::source_location::current()
				);

				my_cpp2020_assert
				(
					(block_size * parallelization_count) < (1ULL << 30ULL),
					"When using Scrypt, the block_size to be generated is multiplied by the parallelized buffer size, which is over the limit!",
					std::source_location::current()
				);


				my_cpp2020_assert
				(
					result_byte_size > 0,
					"When using Scrypt, the byte size of the key that needs to be generated is not zero!",
					std::source_location::current()
				);

				my_cpp2020_assert
				(
					result_byte_size <= std::numeric_limits<std::uint64_t>::max(),
					"When using Scrypt, the byte size of the key that needs to be generated is over the limit!",
					std::source_location::current()
				);

				return this->DoGenerateKeys(secret_passsword_or_key_byte, salt_data, result_byte_size, resource_cost, block_size, parallelization_count);
			}

		private:

			static constexpr std::size_t DefaultResourceCost = 1;
			static constexpr std::size_t DefaultBlockSize = 8;
			static constexpr std::size_t DefaultParallelizationCount = 1;

			void Salsa20_WordSpecification( const std::array<std::uint32_t, 16>& in, std::array<std::uint32_t, 16>& out );
			std::array<std::uint32_t, 16> ExclusiveOrBlock( std::span<const std::uint32_t> left, std::span<const std::uint32_t> right );
			void MixBlock( std::array<std::uint32_t, 16>& word32_buffer, std::span<const std::uint32_t> in, std::span<std::uint32_t> out, const std::uint64_t block_size );
			std::uint64_t Integerify( std::span<std::uint32_t> block, const std::uint64_t block_size );
			void ScryptMixFuncton( std::span<std::uint8_t> block, const std::uint64_t& block_size, const std::uint64_t resource_cost, std::span<std::uint32_t> block_v, std::span<std::uint32_t> block_xy );
			std::vector<std::uint8_t> DoGenerateKeys( std::span<std::uint8_t> secret_passsword_or_key_byte, std::span<std::uint8_t> salt_data, std::uint64_t& result_byte_size, std::uint64_t& resource_cost, std::uint64_t& block_size, std::uint64_t& parallelization_count );
		};
	}
}

#endif	//ALGORITHM_OALDRESPUZZLECRYPTIC_SCRYPT_HPP
