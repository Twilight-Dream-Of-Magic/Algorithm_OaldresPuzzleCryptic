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

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_OPC_MAINALGORITHM_WORKER_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_OPC_MAINALGORITHM_WORKER_HPP

#include "OaldresPuzzle_Cryptic.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		class OPC_MainAlgorithm_Worker
		{
		public:
			explicit OPC_MainAlgorithm_Worker(OaldresPuzzle_Cryptic& AlgorithmCoreObject)
				:
				AlgorithmCorePointer(std::addressof(AlgorithmCoreObject))
			{
				std::cout << "\nSpecial Notice\n";
				std::cout << "The symmetric encryption and decryption algorithm (Type 2 BlockCipher) of the OaldresPuzzle_Cryptic (OPC) designed by Twilight-Dream.\n";
				std::cout << "After calling the encryption function or decryption function, the key state inside the algorithm will change; This design is to deal with any possible brute force guess (including use quantum computer attack).\n";
				std::cout << "If you have called the encryption function or decryption function, but want to restore your 'forward' operation.\n";
				std::cout << "Please destroy the current instance and rebuild, then you can call the 'backward' operation function.\n";
			}

			std::vector<std::uint8_t> EncrypterMain(const std::vector<std::uint8_t>& PlainText, const std::vector<std::uint8_t>& Keys);
			std::vector<std::uint8_t> DecrypterMain(const std::vector<std::uint8_t>& CipherText, const std::vector<std::uint8_t>& Keys);
			std::vector<std::uint8_t> EncrypterMainWithoutPadding(const std::vector<std::uint8_t>& PlainText, const std::vector<std::uint8_t>& Keys);
			std::vector<std::uint8_t> DecrypterMainWithoutUnpadding(const std::vector<std::uint8_t>& CipherText, const std::vector<std::uint8_t>& Keys);

		private:

			OaldresPuzzle_Cryptic* AlgorithmCorePointer = nullptr;

			//检查本轮子密钥已经生成的次数的计数器
			//Counter to check the number of times the current round of subkeys has been generated
			volatile std::uint64_t RoundSubkeysCounter = 0;


			/*
				https://en.wikipedia.org/wiki/Padding_(cryptography)

				ISO 10126 specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.

				Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
			*/
			void PaddingData( std::vector<std::uint8_t>& Data ) const
			{
				using TwilightDreamOfMagical::CommonSecurity::GenerateSecureRandomNumberSeed;

				auto& DataBlockSize = AlgorithmCorePointer->StateDataPointer->OPC_QuadWord_DataBlockSize;

				std::size_t NumberRemainder = Data.size() & ( DataBlockSize * sizeof( std::uint64_t ) ) - 1;

				std::size_t NeedPaddingCount = ( DataBlockSize * sizeof( std::uint64_t ) ) - NumberRemainder;

				std::random_device								HardwareRandomDevice;
				std::mt19937									RandomNumericalGeneratorBySecureSeed( GenerateSecureRandomNumberSeed<std::size_t>( HardwareRandomDevice ) );
				CommonSecurity::RND::UniformIntegerDistribution UniformDistribution( 0, 255 );

				for ( std::size_t loopCount = 0; loopCount < NeedPaddingCount; ++loopCount )
				{
					auto		 integer = static_cast<std::uint32_t>( UniformDistribution( RandomNumericalGeneratorBySecureSeed ) );
					std::uint8_t byteData { static_cast<std::uint8_t>( integer ) };
					Data.push_back( byteData );
				}
				auto		 integer = static_cast<std::uint32_t>( NeedPaddingCount );
				std::uint8_t byteData { static_cast<std::uint8_t>( integer ) };
				Data[ Data.size() - 1 ] = byteData;
			}

			/*
				https://en.wikipedia.org/wiki/Padding_(cryptography)

				ISO 10126 specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.

				Example: In the following example the block size is 8 bytes and padding is required for 4 bytes
			*/
			void UnpaddingData( std::vector<std::uint8_t>& Data ) const
			{
				std::size_t count = static_cast<std::size_t>( Data.back() );
				while ( count-- )
				{
					Data.pop_back();
				}
			}

			/*
				分块加密数据函数
				Split block encryption data function
			*/
			void SplitDataBlockToEncrypt(std::span<std::uint64_t> PlainText, std::span<const std::uint64_t> Keys);

			/*
				分块解密数据函数
				Split block decryption data function
			*/
			void SplitDataBlockToDecrypt(std::span<std::uint64_t> CipherText, std::span<const std::uint64_t> Keys);
		};
	}  // namespace SED::BlockCipher
}  // namespace TwilightDreamOfMagical::CustomSecurity

#endif	//ALGORITHM_OALDRESPUZZLECRYPTIC_OPC_MAINALGORITHM_WORKER_HPP
