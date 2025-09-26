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

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_MIXTRANSFORMATIONUTIL_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_MIXTRANSFORMATIONUTIL_HPP

#include "Modules_OaldresPuzzle_Cryptic.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		namespace ImplementationDetails
		{
			//Part of the OaldresPuzzle_Cryptic algorithm - implementation of the hybrid transformation
			//OaldresPuzzle_Cryptic算法的一部分--混合转换的实现
			class Module_MixTransformationUtil
			{

			public:
				// Friend declaration doesn't need to be templated here
				friend class Module_SubkeyMatrixOperation;

				explicit Module_MixTransformationUtil( CommonStateData& CommonStateDataObject )
					:
					StateDataPointer( std::addressof( CommonStateDataObject ) )
				{}

				~Module_MixTransformationUtil()
				{
					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>( this->Word32Bit_StateRegisters.data(), this->Word32Bit_StateRegisters.size() * sizeof( std::uint32_t ) );
					my_cpp2020_assert( CheckPointer == this->Word32Bit_StateRegisters.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current() );
					CheckPointer = nullptr;
				}

				void Word32Bit_Initialize();

				/*
					该算法思路参考了中国商用流密码，祖冲之的混合变换轮函数
					The algorithm is referenced from the Chinese commercial stream cipher, Zu Chongzhi's mix transform round function

					非线性变换和线性变换函数
					Nonlinear transformations and linear transformation functions
				*/
				std::uint32_t Word32Bit_KeyWithFunction( std::span<const std::uint32_t> RandomWordDataMaterial );

				/*
					Word数据比特的混淆和扩散，然后扩展序列的大小
					Word data bits are obfuscated and spread, and then the size of the sequence is expanded
				*/
				std::vector<std::uint32_t> Word32Bit_ExpandKey( std::span<const std::uint32_t> NeedHashDataWords );

			private:
				CommonStateData* StateDataPointer = nullptr;

				std::array<std::uint32_t, 2> Word32Bit_StateRegisters { 0, 0 };

				/*
					单比特的重组，混淆设计方案 (字 密钥)， 由Twilight-Dream 设计
					Single-bit restructuring, confusion design scheme (Word key), designed by Twilight-Dream

					std::uint32_t (Bit 32)
					00 01 02 0B 0A 03 04 05
					0F 00 06 07 08 09 05 0C 
					0C 0D 01 0A 0B 04 0E 0F 
					06 07 0E 02 03 0D 08 09

					Color groups by seed row (min index in the pair):
					// Green (Row0 bits 00..07)
					  00 09 | 09 00
					  01 12 | 12 01
					  02 1B | 1B 02
					  03 14 | 14 03
					  04 13 | 13 04
					  05 1C | 1C 05
					  06 15 | 15 06
					  07 0E | 0E 07
					// Blue (Row1 bits 08..0F)
					  08 17 | 17 08
					  0A 18 | 18 0A
					  0B 19 | 19 0B
					  0C 1E | 1E 0C
					  0D 1F | 1F 0D
					  0F 10 | 10 0F
					// Red (Row2 bits 10..17)
					  11 1D | 1D 11
					  16 1A | 1A 16
				*/
				std::uint32_t WordBitRestruct( std::uint32_t WordKey );

				std::uint32_t SwapBits( std::uint32_t Word, std::uint32_t BitPosition, std::uint32_t BitPosition2 );
			};

		}  // namespace ImplementationDetails
	}	   // namespace SED::BlockCipher
}  // namespace TwilightDreamOfMagical::CustomSecurity


#endif	//ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_MIXTRANSFORMATIONUTIL_HPP
