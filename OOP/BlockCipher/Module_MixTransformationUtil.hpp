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
			template <std::integral DataType, std::size_t ArraySize>
			class SegmentTree
			{
				/*
					std::has_single_bit(ArraySize)
					ArraySize != 0 && (ArraySize ^ (ArraySize & -ArraySize) == 0)
				*/

			private:
				static constexpr std::size_t N = std::has_single_bit( ArraySize ) ? ArraySize : 0;
				std::array<DataType, N << 1> Nodes {};

			public:
				void Set( std::size_t Position )
				{
					for ( std::size_t CurrentNode = N | Position; CurrentNode; CurrentNode >>= 1 )
						this->Nodes[ CurrentNode ]++;
				}

				DataType Get( std::size_t Order )
				{
					std::size_t CurrentNode = 1;
					for ( std::size_t CurrentLeftSize = N >> 1, LeftTotal = 0; CurrentLeftSize; CurrentLeftSize >>= 1 )
					{
						std::size_t CurrentLeftCount = CurrentLeftSize - this->Nodes[ CurrentNode << 1 ];
						if ( LeftTotal + CurrentLeftCount > Order )
							CurrentNode = CurrentNode << 1;
						else
							CurrentNode = CurrentNode << 1 | 1, LeftTotal += CurrentLeftCount;
					}
					return static_cast<DataType>( CurrentNode ^ N );
				}

				void Clear()
				{
					volatile void* CheckPointer = nullptr;
					CheckPointer = memory_set_no_optimize_function<0x00>( this->Nodes.data(), this->Nodes.size() * sizeof( DataType ) );
					CheckPointer = nullptr;
				}

				~SegmentTree()
				{
					volatile void* CheckPointer = nullptr;
					CheckPointer = memory_set_no_optimize_function<0x00>( this->Nodes.data(), this->Nodes.size() * sizeof( DataType ) );
					CheckPointer = nullptr;
				}
			};

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

					CheckPointer = memory_set_no_optimize_function<0x00>( this->MaterialSubstitutionBox0.data(), this->MaterialSubstitutionBox0.size() );
					my_cpp2020_assert( CheckPointer == this->MaterialSubstitutionBox0.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current() );
					CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>( this->MaterialSubstitutionBox1.data(), this->MaterialSubstitutionBox1.size() );
					my_cpp2020_assert( CheckPointer == this->MaterialSubstitutionBox1.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current() );
					CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>( this->Word32Bit_StreamCipherStateRegisters.data(), this->Word32Bit_StreamCipherStateRegisters.size() * sizeof( std::uint32_t ) );
					my_cpp2020_assert( CheckPointer == this->Word32Bit_StreamCipherStateRegisters.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current() );
					CheckPointer = nullptr;
				}

				void Word32Bit_Initialize();

				/*
					该算法参考了中国商用流密码，祖冲之的混合变换轮函数
					The algorithm is referenced from the Chinese commercial stream cipher, Zu Chongzhi's mix transform round function

					非线性变换和线性变换函数
					Nonlinear transformations and linear transformation functions
				*/
				std::uint32_t Word32Bit_KeyWithStreamCipherFunction( std::span<const std::uint32_t> RandomWordDataMaterial );

				/*
					Word数据比特的混淆和扩散，然后扩展序列的大小
					Word data bits are obfuscated and spread, and then the size of the sequence is expanded
				*/
				std::vector<std::uint32_t> Word32Bit_ExpandKey( std::span<const std::uint32_t> NeedHashDataWords );

			private:
				CommonStateData* StateDataPointer = nullptr;

				//Part of the Chinese ZUC stream cipher modified by Twilight-Dream
				//This does not use the original Chinese ZUC stream cipher algorithm, nor does it use the linear feedback shift register of the original algorithm
				//由Twilight-Dream修改的中国ZUC流密码的一部分
				//这不是使用原始的中国ZUC流密码算法，也不使用原算法的线性反馈移位寄存器

				/*
					This byte-substitution box: Strict avalanche criterion is satisfied !
					ByteDataSecurityTestData Transparency Order Is: 7.81299
					ByteDataSecurityTestData Nonlinearity Is: 94
					ByteDataSecurityTestData Propagation Characteristics Is: 8
					ByteDataSecurityTestData Delta Uniformity Is: 10
					ByteDataSecurityTestData Robustness Is: 0.960938
					ByteDataSecurityTestData Signal To Noise Ratio/Differential Power Analysis Is: 9.29288
					ByteDataSecurityTestData Absolute Value Indicatorer Is: 120
					ByteDataSecurityTestData Sum Of Square Value Indicator Is: 244160
					ByteDataSecurityTestData Algebraic Degree Is: 8
					ByteDataSecurityTestData Algebraic Immunity Degree Is: 4
				*/
				std::array<std::uint8_t, 256> MaterialSubstitutionBox0
				{
					0xF4, 0x53, 0x75, 0x96, 0xBE, 0x6F, 0x66, 0x11, 0x80, 0xC8, 0x5C, 0xDF, 0xF7, 0xAE, 0xC6, 0x93,
					0xF1, 0x2F, 0x5F, 0x47, 0xB8, 0xF2, 0x71, 0x30, 0x1E, 0x87, 0x32, 0x0A, 0xCA, 0x6E, 0x16, 0xCB,
					0x65, 0x2C, 0x35, 0x0D, 0x8C, 0x1C, 0x3A, 0xA8, 0xC4, 0x84, 0xC7, 0x46, 0x0B, 0xCE, 0xFC, 0xB1,
					0x62, 0x5A, 0x59, 0x6D, 0x42, 0x3D, 0xA9, 0xAA, 0xD6, 0x14, 0x88, 0x02, 0xE8, 0x82, 0x9A, 0x7E,
					0xF6, 0x9E, 0x43, 0x27, 0x33, 0x4C, 0x57, 0x01, 0x8B, 0x25, 0x79, 0xB0, 0x18, 0xB9, 0xB2, 0x9D,
					0xAF, 0x0E, 0xD4, 0xE1, 0x2E, 0x0C, 0xDB, 0x8E, 0x1D, 0xE2, 0x00, 0x51, 0xB3, 0xF3, 0x7F, 0x99,
					0xA5, 0xCD, 0x77, 0xB4, 0xD9, 0x61, 0x76, 0x70, 0x40, 0x9F, 0x5E, 0xFF, 0x4D, 0xF9, 0x86, 0xAB,
					0xD3, 0x41, 0xB5, 0x2B, 0xA1, 0x39, 0x63, 0xC9, 0x6C, 0x73, 0x9B, 0xBB, 0x7B, 0xD0, 0xAD, 0x7C,
					0xEE, 0xDE, 0xF8, 0xD8, 0xB6, 0xED, 0x98, 0x19, 0xFA, 0x8F, 0x92, 0xAC, 0x12, 0xC2, 0x05, 0xCF,
					0xC0, 0xEF, 0x08, 0xFE, 0xDD, 0x50, 0x23, 0x4B, 0xC3, 0x15, 0xE5, 0xD5, 0x3E, 0xE0, 0x2A, 0x52,
					0x95, 0x44, 0x72, 0x56, 0x0F, 0x1B, 0xF5, 0x90, 0xE3, 0x58, 0x69, 0x8D, 0x48, 0x26, 0xD2, 0xA2,
					0x7A, 0x38, 0x49, 0xEC, 0x13, 0x67, 0x07, 0x81, 0xE9, 0xD1, 0x34, 0x36, 0x85, 0xA3, 0x5D, 0x22,
					0x24, 0x6B, 0xBA, 0x37, 0x7D, 0xBF, 0x6A, 0x2D, 0x45, 0x3C, 0x55, 0x5B, 0x74, 0xF0, 0xDA, 0x83,
					0xDC, 0x4A, 0x91, 0x31, 0x97, 0xA4, 0xE6, 0x1A, 0x1F, 0x4F, 0xC5, 0x54, 0xFD, 0x17, 0x06, 0x89,
					0x60, 0xA6, 0xB7, 0x3B, 0xA7, 0xFB, 0x78, 0x94, 0xBD, 0xA0, 0xE7, 0xD7, 0xEB, 0x21, 0xE4, 0xEA,
					0x09, 0xC1, 0x03, 0xBC, 0xCC, 0x68, 0x20, 0x04, 0x28, 0x9C, 0x4E, 0x3F, 0x10, 0x29, 0x8A, 0x64,
				};

				/*
					This byte-substitution box: Strict avalanche criterion is satisfied !
					ByteDataSecurityTestData Transparency Order Is: 7.80907
					ByteDataSecurityTestData Nonlinearity Is: 94
					ByteDataSecurityTestData Propagation Characteristics Is: 8
					ByteDataSecurityTestData Delta Uniformity Is: 12
					ByteDataSecurityTestData Robustness Is: 0.953125
					ByteDataSecurityTestData Signal To Noise Ratio/Differential Power Analysis Is: 9.25523
					ByteDataSecurityTestData Absolute Value Indicatorer Is: 96
					ByteDataSecurityTestData Sum Of Square Value Indicator Is: 199424
					ByteDataSecurityTestData Algebraic Degree Is: 8
					ByteDataSecurityTestData Algebraic Immunity Degree Is: 4
				*/
				std::array<std::uint8_t, 256> MaterialSubstitutionBox1
				{
					0x88, 0xB4, 0x21, 0xF9, 0xC9, 0xBC, 0x7C, 0x5D, 0xAB, 0x7D, 0x04, 0x69, 0x96, 0x8E, 0x00, 0x71,
					0x94, 0xB0, 0xFB, 0xE1, 0xD6, 0xA2, 0xD5, 0xE6, 0x74, 0x6C, 0xB9, 0x31, 0xAE, 0xDD, 0x49, 0x19,
					0x02, 0x75, 0x34, 0x33, 0x46, 0x0A, 0xA9, 0x54, 0x1F, 0x5F, 0xCA, 0x56, 0xD2, 0xD8, 0x41, 0xD9,
					0x0D, 0x47, 0xF0, 0xB3, 0x62, 0x8F, 0x52, 0x08, 0x3F, 0x4C, 0x84, 0x1C, 0xA8, 0x3A, 0x7A, 0xCE,
					0x22, 0x2C, 0x1B, 0x4D, 0xFA, 0x30, 0x2F, 0x80, 0x3B, 0x55, 0x91, 0x05, 0x61, 0x03, 0x64, 0x87,
					0xFF, 0xE0, 0x26, 0xBE, 0x68, 0x0E, 0x50, 0xC3, 0x29, 0x42, 0x6F, 0x2B, 0x53, 0x79, 0xB5, 0x27,
					0x77, 0x97, 0x32, 0x38, 0x07, 0xBB, 0xF7, 0xF5, 0x28, 0x11, 0x36, 0x9B, 0x5C, 0x81, 0x65, 0x6A,
					0xEB, 0xE5, 0x17, 0xF4, 0x3C, 0xE9, 0x39, 0x58, 0xF8, 0x66, 0x15, 0xC6, 0xA4, 0xEA, 0xE2, 0xDF,
					0xCC, 0xFD, 0x3D, 0xEF, 0x1A, 0x24, 0x4A, 0xBF, 0xB6, 0x67, 0xF6, 0x45, 0xB7, 0x4B, 0xB2, 0x5E,
					0x60, 0x7F, 0x89, 0x76, 0xD4, 0x59, 0xE4, 0xAD, 0xCB, 0xA3, 0xFC, 0x7B, 0xBD, 0x35, 0x51, 0xC7,
					0xA0, 0xA1, 0x8C, 0x13, 0x83, 0xA5, 0xCF, 0x44, 0x95, 0xDE, 0x9E, 0xF3, 0x1D, 0x40, 0x2E, 0x0F,
					0x72, 0xD0, 0x6E, 0x8A, 0xAF, 0x6D, 0x16, 0xC1, 0xE7, 0x43, 0x8B, 0x9C, 0x4F, 0x82, 0x10, 0xDA,
					0x57, 0x0C, 0xCD, 0x63, 0x9F, 0xBA, 0x0B, 0x4E, 0x90, 0x93, 0xAA, 0xF2, 0xC0, 0x20, 0x14, 0x78,
					0xEE, 0xA7, 0x85, 0x3E, 0x5A, 0x2D, 0x01, 0xED, 0xC4, 0xAC, 0x25, 0x73, 0x5B, 0x98, 0x06, 0xEC,
					0xDC, 0x12, 0xB8, 0xD3, 0xD7, 0xC5, 0xE3, 0x9A, 0xF1, 0xD1, 0xE8, 0x6B, 0xB1, 0x48, 0xFE, 0x86,
					0x70, 0xA6, 0x9D, 0x18, 0xC2, 0x99, 0x1E, 0x09, 0x7E, 0x37, 0x2A, 0xDB, 0x8D, 0xC8, 0x23, 0x92,
				};

				std::array<std::uint32_t, 2> Word32Bit_StreamCipherStateRegisters { 0, 0 };

				/*
					单比特的重组，混淆设计方案 (字 密钥)， 由Twilight-Dream 设计
					Single-bit restructuring, confusion design scheme (Word key), designed by Twilight-Dream

					std::uint32_t (Bit 32)
					0 0 0 0 0 0 0 0
					0 0 0 0 0 0 0 0
					0 0 0 0 0 0 0 0
					0 0 0 0 0 0 0 0

					//Green Step
					Bit 0 swap Bit 9
					Bit 1 swap Bit 18
					Bit 2 swap Bit 27

					Bit 5 swap Bit 28
					Bit 6 swap Bit 21
					Bit 7 swap Bit 14

					//Orange Step
					Bit 10 swap Bit 24
					Bit 11 swap Bit 25
					Bit 12 swap Bit 30
					Bit 13 swap Bit 31

					//Red Step
					Bit 19 swap Bit 4
					Bit 20 swap Bit 3

					//Yellow Step
					Bit 17 swap Bit 2
					Bit 22 swap Bit 5

					//Blue Step
					Bit 27 swap Bit 15
					Bit 28 swap Bit 9
				*/
				std::uint32_t WordBitRestruct( std::uint32_t WordKey );

				std::uint32_t SwapBits( std::uint32_t Word, std::uint32_t BitPosition, std::uint32_t BitPosition2 );

				std::array<std::uint8_t, 256> RegenerationRandomMaterialSubstitutionBox( std::span<const std::uint8_t> OldDataBox );

				void RegenerationRandomMaterialSubstitutionBox()
				{
					//Regenerate material substitution boxes
					//重新生成材料替代箱
					MaterialSubstitutionBox0 = this->RegenerationRandomMaterialSubstitutionBox( MaterialSubstitutionBox0 );
					MaterialSubstitutionBox1 = this->RegenerationRandomMaterialSubstitutionBox( MaterialSubstitutionBox1 );
				}
			};

		}  // namespace ImplementationDetails
	}	   // namespace SED::BlockCipher
}  // namespace TwilightDreamOfMagical::CustomSecurity


#endif	//ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_MIXTRANSFORMATIONUTIL_HPP
