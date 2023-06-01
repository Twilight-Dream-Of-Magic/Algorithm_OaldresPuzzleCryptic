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

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_SECUREROUNDSUBKEYGENERATATION_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_SECUREROUNDSUBKEYGENERATATION_HPP

#include "Modules_OaldresPuzzle_Cryptic.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		namespace ImplementationDetails
		{
			//模块B: 安全的生成每轮混合子密钥
			//Module B: Securely generate mixed subkeys for each round
			class Module_SecureRoundSubkeyGeneratation
			{

			public:
				explicit Module_SecureRoundSubkeyGeneratation( CommonStateData& CommonStateDataObject )
					:
					StateDataPointer( std::addressof( CommonStateDataObject ) )
				{
					GeneratedRoundSubkeyMatrix = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>::Zero( StateDataPointer->OPC_KeyMatrix_Rows, StateDataPointer->OPC_KeyMatrix_Columns );
					GeneratedRoundSubkeyVector = std::vector<std::uint64_t>( StateDataPointer->OPC_KeyMatrix_Rows * StateDataPointer->OPC_KeyMatrix_Columns, 0 );
				}

				~Module_SecureRoundSubkeyGeneratation()
				{
					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedRoundSubkeyVector.data(), GeneratedRoundSubkeyVector.size() * sizeof( std::uint64_t ) );
					CheckPointer = nullptr;

					GeneratedRoundSubkeyMatrix.setZero();
				}

				//将旧的QuadWord子密钥矩阵以及用于轮函数的QuadWord子密钥矩阵，进行单向变换和运算，并生成新的QuadWord子密钥矩阵和子密钥向量，并作为轮函数的RoundSubkey使用
				//Take the old QuadWord subkey matrix and the QuadWord subkey matrix used for the round function, perform one-way transformation and operation, and generate a new QuadWord subkey matrix and subkey vector, and use them as the RoundSubkey of the round function
				void GenerationRoundSubkeys();

				/*
					The following functions will be used for the structure of the Lai-Massey scheme
					以下函数将会给Lai–Massey scheme的结构使用

				    H-functions and F-function
				*/

				std::array<std::uint32_t, 2> ForwardTransform( std::uint32_t LeftWordData, std::uint32_t RightWordData );

				std::array<std::uint32_t, 2> BackwardTransform( std::uint32_t LeftWordData, std::uint32_t RightWordData );

				/*
					使用生成的伪随机数序列对相关(字)进行疯狂比特变换
					Crazy bit transformation of the correlation (word) using the generated pseudo-random number sequence
				*/
				std::uint32_t CrazyTransformAssociatedWord( std::uint32_t AssociatedWordData, const std::uint64_t WordKeyMaterial );

				auto& UseRoundSubkeyVectorReference()
				{
					return this->GeneratedRoundSubkeyVector;
				}

			private:
				CommonStateData* StateDataPointer = nullptr;

				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>
				//生成的轮函数的子密钥的矩阵(来自变换后的子密钥矩阵)
				//The subkey of the generated round function (from the transformed subkey matrix)
				GeneratedRoundSubkeyMatrix;

				std::vector<std::uint64_t>
				//生成的轮函数的子密钥向量(来自生成的轮函数的子密钥的矩阵)
				//Generated subkey (from the transformed key matrix)
				GeneratedRoundSubkeyVector;

				std::uint64_t MatrixTransformationCounter = 0;

				//奥尔德雷斯之谜 - 不可预测的矩阵变换
				//OaldresPuzzle-Cryptic - Unpredictable matrix transformation
				void OPC_MatrixTransformation();
			};
		}  // namespace ImplementationDetails
	}	   // namespace SED::BlockCipher
}  // namespace TwilightDreamOfMagical::CustomSecurity

#endif	//ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_SECUREROUNDSUBKEYGENERATATION_HPP
