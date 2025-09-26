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

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_SECURESUBKEYGENERATATION_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_SECURESUBKEYGENERATATION_HPP

#include "Modules_OaldresPuzzle_Cryptic.hpp"
#include "Module_SubkeyMatrixOperation.hpp"
#include "CustomSecureHash.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		namespace ImplementationDetails
		{
			struct TDOM_HashModule
			{

			public:

				//This is sponge bit hash!
				CustomSecureHash CustomSecureHashObject;

				static constexpr std::uint64_t LargePrimeNumber = 18446744073709551557ULL;

				static constexpr std::uint64_t UnbiasedThreshold = std::numeric_limits<std::uint64_t>::max() - ( std::numeric_limits<std::uint64_t>::max() % LargePrimeNumber );

				/*
					@details
					https://en.wikipedia.org/wiki/Short_integer_solution_problem
					Short integer solution (SIS) and ring-SIS problems are two average-case problems that are used in lattice-based cryptography constructions.
					短整数解（SIS）和环形SIS问题是两个平均案例问题，被用于基于格子的密码学构建。

					使用短矢量查找Ajtais哈希函数中的碰撞问题
					https://crypto.stackexchange.com/questions/34400/find-collision-in-ajtais-hash-function-using-short-vector

					高效算术-哈希函数
					https://crypto.stackexchange.com/questions/61687/efficient-arithmetic-hash-function/

					什么时候开始，SIS的短整数解格子问题变得容易了？
					https://crypto.stackexchange.com/questions/71591/when-does-the-sis-short-integer-solution-lattice-problem-start-becoming-easy

					
					
					The largest prime number is that will fit into a 64-bit unsigned variable: 18446744073709551557
					
					Ajtais哈希函数:
					Original Ajtai's Hash Function Algorithm:
					```
					A is Z_p matrices (In The Prime Field)
					x and y = is input and output vector
					LargePrimeNumber = 18446744073709551557

					y = Ax (mod LargePrimeNumber)
					```

					Our Hashing algorithms resistant to quantum computing (Referenced Lattice Cryptography and Learning with Errors):
					```
					y = Ax 
					(Each Element Compute In The Prime Field) Matrix-Vector Multiplication
					y' = CustomSpongeHash(y)
					y'' = y + y' (mod LargePrimeNumber)
					```

					@return EigenLibrary column vector
				*/
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>
				SecureHash
				(
					const Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>& RandomQuadWordMatrix,
					const Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>& IntegerVector
				);

				explicit TDOM_HashModule(std::uint32_t HashBitSize)
					:
					CustomSecureHashObject(HashBitSize)
				{

				}

				~TDOM_HashModule() = default;
			};

			//模块A: 安全的生成子密钥
			//Module A: Secure generation of subkeys
			class Module_SecureSubkeyGeneratation
			{
			public:

				explicit Module_SecureSubkeyGeneratation(CommonStateData& CommonStateDataObject)
					:
					StateDataPointer(std::addressof(CommonStateDataObject)),
					SubkeyMatrixOperationObject(CommonStateDataObject)
				{
					std::uint32_t HashBitSize = static_cast<uint32_t>((StateDataPointer->OPC_KeyMatrix_Rows) * 64) / 2;
					HashObjectPointer = std::unique_ptr<TDOM_HashModule>(new TDOM_HashModule(HashBitSize));
				}

				~Module_SecureSubkeyGeneratation() = default;

				/*
					使用说明：

					字64位Word64Bit_MasterKey，一个临时存储的主密钥，是在StateData_Worker类的函数里;
					WordKeyDataVector在CommonStateData类里，大小为OPC_QuadWord_KeyBlockSize；

					主密钥未使用时，应该更新WordKeyDataVector

					如果主密钥的长度大于OPC_QuadWord_KeyBlockSize
					那么第一次从Word64Bit_MasterKey里面，直接复制这个长度的主密钥给这个WordKeyDataVector，之后记录这个偏移在主密钥(Word64Bit_MasterKey[index])，index偏移重置为0在WordKeyDataVector[index]，使用ExclusiveOr(异或)操作把主密钥应用到WordKeyDataVector。
					重复以上步骤，就可以把主密钥(Word64Bit_MasterKey)给使用完毕。

					主密钥使用完毕之后，无需更新WordKeyDataVector，直接使用这个函数

					如果主密钥的长度小于OPC_QuadWord_KeyBlockSize
					应该填充伪随机数到主密钥，直到主密钥的长度等于OPC_QuadWord_KeyBlockSize

					这个函数执行完毕之后，将会更新"变换的子密钥矩阵"

					Usage Notes.

					Word64Bit_MasterKey, a temporary storage of the master key, is in the function of the StateData_Worker class;
					WordKeyDataVector in the CommonStateData class, of size OPC_QuadWord_KeyBlockSize.

					The WordKeyDataVector should be updated when the master key is not used

					If the length of the master key is greater than OPC_QuadWord_KeyBlockSize
					then the first time from Word64Bit_MasterKey inside, directly copy this length of the master key to this WordKeyDataVector, after recording this offset in the master key (Word64Bit_MasterKey[index]), index offset reset to 0 in WordKeyDataVector[index], use exclusive-or operation to apply the master key to the WordKeyDataVector.
					Repeat the above steps, you can the master key (Word64Bit_MasterKey) to complete used.

					After the used of the master key, no need to update the WordKeyDataVector, directly using this function

					If the length of the master key is less than OPC_QuadWord_KeyBlockSize
					it should be filled with pseudo-random numbers until the length of the master key equals OPC_QuadWord_KeyBlockSize

					After this function is executed, the "transformed subkey matrix" will be updated
				*/
				void GenerationSubkeys(std::span<const std::uint64_t> WordKeyDataVector);

			private:
				std::unique_ptr<TDOM_HashModule> HashObjectPointer = nullptr;
				Module_SubkeyMatrixOperation SubkeyMatrixOperationObject;

				CommonStateData* StateDataPointer = nullptr;

				void LatticeCryptographyAndHash(std::span<const std::uint64_t> Input, std::span<std::uint64_t> Output);
			};
		}
	}
}


#endif //ALGORITHM_OALDRESPUZZLECRYPTIC_MODULE_SECURESUBKEYGENERATATION_HPP
