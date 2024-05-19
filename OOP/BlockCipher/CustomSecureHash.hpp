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

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_CUSTOMSECUREHASH_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_CUSTOMSECUREHASH_HPP

#include "../../BitRotation.hpp"
#include "Includes/PRNGs.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		namespace ImplementationDetails
		{
			/*
				https://en.wikipedia.org/wiki/Sponge_function

				基于海绵结构的密码学哈希函数，使用的伪随机置换函数由Twilight-Dream设计
				Cryptographic hash function based on sponge structure using a pseudo-random permutation function designed by Twilight-Dream

				Reference: https://locklessinc-com.translate.goog/articles/crypto_hash/?_x_tr_sl=en&_x_tr_tl=zh-CN&_x_tr_hl=zh-CN&_x_tr_pto=sc
			*/
			class CustomSecureHash
			{

			private:

				/*
					哈希状态比特大小=比特率大小+比特容量大小

					例子:
					海绵函数的安全性取决于其内部状态的长度和块的长度。
					如果信息块的长度为r位，内部状态的长度为w位，那么有c = w - r位的内部状态不能被信息块所修改。
					c的值被称为海绵的容量，海绵函数所保证的安全级别是c/2。例如，要达到256位的安全与64位的消息块，内部状态应该是w=2×256+64=576位。
					当然，安全级别也取决于哈希值的长度n。因此，碰撞攻击的复杂性是2^{n/2}和2^{c/2}之间的最小值，而第二次预像攻击的复杂性是2^n和2^{c/2}之间的最小值。

					为了安全起见，排列组合P应该表现得像一个随机排列组合，没有统计上的偏差，也没有让攻击者预测输出的数学结构。
					与基于压缩函数的哈希值一样，海绵函数也会对信息进行填充，但填充更简单，因为它不需要包括信息的长度。
					最后一个信息位只是由一个1位和尽可能多的0跟在后面。

					Hash state bits size =  Bits rate size + Bits capacity size

					Example :
					The security of a sponge function depends on the length of its internal state and the length of the blocks.
					If message blocks are r-bit long and the internal state is w-bit long, then there are c = w – r bits of the internal state that can’t be modified by message blocks.
					The value of c is called a sponge’s capacity, and the security level guaranteed by the sponge function is c/2. For example, to reach 256-bit security with 64-bit message blocks, the internal state should be w = 2 × 256 + 64 = 576 bits.
					Of course, the security level also depends on the length, n, of the hash value. The complexity of a collision attack is therefore the smallest value between 2^{n/2} and 2^{c/2}, while the complexity of a second preimage attack is the smallest value between 2^n and 2^{c/2}.

					To be secure, the permutation P should behave like a random permutation, without statistical bias and without a mathematical structure that would allow an attacker to predict outputs.
					As in compression function–based hashes, sponge functions also pad messages, but the padding is simpler because it doesn’t need to include the message’s length.
					The last message bit is simply followed by a 1 bit and as many zeroes as necessary.
				*/

				const std::uint64_t HashBitSize;
				const std::uint64_t BITS_STATE_SIZE = 2 * HashBitSize + std::numeric_limits<std::uint64_t>::digits;
				const std::uint64_t BITS_RATE = HashBitSize;
				const std::uint64_t BITS_CAPACITY = BITS_STATE_SIZE - BITS_RATE;

				const std::uint64_t BYTES_RATE = BITS_RATE / std::numeric_limits<std::uint8_t>::digits;
				const std::uint64_t BITWORDS_RATE = BYTES_RATE / sizeof(std::uint64_t);
				const std::uint64_t BYTES_CAPACITY = BITS_CAPACITY / std::numeric_limits<std::uint8_t>::digits;
				const std::uint64_t BITWORDS_CAPACITY = BYTES_CAPACITY / sizeof(std::uint64_t);

				static constexpr std::uint8_t PAD_BYTE_DATA = 0b00000001;
				static constexpr std::uint64_t PAD_BITSWORD_DATA = 0b0000000100000001000000010000000100000001000000010000000100000001;

				std::vector<std::uint64_t> BitsHashState = std::vector<std::uint64_t>(BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits, 0);

				const std::array<std::uint32_t, 63> MoveBitCounts {};
				const std::vector<std::uint32_t> HashStateIndices = std::vector<std::uint32_t>(BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits, 0);

				std::vector<std::uint32_t> LeftRotatedStateBufferIndices = std::vector<std::uint32_t>(BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2, 0);
				std::vector<std::uint32_t> RightRotatedStateBufferIndices = std::vector<std::uint32_t>(BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2, 0);

				std::size_t StateCurrentCounter = 1;

				/*
					这里的伪随机数来源，可以是大素数的立方根或者平方根所生成的比特位，也可以是无理数所生成的比特位，也可以是严格设计的比特掩码
					The source of the pseudo-random numbers here can be the bits generated by the cube root or square root of a large prime number, the bits generated by an irrational number, or a strictly designed bit mask
				*/
				static constexpr std::array<std::uint64_t, 64> HASH_ROUND_CONSTANTS
				{
					0xe02d51d52e6988abULL,0xfc48780c20090b50ULL,0xc6144c4d89151352ULL,0xb98669bb3a32a8f1ULL,0xd4786928fe033c03ULL,0xaebb38f01d73faabULL,0x936cb166f1ff8493ULL,0x60310a07294f5dc8ULL,
					0x06d5b3dbf088ae77ULL,0x7e2be74e7f525e23ULL,0xe5459a079549e2e3ULL,0x352ba71a6a95e6d6ULL,0x7b40c16d92d5e43bULL,0xa559af839ba27363ULL,0x985236a57aa17c27ULL,0xf4be83da5a08c659ULL,
					0x9ab94838ff7737c6ULL,0x718d70cd883014f9ULL,0x0bda9af50ba21d4dULL,0xd88cb07c07a814d5ULL,0xa6c8d66f9b3d8933ULL,0x80643413e011c839ULL,0x5456e69b40922372ULL,0x86a8e11d2e20eb52ULL,
					0x19224d7b455813b1ULL,0xb1dbd44f138bac7fULL,0x2ba9107bb26a6134ULL,0x48297fe2c4167b76ULL,0x776528a5edb8a68eULL,0x2381e0eb054681a8ULL,0x41a27b65af8e39bfULL,0xeda2847d88303971ULL,
					0x655f38e3d5446574ULL,0xd8093b5a1172958cULL,0x28880627fe4c014bULL,0x0459d6592d1b2b51ULL,0x2aeb8df1c83b63beULL,0xcba3ca8c513a8205ULL,0xa4967565ebf34510ULL,0x1041efcb786f9e59ULL,
					0xdf8ee44352384448ULL,0xff38527afa3b13a2ULL,0x9ff904a86c03fe22ULL,0xe81a56aef956f93fULL,0x3c13136bf0612494ULL,0xca9b0621705e9748ULL,0xe89292acf259cef1ULL,0x373480242c1c5effULL,
					0xd249f4efd3685008ULL,0xda2779c07b0e4a43ULL,0x1cc1bd402438ea81ULL,0x7b090a135f97ba29ULL,0xd25e80bc98b09e4bULL,0xeea820f2885ac1f8ULL,0x939c9063e5bdc233ULL,0x01c1b92d1ed7777bULL,
					0x75208f3a3cb244dfULL,0x20f74f61571512b4ULL,0xfd526ef256343eb7ULL,0x753082ea79791d09ULL,0x41a3a000a8c7ae30ULL,0xb2a056be3a257d27ULL,0x152a2da04d5f2393ULL,0x99dba5727ec6dabbULL
				};

				std::array<std::uint32_t, 63>
				GenerateRandomMoveBitCounts()
				{
					//0110 1110 1010 0011 1000 1101 1111 1011 1000 1001 1011 0010 1101
					CSPRNG::ISAAC::isaac64<8> isaac = CSPRNG::ISAAC::isaac64<8>(1946379852749613ULL);

					isaac.discard(1024);

					std::array<std::uint32_t, 63> MoveBitCounts {};

					std::iota(MoveBitCounts.begin(), MoveBitCounts.end(), 1);

					for(std::uint64_t Index = 0; Index < MoveBitCounts.size(); ++Index)
					{
						std::swap(MoveBitCounts[Index], MoveBitCounts[(Index + isaac()) % MoveBitCounts.size()]);
					}

					return MoveBitCounts;
				}

				std::vector<std::uint32_t>
				GenerateRandomHashStateIndices()
				{
					//0110 1110 1010 0011 1000 1101 1111 1011 1000 1001 1011 0010 1101
					CSPRNG::ISAAC::isaac64<8> isaac = CSPRNG::ISAAC::isaac64<8>(1946379852749613ULL);

					isaac.discard(2048);

					std::vector<std::uint32_t> RandomHashStateIndices(BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2, 0);

					std::iota(RandomHashStateIndices.begin(), RandomHashStateIndices.end(), 0);

					for(std::uint64_t Index = 0; Index < RandomHashStateIndices.size(); ++Index)
					{
						std::swap(RandomHashStateIndices[Index], RandomHashStateIndices[(Index + isaac()) % RandomHashStateIndices.size()]);
					}

					return RandomHashStateIndices;
				}

				/*
					这个对应了海绵函数结构中的数学抽象的F函数(它应该是一个安全的伪随机置换函数)。

					它有以下几个步骤:
					1.哈希状态混合
					2.应用线性函数
					3.应用比特伪随机置换 (P函数)
					4.应用非线性函数
					5.每一轮需要哈希状态和哈希使用的常量进行混合

					This corresponds to the mathematical abstraction of the F function in the structure of the sponge function (it is supposed to be a safe pseudo-random permutation function).

					It has the following steps:
					1. Hash state mixing
					2. Apply linear function
					3. Apply bit pseudo-random permutation (P function)
					4. Apply nonlinear functions
					5. Each round requires a mix of hash state and constants used by the hash
				*/
				void TransfromState(std::size_t Counter)
				{
					using TwilightDreamOfMagical::BaseOperation::rotate_left;
					using TwilightDreamOfMagical::BaseOperation::rotate_right;

					std::vector<std::uint64_t> StateBuffer(BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2, 0);
					std::vector<std::uint64_t> StateBuffer2(BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2, 0);
					std::vector<std::uint64_t> StateBuffer3(BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2, 0);

					for(std::size_t RoundIndex = BitsHashState.size() - 1 - Counter; RoundIndex < BitsHashState.size(); ++RoundIndex)
					{
						//Step 1
						while(StateCurrentCounter % BitsHashState.size() != 0)
						{
							StateBuffer[StateCurrentCounter % StateBuffer.size()] = BitsHashState[StateCurrentCounter % BitsHashState.size()] ^ BitsHashState[(StateCurrentCounter + 1) % BitsHashState.size()];
							++StateCurrentCounter;
							StateBuffer[StateCurrentCounter % StateBuffer.size()] = BitsHashState[(StateCurrentCounter + 2) % BitsHashState.size()] ^ BitsHashState[(StateCurrentCounter + 3) % BitsHashState.size()];
							++StateCurrentCounter;
						}

						//Step 2
						for(std::size_t StateBufferIndex = 0; StateBufferIndex < BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2; ++StateBufferIndex)
						{
							StateBuffer2[StateBufferIndex] = StateBuffer[RightRotatedStateBufferIndices[StateBufferIndex]] ^ rotate_right(StateBuffer[LeftRotatedStateBufferIndices[StateBufferIndex]], 1);
						}

						//Step 3
						StateBuffer3[0] = BitsHashState[0] ^ StateBuffer2[0];

						for(std::size_t StateBufferIndex = 1; StateBufferIndex < StateBuffer3.size(); ++StateBufferIndex)
						{
							StateBuffer3[HashStateIndices[StateBufferIndex]] = rotate_right(BitsHashState[StateBufferIndex] ^ StateBuffer2[StateBufferIndex % StateBuffer2.size()], MoveBitCounts[StateCurrentCounter % MoveBitCounts.size()]);
							++StateCurrentCounter;
						}

						//Step 4
						for(std::size_t StateBufferIndex = 0; StateBufferIndex < StateBuffer3.size(); ++StateBufferIndex)
						{
							BitsHashState[StateBufferIndex] = StateBuffer3[StateBufferIndex] ^ ( ~(StateBuffer3[(StateBufferIndex + 1) % StateBuffer3.size()]) & StateBuffer3[(StateBufferIndex + 2) % StateBuffer3.size()] );
						}

						//Step 5
						BitsHashState[0] ^= HASH_ROUND_CONSTANTS[RoundIndex % HASH_ROUND_CONSTANTS.size()];
						BitsHashState[BitsHashState.size() - 1] ^= HASH_ROUND_CONSTANTS[(HASH_ROUND_CONSTANTS.size() - 1 - RoundIndex) % HASH_ROUND_CONSTANTS.size()];
					}
				}

				void AbsorbInputData(std::span<const std::uint8_t> ByteDatas)
				{
					using CommonToolkit::IntegerExchangeBytes::MessagePacking;

					std::vector<std::uint64_t> BitWords(ByteDatas.size() / sizeof(std::uint64_t), 0);

					MessagePacking<std::uint64_t, std::uint8_t>(ByteDatas, BitWords.data());

					for(std::uint64_t InputBytesIndex = 0, OutputBytesIndex = 0; OutputBytesIndex < BitWords.size(); ++InputBytesIndex, ++OutputBytesIndex)
					{
						if(InputBytesIndex >= BITWORDS_RATE)
							InputBytesIndex = 0;
						BitsHashState[InputBytesIndex] ^= BitWords[OutputBytesIndex];

						//状态排列和变换(信息熵池搅拌)
						//State permutation and transformation (string of information entropy pool)
						this->TransfromState(BitsHashState.size());
					}

					memory_set_no_optimize_function<0x00>(BitWords.data(), BitWords.size() * sizeof(std::uint64_t));
				}

				void AbsorbInputData(std::span<const std::uint64_t> BitWordDatas)
				{
					for(std::uint64_t InputBitsIndex = 0, OutputBitsIndex = 0; OutputBitsIndex < BitWordDatas.size(); ++InputBitsIndex, ++OutputBitsIndex)
					{
						if(InputBitsIndex >= BITWORDS_RATE)
							InputBitsIndex = 0;
						BitsHashState[InputBitsIndex] ^= BitWordDatas[OutputBitsIndex];

						//状态排列和变换(信息熵池搅拌)
						//State permutation and transformation (string of information entropy pool)
						this->TransfromState(BitsHashState.size());
					}
				}

				void SqueezeOutputData(std::span<std::uint8_t> ByteDatas)
				{
					using CommonToolkit::IntegerExchangeBytes::MessageUnpacking;

					std::vector<std::uint64_t> BitWords(HashBitSize / std::numeric_limits<std::uint64_t>::digits, 0);
					
					size_t BitsIndexOffest = 0;
					
					for(std::uint64_t BitsIndex = 0; BitsIndex < BitWords.size(); ++BitsIndex)
					{
						BitWords[BitsIndex] = BitsHashState[BitsIndexOffest];
						
						if(BitsIndexOffest >= BITWORDS_RATE)
						{
							//状态排列和变换(信息熵池搅拌)
							//State permutation and transformation (string of information entropy pool)
							this->TransfromState(BitsHashState.size());
							
							BitsIndexOffest = 0;
						}
					}

					MessageUnpacking<std::uint64_t, std::uint8_t>(BitWords, ByteDatas.data());
				}

				void SqueezeOutputData(std::span<std::uint64_t> WordDatas)
				{
					size_t BitsIndexOffest = 0;
				
					for(std::uint64_t BitsIndex = 0; BitsIndex < (HashBitSize / std::numeric_limits<std::uint64_t>::digits); ++BitsIndex)
					{
						WordDatas[BitsIndex] = BitsHashState[BitsIndexOffest];
						
						if(BitsIndexOffest >= BITWORDS_RATE)
						{
							//状态排列和变换(信息熵池搅拌)
							//State permutation and transformation (string of information entropy pool)
							this->TransfromState(BitsHashState.size());
							
							BitsIndexOffest = 0;
						}
					}
				}

			public:

				void Reset()
				{
					this->StateCurrentCounter = 0;
					memory_set_no_optimize_function<0x00>(BitsHashState.data(), BitsHashState.size() * sizeof(std::uint64_t));
				}

				//不提供外部数据的测试
				//Tests that do not provide external data
				std::vector<std::uint64_t> Test()
				{
					for(std::size_t BlockCounter = 0; BlockCounter < (HashBitSize / std::numeric_limits<std::uint64_t>::digits); BlockCounter++)
					{
						this->TransfromState(BlockCounter);
					}

					std::vector<std::uint64_t> TestData(HashBitSize / std::numeric_limits<std::uint64_t>::digits, 0);
					this->SqueezeOutputData(TestData);

					this->Reset();

					return TestData;
				}

				void SpongeHash
				(
					std::span<const std::uint8_t> InputData,
					std::span<std::uint8_t> OuputData
				)
				{
					std::vector<std::uint8_t> BlockDataBuffer(InputData.begin(), InputData.end());

					//填充数据和吸收数据阶段
					//Pad data and Absorbing data stage
					if(BlockDataBuffer.size() % BYTES_RATE != 0)
					{
						for(std::size_t PadCount = 0; PadCount < BlockDataBuffer.size() % BYTES_RATE; ++PadCount)
						{
							BlockDataBuffer.push_back(PAD_BYTE_DATA);
						}
					}
					this->AbsorbInputData(BlockDataBuffer);

					//挤压数据阶段
					//squeeze data stage
					this->SqueezeOutputData(OuputData);

					memory_set_no_optimize_function<0x00>(BlockDataBuffer.data(), BlockDataBuffer.size());

					//如果已经生成哈希摘要数据，就必须把当前状态全部重置和清理
					//如果不重置和清理，你将会影响哈希函数的质量
					//If the hash summary data has been generated, the current state must be completely reset and cleaned up.
					//If you don't reset and clean, you will affect the quality of the hash function
					this->Reset();
				}

				void SpongeHash
				(
					std::span<const std::uint64_t> InputData,
					std::span<std::uint64_t> OuputData
				)
				{
					std::vector<std::uint64_t> BlockDataBuffer(InputData.begin(), InputData.end());

					//填充数据和吸收数据阶段
					//Pad data and Absorbing data stage
					if(BlockDataBuffer.size() % BITWORDS_RATE != 0)
					{
						for(std::size_t PadCount = 0; PadCount < BlockDataBuffer.size() % BYTES_RATE; ++PadCount)
						{
							BlockDataBuffer.push_back(PAD_BITSWORD_DATA);
						}
					}
					this->AbsorbInputData(BlockDataBuffer);

					//挤压数据阶段
					//squeeze data stage
					this->SqueezeOutputData(OuputData);

					memory_set_no_optimize_function<0x00>(BlockDataBuffer.data(), BlockDataBuffer.size() * sizeof(std::uint64_t));

					//如果已经生成哈希摘要数据，就必须把当前状态全部重置和清理
					//如果不重置和清理，你将会影响哈希函数的质量
					//If the hash summary data has been generated, the current state must be completely reset and cleaned up.
					//If you don't reset and clean, you will affect the quality of the hash function
					this->Reset();
				}

				explicit CustomSecureHash(std::uint32_t HashBitState)
					:
					HashBitSize(HashBitState),
					MoveBitCounts(GenerateRandomMoveBitCounts()),
					HashStateIndices(GenerateRandomHashStateIndices())
				{
					std::vector<std::uint32_t> StateBufferIndices = std::vector<std::uint32_t>(BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2, 0);

					for(std::size_t index = 0, value = 0; index < BITS_STATE_SIZE / std::numeric_limits<std::uint64_t>::digits / 2; ++index)
					{
						StateBufferIndices[index] = value;
						++value;
					}

					my_cpp2020_assert(HashBitSize >= 128 && HashBitSize % 8 == 0, "The hash bit size you chose is not secure!", std::source_location::current());

					std::ranges::rotate_copy(StateBufferIndices.begin(), StateBufferIndices.begin() + 1, StateBufferIndices.end(), LeftRotatedStateBufferIndices.begin());
					std::ranges::rotate_copy(StateBufferIndices.begin(), StateBufferIndices.end() - 1, StateBufferIndices.end(), RightRotatedStateBufferIndices.begin());
				}

				~CustomSecureHash() = default;
			};
		}
	}
}

#endif //ALGORITHM_OALDRESPUZZLECRYPTIC_CUSTOMSECUREHASH_HPP
