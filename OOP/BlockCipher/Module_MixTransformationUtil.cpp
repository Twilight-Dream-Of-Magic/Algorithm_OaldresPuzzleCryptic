#include "Module_MixTransformationUtil.hpp"

/*
 * 模块说明｜Module Overview
 * - 作用：提供 32 位数据的混合变换与密钥扩展工具，组合「门级非线性」与「线性扩散」。
 * - 场景：用于自研分组密码/杂凑内部的轮函数或子密钥生成。
 * - 设计取向：无 S-box/查表/大整数，仅靠基本位操作与旋转，强调可移植与可审计。
 *
 * Purpose: Utilities for 32‑bit mixed transforms and key expansion, combining
 * gate‑level nonlinearity with linear diffusion. Intended for round functions
 * or subkey generation in custom block ciphers / hashes. Avoids S‑boxes and
 * lookup tables; sticks to simple bit‑ops/rotates for portability and auditability.
 */

namespace TwilightDreamOfMagical::CustomSecurity
{
	// 对称加解密（Symmetric Encryption/Decryption）
	namespace SED::BlockCipher
	{
		namespace ImplementationDetails
		{

			// 非线性变换和线性变换函数
			// Nonlinear transformations and linear transformation functions
			// 轮函数样式的混合变换（无 S‑box） / Keccak‑style mixed layer (no S‑box)
			// 输入：随机字料 + 内部状态；输出：回写扩散后的状态，并返回一字作回馈。
			// Input: random word material + internal state; updates state and returns a feedback word.
			std::uint32_t Module_MixTransformationUtil::Word32Bit_KeyWithFunction( std::span<const std::uint32_t> RandomWordDataMaterial )
			{
				using TwilightDreamOfMagical::BaseOperation::rotate_left;
				using TwilightDreamOfMagical::BaseOperation::rotate_right;

				my_cpp2020_assert( RandomWordDataMaterial.size() == 4, "", std::source_location::current() );

				auto& StateValue0 = this->Word32Bit_StateRegisters[ 0 ];
				auto& StateValue1 = this->Word32Bit_StateRegisters[ 1 ];

				// NAND / NOR（函数完备；functionally complete）
				auto NAND32 = []( std::uint32_t x, std::uint32_t y ) noexcept -> std::uint32_t {
					return ~( x & y );
				};
				auto NOR32 = []( std::uint32_t x, std::uint32_t y ) noexcept -> std::uint32_t {
					return ~( x | y );
				};

				std::uint32_t		RandomWordData0 = NAND32( RandomWordDataMaterial[ 0 ] ^ StateValue0, StateValue1 );
				const std::uint32_t RandomWordData1 = NOR32( StateValue0, RandomWordDataMaterial[ 1 ] );
				const std::uint32_t RandomWordData2 = StateValue1 ^ RandomWordDataMaterial[ 2 ];

				// 32 位半字交错拼接 / 32-bit half-word interleave
				volatile std::uint32_t RandomWordDataA = ( RandomWordData1 << 16 ) | ( RandomWordData2 >> 16 );
				volatile std::uint32_t RandomWordDataB = ( RandomWordData2 << 16 ) | ( RandomWordData1 >> 16 );

				// 非线性门级层（无 S-box/查表/加法） / Nonlinear gate layer (no S-box/tables/addition)
				// 位切片风格，借鉴 Keccak χ / Ascon 的思路（NOT/AND/OR 组合） / Bit-sliced style inspired by Keccak χ / Ascon (NOT/AND/OR)
				// 仅用 NAND/NOR + XOR/ROT 组合出轻量非线性 / Lightweight NL built from NAND/NOR + XOR/ROT
				std::uint32_t Temporary0 = NAND32( StateValue0, StateValue1 );
				std::uint32_t Temporary1 = NOR32( StateValue0, rotate_right( StateValue1, 1 ) );
				std::uint32_t Temporary2 = NAND32( rotate_right( StateValue0, 5 ), Temporary1 );
				StateValue0 = ( StateValue0 ^ Temporary0 ) ^ rotate_right( Temporary2, 3 );

				std::uint32_t Temporary3 = NAND32( StateValue1, rotate_right( StateValue0, 2 ) );
				std::uint32_t Temporary4 = NOR32( StateValue1, rotate_right( StateValue0, 7 ) );
				StateValue1 = ( StateValue1 ^ Temporary3 ) ^ rotate_right( Temporary4, 1 );

				// 线性扩散 / Linear diffusion
				StateValue0 = RandomWordDataA ^ rotate_left( RandomWordDataA, 2 ) ^ rotate_left( RandomWordDataA, 10 ) ^ rotate_left( RandomWordDataA, 18 ) ^ rotate_left( RandomWordDataA, 24 );

				StateValue1 = RandomWordDataB ^ rotate_left( RandomWordDataB, 8 ) ^ rotate_left( RandomWordDataB, 14 ) ^ rotate_left( RandomWordDataB, 22 ) ^ rotate_left( RandomWordDataB, 30 );

				return RandomWordData0;
			}

			// 状态初始化：组合 NLFSR/LFSR/SDP 的输出 / State init via NLFSR/LFSR/SDP mixing
			// 目的：播种 64‑bit 随机值并拆为两个 32‑bit 状态寄存器。
			// Goal: seed a 64‑bit value and split into two 32‑bit state registers.
			void Module_MixTransformationUtil::Word32Bit_Initialize()
			{
				auto& LFSR_Object = *( StateDataPointer->LFSR_ClassicPointer );
				auto& NLFSR_Object = *( StateDataPointer->NLFSR_ClassicPointer );
				auto& SDP_Object = *( StateDataPointer->SDP_ClassicPointer );

				auto& StateValue0 = this->Word32Bit_StateRegisters[ 0 ];
				auto& StateValue1 = this->Word32Bit_StateRegisters[ 1 ];

				std::uint64_t		   BaseNumber = NLFSR_Object() ^ SDP_Object( 0ULL, 0xFFFFFFFFFFFFFFFFULL );
				volatile std::uint64_t RandomNumber = 0;

				for ( size_t Count = 129; Count > 0; --Count )
				{
					BaseNumber = NLFSR_Object.unpredictable_bits( BaseNumber, 64 ) ^ LFSR_Object();
				}

				RandomNumber = NLFSR_Object() ^ ~( LFSR_Object() ^ BaseNumber );

				StateValue0 = static_cast<std::uint32_t>( RandomNumber >> 32 );
				StateValue1 = static_cast<std::uint32_t>( ( RandomNumber << 32 ) >> 32 );

				RandomNumber = 0;
			}

			// InitialVector密钥扩展：从输入词生成 12 个扩展字 / Subkey expansion: 12 words per input word
			// 步骤：重组→分割→χ‑like 非线性→PHT 扩散→直接写出 12 子键。
			// Steps: reorganize → split → χ‑like NL → PHT diffusion → emit 12 subkeys.
			std::vector<std::uint32_t> Module_MixTransformationUtil::Word32Bit_ExpandKey( std::span<const std::uint32_t> NeedHashDataWords )
			{
				using CommonToolkit::IntegerExchangeBytes::ByteSwap::byteswap;

				std::vector<std::uint32_t> ProcessedWordKeys( NeedHashDataWords.size() * 12, 0 );

				std::size_t NeedHashDataIndex = 0;
				while ( NeedHashDataIndex < NeedHashDataWords.size() )
				{

					/*
						Step 1 : Data word do bitwise reorganization
						数据字做比特重组
					*/

					std::uint32_t RestructedWordKey = this->WordBitRestruct( NeedHashDataWords[ NeedHashDataIndex ] );

					if constexpr ( std::endian::native == std::endian::big )
						RestructedWordKey = byteswap( RestructedWordKey );

					/*
						Step 2 : Data words do bitwise splitting
						数据字做比特分割
					*/

					std::uint32_t UpPartWord = ( RestructedWordKey >> 16 );
					std::uint32_t DownPartWord = ( RestructedWordKey << 16 ) >> 16;
					std::uint32_t LeftPartWord = ( RestructedWordKey & 0xF000'0000U ) | ( ( RestructedWordKey & 0x00F0'0000U ) << 4 ) | ( ( RestructedWordKey & 0x0000'F000U ) << 8 ) | ( ( RestructedWordKey & 0x0000'00F0U ) << 12 );
					std::uint32_t RightPartWord = ( ( RestructedWordKey & 0x0F00'0000U ) << 4 ) | ( ( RestructedWordKey & 0x000F'0000U ) << 8 ) | ( ( RestructedWordKey & 0x0000'0F00U ) << 12 ) | ( ( RestructedWordKey & 0x0000'000FU ) << 14 );

					/*
						Step 3 : Data words do byte mixing and number expansions
						数据字做字节混合和数量扩展
					*/

					volatile std::uint32_t DiffusionResult0 = UpPartWord ^ DownPartWord;
					volatile std::uint32_t DiffusionResult1 = LeftPartWord ^ RightPartWord;
					volatile std::uint32_t DiffusionResult2 = UpPartWord ^ LeftPartWord;
					volatile std::uint32_t DiffusionResult3 = DownPartWord ^ RightPartWord;
					volatile std::uint32_t DiffusionResult4 = UpPartWord ^ RightPartWord;
					volatile std::uint32_t DiffusionResult5 = DownPartWord ^ LeftPartWord;

					// 两轮：χ-like 非线性 + PHT 扩散 / Two rounds: χ-like nonlinearity + PHT diffusion
					auto pht = []( std::uint32_t& a, std::uint32_t& b ) {
						a = a + ( b << 1 );	 // mod 2^32
						b = b + a;			 // mod 2^32
					};

					std::uint32_t a = DiffusionResult0, b = DiffusionResult1, c = DiffusionResult2;
					std::uint32_t d = DiffusionResult3, e = DiffusionResult4, f = DiffusionResult5;

					for ( size_t r = 0; r < 2; ++r )
					{
						// χ-like 非线性（NOT/AND/XOR 门） / χ-like nonlinearity (NOT/AND/XOR)
						std::uint32_t a0 = a, b0 = b, c0 = c, d0 = d, e0 = e, f0 = f;
						a0 ^= ( ~b0 ) & c0;
						d0 ^= ( ~e0 ) & f0;
						b0 ^= ( ~c0 ) & d0;
						e0 ^= ( ~f0 ) & a0;
						c0 ^= ( ~d0 ) & e0;
						f0 ^= ( ~a0 ) & b0;

						// 轻量旋转（打破模式；可改为移位 + 掩码） / Lightweight rotates (or shifts + mask)
						a = std::rotl( a0, 5 );
						b = std::rotl( b0, 11 );
						c = std::rotl( c0, 17 );
						d = std::rotr( d0, 7 );
						e = std::rotr( e0, 13 );
						f = std::rotr( f0, 19 );

						// PHT 线性扩散（快速、可逆） / PHT diffusion (fast, invertible)
						pht( a, b );
						pht( c, d );
						pht( e, f );
					}

					// Step 4：直接写出 12 个扩展字（不再整体旋转向量） / Emit 12 subkeys directly (no vector‑wide rotate)
					std::size_t KeyIndex = NeedHashDataIndex * 12;
					ProcessedWordKeys[ KeyIndex + 0 ] ^= a;
					ProcessedWordKeys[ KeyIndex + 1 ] ^= b;
					ProcessedWordKeys[ KeyIndex + 2 ] ^= c;
					ProcessedWordKeys[ KeyIndex + 3 ] ^= d;
					ProcessedWordKeys[ KeyIndex + 4 ] ^= e;
					ProcessedWordKeys[ KeyIndex + 5 ] ^= f;
					ProcessedWordKeys[ KeyIndex + 6 ] ^= ( a ^ c );
					ProcessedWordKeys[ KeyIndex + 7 ] ^= ( b ^ d );
					ProcessedWordKeys[ KeyIndex + 8 ] ^= ( c ^ e );
					ProcessedWordKeys[ KeyIndex + 9 ] ^= ( d ^ f );
					ProcessedWordKeys[ KeyIndex + 10 ] ^= ( e ^ a );
					ProcessedWordKeys[ KeyIndex + 11 ] ^= ( f ^ b );

					//敏感临时数据清零，降低被分析风险 / Zero out sensitive temporaries
					a = b = c = d = e = f = 0;
					RestructedWordKey = UpPartWord = DownPartWord = LeftPartWord = RightPartWord = 0;

				}

				return ProcessedWordKeys;
			}  // namespace ImplementationDetails

			static constexpr std::array<std::uint8_t, 32> SwapBitPairs { 0x00, 0x09, 0x01, 0x12, 0x02, 0x1B, 0x03, 0x14, 0x04, 0x13, 0x05, 0x1C, 0x06, 0x15, 0x07, 0x0E, 0x08, 0x17, 0x0A, 0x18, 0x0B, 0x19, 0x0C, 0x1E, 0x0D, 0x1F, 0x0F, 0x10, 0x11, 0x1D, 0x16, 0x1A };

			// 位重组：按固定交换表打乱位次 / Bit restructure using a fixed swap table
			// 目标：打破局部相关，为后续扩散/非线性制造多样输入。
			// Goal: break locality and feed diverse patterns into diffusion/NL layers.
			std::uint32_t Module_MixTransformationUtil::WordBitRestruct( std::uint32_t WordKey )
			{
				for ( std::size_t i = 0; i < 32; i += 2 )
				{
					WordKey = this->SwapBits( WordKey, SwapBitPairs[ i ], SwapBitPairs[ i + 1 ] );
				}
				return WordKey;
			}

			// 交换指定位：用两次异或构造掩码并回写 / Swap two bit positions via XOR mask
			// 常量时间实现，无条件分支 / Constant‑time style, no data‑dependent branches.
			std::uint32_t Module_MixTransformationUtil::SwapBits( std::uint32_t Word, std::uint32_t BitPosition, std::uint32_t BitPosition2 )
			{
				/* 将第 BitPosition 位移至最低位（取位） / Move BitPosition-th to LSB (get bit) */
				//std::uint32_t Bit1 = (Word >> BitPosition) & 1；

				/* 将第 BitPosition2 位移至最低位（取位） / Move BitPosition2-th to LSB (get bit) */
				//std::uint32_t Bit2 = (Word >> BitPosition2) & 1；

				/* 两位异或得到掩码 / XOR the two bits to build mask */
				//std::uint32_t BitMask = Bit1 ^ Bit2;

				/* 将掩码写回到两个目标位 / Place the mask back at both positions */
				//BitMask = (BitMask << BitPosition) | (BitMask << BitPosition2);

				/* 用 BitMask 异或原数，实现两位互换 / XOR with BitMask to swap the two bits */
				//return Word ^ BitMask;

				std::uint32_t BitMask = ( ( Word >> BitPosition ) & std::uint32_t { 1 } ) ^ ( ( Word >> BitPosition2 ) & std::uint32_t { 1 } );

				//If it is two same bits, then return the word that does not change
				if ( BitMask == std::uint32_t { 0 } )
					return Word;

				BitMask = ( BitMask << BitPosition ) | ( BitMask << BitPosition2 );
				return Word ^ BitMask;
			}
		}  // namespace ImplementationDetails
		// namespace SED::BlockCipher
	}  // namespace SED::BlockCipher
}  // namespace TwilightDreamOfMagical::CustomSecurity
