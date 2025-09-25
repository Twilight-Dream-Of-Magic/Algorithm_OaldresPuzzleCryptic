#include "LittleOaldresPuzzle_Cryptic.h"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::StreamCipher
	{
		/*
			Implementation of Custom Data Encrypting Worker and Decrypting Worker
			自定义加密和解密数据工作器的实现

			OaldresPuzzle-Cryptic (Type 1)
			隐秘的奥尔德雷斯之谜 (类型 1)
		*/

		constexpr std::array<std::uint32_t, 16> ROUND_CONSTANT
		{ 
			//1,2,3,5,8,13,21,34,55,89,144,233,377,610,987,1597,2584,4181 (Fibonacci numbers)
			//Concatenation of Fibonacci numbers : 123581321345589144233377610987159725844181
			//Hexadecimal : 16b2c40bc117176a0f9a2598a1563aca6d5
			0x16B2C40B, 0xC117176A, 0x0F9A2598, 0xA1563ACA,

			/*
					Mathematical Constants - Millions of Digits
					http://www.numberworld.org/constants.html
			*/

			//π Pi (3.243f6a8885a308d313198a2e0370734)
			0x243F6A88, 0x85A308D3, 0x13198102, 0xE0370734,
			//φ Golden ratio (1.9e3779b97f4a7c15f39cc0605cedc834)
			0x9E3779B9, 0x7F4A7C15, 0xF39CC060, 0x5CEDC834,
			//e Natural Constant (2.b7e151628aed2a6abf7158809cf4f3c7)
			0xB7E15162, 0x8AED2A6A, 0xBF715880, 0x9CF4F3C7
		};

		//NeoAlzette is like the Alzette ARX-box of Sparkle algorithms, but not, just similar in structure.
		//NeoAlzette就像 Sparkle 算法的 Alzette ARX-box，但又不是，只是结构相似而已。
		//https://eprint.iacr.org/2019/1378.pdf
		//NeoAlzette has only one more layer than the Alzette ARX-box, and the confusions are better
		//NeoAlzette只比Alzette ARX-box多一层，而且混淆程度更好
		inline void NeoAlzette_ForwardLayer( uint32_t& a, uint32_t& b, const uint32_t rc )
		{
#if 1
			b = b ^ a;
			a = std::rotr( a + b, 31 );
			a = a ^ rc;

			b = b + a;
			a = std::rotl( a ^ b, 24 );
			a = a + rc;

			//a = a - std::rotl(b ^ rc, 17);
			//b = b + (a ^ rc);
			//b = b - std::rotr(a ^ rc, 24);
			//a = a + (b ^ rc);
			b = std::rotl( b, 8 ) ^ rc;
			a = a + b;

			a = a ^ b;
			b = std::rotr( a + b, 17 );
			b = b ^ rc;

			a = a + b;
			b = std::rotl( a ^ b, 16 );
			b = b + rc;
#else
			//Alzette ForwardLayer

			a += std::rotr( b, 31 );
			b ^= std::rotr( a, 24 );
			a ^= rc;

			a += std::rotr( b, 17 );
			b ^= std::rotr( a, 17 );
			a ^= rc;

			a += std::rotr( b, 0 );
			b ^= std::rotr( a, 31 );
			a ^= rc;

			a += std::rotr( b, 24 );
			b ^= std::rotr( a, 16 );
			a ^= rc;
#endif
		}

		inline void NeoAlzette_BackwardLayer( uint32_t& a, uint32_t& b, const uint32_t rc )
		{
#if 0
			//Alzette BackwardLayer

			a ^= rc;
			b ^= std::rotr(a, 16);
			a -= std::rotr(b, 24);

			a ^= rc;
			b ^= std::rotr(a, 31);
			a -= std::rotr(b, 0);

			a ^= rc;
			b ^= std::rotr(a, 17);
			a -= std::rotr(b, 17);

			a ^= rc;
			b ^= std::rotr(a, 24);
			a -= std::rotr(b, 31);
#else
			b = b - rc;
			b = std::rotr( b, 16 ) ^ a;
			a = a - b;

			b = b ^ rc;
			b = std::rotl( b, 17 ) - a;
			a = a ^ b;

			a = a - b;
			b = std::rotr( b ^ rc, 8 );
			//a = a - (b ^ rc);
			//b = b + std::rotr(a ^ rc, 24);
			//b = b - (a ^ rc);
			//a = a + std::rotl(b ^ rc, 17);

			a = a - rc;
			a = std::rotr( a, 24 ) ^ b;
			b = b - a;

			a = a ^ rc;
			a = std::rotl( a, 31 ) - b;
			b = b ^ a;
#endif
		}

		uint64_t ghash_multiply( uint64_t a, uint64_t b )
		{
			uint64_t	   product = 0;
			const uint64_t POLYNOMIAL = 0xE100000000000000;	 // This is x^64 + x^4 + x^3 + x + 1 in binary

			for ( int i = 0; i < 64; i++ )
			{
				if ( b & 1 )
				{
					product ^= a;
				}

				//boolean type
				uint64_t high_bit_set = a & 0x8000000000000000;

				a <<= 1;

				if ( high_bit_set )
				{
					a ^= POLYNOMIAL;
				}

				b >>= 1;
			}

			return product;
		}
		
		// 生成所有轮次密钥状态的方法
		void LittleOaldresPuzzle_Cryptic::GenerateAndStoreKeyStates( const Key128 key, const std::uint64_t number_once )
		{
			// Crypto Version Fold Multiply Generate Seed
			uint64_t a = ( key.first ^ key.second );
			uint64_t b = ~ghash_multiply( key.first, key.second );
			mix( a, b );
			// Rationale for rot=1 and rot=13:
			// - rot1(b): 打断 a'⊕b' 的线性抵消恒等式（I⊕S），把乘法支路 b 的影响直接扩散到相邻位；
			// - rot13(a): 选用与 64 互素且与{8,16,24,31,17,…}等常见角度“错位”的中距奇数旋转，
			//             既避开与轮函数既有旋转的对齐/共振，又提供与 rot1 频段互补的扩散；
			//   两者叠加保证 a、b 两路都进 seed，且不存在简单线性组合把其中一路整体消掉。
			//   （说明：任意两个“奇数、互异、与现有角度不共振”的旋转也可行；1+13 是在扩散/代价/实现友好之间的折中。）
			uint64_t			seed = ( a ^ std::rotl( b, 1 ) ) ^ std::rotl( a, 13 );
			XorConstantRotation key_prng( seed );

			uint32_t round_constant_index = 0;
			for ( size_t round = 0; round < rounds; round++ )
			{
				KeyState& key_state = KeyStates[ round ];

				const uint64_t sk0 = key_prng( number_once );		// 密钥驱动（有状态→每轮不同）
				const uint64_t para = prng( number_once ^ round );	// 公开盐（含 round）

				// 两半子密钥：都含密钥信息
				key_state.subkey.first = key.first ^ sk0;
				key_state.subkey.second = key.second ^ para;

				// 由子密钥驱动选路（保留“PRG 输出的低 2 位”语义）
				key_state.choice_function = key_prng( key_state.subkey.first ^ ( key.first >> 1 ) ) & 0x3;

				// 旋转量由 subkey.second 与 choice 再驱动（保留链式依赖）
				const uint64_t bit_rotation = prng( key_state.subkey.second ^ key_state.choice_function );
				key_state.bit_rotation_amount_a = bit_rotation & 0x3F;			 // 0..63 (Selected bit 0~5)
				key_state.bit_rotation_amount_b = ( bit_rotation >> 6 ) & 0x3F;	 // 0..63 (Selected bit 6~11)

				key_state.round_constant_index = ( round_constant_index >> 1 ) & 0x0F;
				round_constant_index += 2;
			}
		}

		static inline uint64_t pack64( uint32_t hi, uint32_t lo )
		{
			return ( uint64_t( hi ) << 32 ) | uint64_t( lo );
		}

		static inline void unpack64( uint64_t v, uint32_t& hi, uint32_t& lo )
		{
			hi = uint32_t( v >> 32 );
			lo = uint32_t( v );
		}

		// Return 0xFFFFFFFFFFFFFFFF iff x == y, else 0x0. Constant-time, branchless.
		inline uint64_t ConstantTimeEqualMask( uint64_t x, uint64_t y )
		{
			uint64_t q = x ^ y;
			q |= ( uint64_t )0 - q;	 // q | (-q)
			q >>= 63;				 // 0 if equal, 1 otherwise
			return q - 1;			 // 0xFFFFFFFFFFFFFFFF if equal, 0x0 otherwise
		}

		//Mix Linear Transform Layer (Forward)
		inline void MixLinearTransform_Forward
		(
			uint64_t& lane0, uint64_t& lane1, const KeyState& current_key_state
		)
		{
			/*
				switch ( current_key_state.choice_function & 3ULL )
				{
				case 0:
					lane0 ^= current_key_state.subkey.first;
					lane1 ^= current_key_state.subkey.second;
					break;
				case 1:
					lane0 = (~lane0) ^ current_key_state.subkey.first;
					lane1 = (~lane1) ^ current_key_state.subkey.second;
					break;
				case 2:
					lane0 = std::rotl( lane0, current_key_state.bit_rotation_amount_b );
					lane1 = std::rotl( lane1, current_key_state.bit_rotation_amount_b );
					break;
				case 3:
					lane0 = std::rotr( lane0, current_key_state.bit_rotation_amount_b );
					lane1 = std::rotr( lane1, current_key_state.bit_rotation_amount_b );
					break;
				}
			*/

			const uint64_t& choice_function = current_key_state.choice_function;
			const uint64_t& subkey_first = current_key_state.subkey.first;
			const uint64_t& subkey_second = current_key_state.subkey.second;

			const uint64_t lane0_case0 = (lane0) ^ subkey_first;
			const uint64_t lane1_case0 = (lane1) ^ subkey_second;

			const uint64_t lane0_case1 = (~lane0) ^ subkey_first;
			const uint64_t lane1_case1 = (~lane1) ^ subkey_second;

			const uint64_t lane0_case2 = std::rotl(lane0, current_key_state.bit_rotation_amount_b & 63ULL);
			const uint64_t lane1_case2 = std::rotl(lane1, current_key_state.bit_rotation_amount_b & 63ULL);

			const uint64_t lane0_case3 = std::rotr(lane0, current_key_state.bit_rotation_amount_b & 63ULL);
			const uint64_t lane1_case3 = std::rotr(lane1, current_key_state.bit_rotation_amount_b & 63ULL);

			const uint64_t m0 = ConstantTimeEqualMask(choice_function & 3ULL, 0ULL);
			const uint64_t m1 = ConstantTimeEqualMask(choice_function & 3ULL, 1ULL);
			const uint64_t m2 = ConstantTimeEqualMask(choice_function & 3ULL, 2ULL);
			const uint64_t m3 = ConstantTimeEqualMask(choice_function & 3ULL, 3ULL);

			lane0 = (lane0_case0 & m0) | (lane0_case1 & m1) | (lane0_case2 & m2) | (lane0_case3 & m3);
			lane1 = (lane1_case0 & m0) | (lane1_case1 & m1) | (lane1_case2 & m2) | (lane1_case3 & m3);
		}

		// Mix Linear Transform Layer (Backward)
		inline void MixLinearTransform_Backward
		(
			uint64_t& lane0, uint64_t& lane1, const KeyState& current_key_state
		)
		{
			/*
				switch ( current_key_state.choice_function & 3ULL )
				{
				case 0:
					lane0 ^= current_key_state.subkey.first;
					lane1 ^= current_key_state.subkey.second;
					break;
				case 1:
					lane0 = (~lane0) ^ current_key_state.subkey.first;
					lane1 = (~lane1) ^ current_key_state.subkey.second;
					break;
				case 2:
					lane0 = std::rotr( lane0, current_key_state.bit_rotation_amount_b );
					lane1 = std::rotr( lane1, current_key_state.bit_rotation_amount_b );
					break;
				case 3:
					lane0 = std::rotl( lane0, current_key_state.bit_rotation_amount_b );
					lane1 = std::rotl( lane1, current_key_state.bit_rotation_amount_b );
					break;
				}
			*/

			const uint64_t& choice_function = current_key_state.choice_function;
			const uint64_t& subkey_first = current_key_state.subkey.first;
			const uint64_t& subkey_second = current_key_state.subkey.second;

			const uint64_t lane0_case0 = (lane0) ^ subkey_first;
			const uint64_t lane1_case0 = (lane1) ^ subkey_second;

			const uint64_t lane0_case1 = (~lane0) ^ subkey_first;
			const uint64_t lane1_case1 = (~lane1) ^ subkey_second;

			const uint64_t lane0_case2 = std::rotr(lane0, current_key_state.bit_rotation_amount_b & 63ULL);
			const uint64_t lane1_case2 = std::rotr(lane1, current_key_state.bit_rotation_amount_b & 63ULL);

			const uint64_t lane0_case3 = std::rotl(lane0, current_key_state.bit_rotation_amount_b & 63ULL);
			const uint64_t lane1_case3 = std::rotl(lane1, current_key_state.bit_rotation_amount_b & 63ULL);

			const uint64_t m0 = ConstantTimeEqualMask(choice_function & 3ULL, 0ULL);
			const uint64_t m1 = ConstantTimeEqualMask(choice_function & 3ULL, 1ULL);
			const uint64_t m2 = ConstantTimeEqualMask(choice_function & 3ULL, 2ULL);
			const uint64_t m3 = ConstantTimeEqualMask(choice_function & 3ULL, 3ULL);

			lane0 = (lane0_case0 & m0) | (lane0_case1 & m1) | (lane0_case2 & m2) | (lane0_case3 & m3);
			lane1 = (lane1_case0 & m0) | (lane1_case1 & m1) | (lane1_case2 & m2) | (lane1_case3 & m3);
		}

		Block128 LittleOaldresPuzzle_Cryptic::EncryptionCoreFunction( const Block128 data, const Key128 key, const std::uint64_t number_once )
		{
			// 生成并缓存密钥状态（保持实现不变）
			GenerateAndStoreKeyStates( key, number_once );

			// 128-bit 状态按两条 64-bit 车道存放
			uint64_t lane0 = data.first;   // (w0 || w1)
			uint64_t lane1 = data.second;  // (w2 || w3)

			// 拆成 4×32（注意：hi 在前、lo 在后）
			uint32_t w0, w1, w2, w3;

			for ( size_t round = 0; round < rounds; ++round )
			{
				const KeyState& current_key_state = KeyStates[ round ];
				const uint32_t	rc = ROUND_CONSTANT[ current_key_state.round_constant_index ];

				unpack64( lane0, w0, w1 );
				unpack64( lane1, w2, w3 );

				/*
					NeoAlzette ARX Layer (Forward)
					—— 采用“对角配对”：(w0,w2) 与 (w1,w3)，跨车道混合
				*/
				NeoAlzette_ForwardLayer( w0, w2, rc );
				NeoAlzette_ForwardLayer( w1, w3, rc );

				// 重新打包回两条 64-bit 车道
				lane0 = pack64( w0, w1 );
				lane1 = pack64( w2, w3 );

				/* Keyed Switching Layer - MixLinearTransform (Forward) */
				MixLinearTransform_Forward(lane0, lane1, current_key_state);

				/*  Keyed Switching Layer - Random Bit Tweak (Nonlinear)(Forward) */
				lane0 ^= ( uint64_t( 1 ) << current_key_state.bit_rotation_amount_a );
				lane1 ^= ( uint64_t( 1 ) << ( 63 - current_key_state.bit_rotation_amount_a ) );

				// Add Round Key
				const uint64_t k0 = key.first;
				const uint64_t k1 = key.second;

				lane0 += ( k0 ^ current_key_state.subkey.first );
				lane0 = std::rotr( lane0 ^ k0, 16 );
				lane0 ^= std::rotl( k0 + current_key_state.subkey.first, 48 );

				lane1 += ( k1 ^ current_key_state.subkey.second );
				lane1 = std::rotr( lane1 ^ k1, 16 );
				lane1 ^= std::rotl( k1 + current_key_state.subkey.second, 48 );
			}

			return Block128 { lane0, lane1 };
		}

		Block128 LittleOaldresPuzzle_Cryptic::DecryptionCoreFunction( const Block128 data, const Key128 key, const std::uint64_t number_once )
		{
			// 生成并缓存密钥状态（保持实现不变）
			GenerateAndStoreKeyStates( key, number_once );

			uint64_t lane0 = data.first;
			uint64_t lane1 = data.second;

			// NeoAlzette ARX Layer (Backward)
			uint32_t w0, w1, w2, w3;

			for ( size_t round = rounds; round > 0; --round )
			{
				const KeyState& current_key_state = KeyStates[ round - 1 ];
				const uint32_t	rc = ROUND_CONSTANT[ current_key_state.round_constant_index ];

				// Subtract Round key
				const uint64_t k0 = key.first;
				const uint64_t k1 = key.second;

				lane1 ^= std::rotl( k1 + current_key_state.subkey.second, 48 );
				lane1 = std::rotl( lane1, 16 ) ^ k1;
				lane1 -= ( k1 ^ current_key_state.subkey.second );

				lane0 ^= std::rotl( k0 + current_key_state.subkey.first, 48 );
				lane0 = std::rotl( lane0, 16 ) ^ k0;
				lane0 -= ( k0 ^ current_key_state.subkey.first );

				/* Keyed Switching Layer^{-1} - Random Bit Tweak (Nonlinear)(Backward) */
				lane0 ^= ( uint64_t( 1 ) << current_key_state.bit_rotation_amount_a );
				lane1 ^= ( uint64_t( 1 ) << ( 63 - current_key_state.bit_rotation_amount_a ) );

				/* Keyed Switching Layer^{-1} - MixLinearTransform (Backward) */
				MixLinearTransform_Backward(lane0, lane1, current_key_state);

				unpack64( lane0, w0, w1 );
				unpack64( lane1, w2, w3 );

				NeoAlzette_BackwardLayer( w1, w3, rc );
				NeoAlzette_BackwardLayer( w0, w2, rc );

				lane0 = pack64( w0, w1 );
				lane1 = pack64( w2, w3 );
			}

			return Block128 { lane0, lane1 };
		}
	}  // TwilightDreamOfMagical
	
}