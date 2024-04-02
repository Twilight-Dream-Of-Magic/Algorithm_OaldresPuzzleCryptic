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
			0x16B2C40B,0xC117176A,0x0F9A2598,0xA1563ACA,

			/*
				Mathematical Constants - Millions of Digits
				http://www.numberworld.org/constants.html
			*/

			//π Pi (3.243f6a8885a308d313198a2e0370734)
			0x243F6A88,0x85A308D3,0x13198102,0xE0370734,
			//φ Golden ratio (1.9e3779b97f4a7c15f39cc0605cedc834)
			0x9E3779B9,0x7F4A7C15,0xF39CC060,0x5CEDC834,
			//e Natural Constant (2.b7e151628aed2a6abf7158809cf4f3c7)
			0xB7E15162,0x8AED2A6A,0xBF715880,0x9CF4F3C7
		};
		
		//NeoAlzette is like the Alzette ARX-box of Sparkle algorithms, but not, just similar in structure.
		//NeoAlzette就像 Sparkle 算法的 Alzette ARX-box，但又不是，只是结构相似而已。
		//https://eprint.iacr.org/2019/1378.pdf
		//NeoAlzette has only one more layer than the Alzette ARX-box, and the confusions are better
		//NeoAlzette只比Alzette ARX-box多一层，而且混淆程度更好
		inline void NeoAlzette_ForwardLayer(uint32_t& a, uint32_t& b, const uint32_t rc)
		{
			#if 1
			b = b ^ a;
			a = std::rotr(a + b, 31);
			a = a ^ rc;

			b = b + a;
			a = std::rotl(a ^ b, 24);
			a = a + rc;
	
			//a = a - std::rotl(b ^ rc, 17);
			//b = b + (a ^ rc);
			//b = b - std::rotr(a ^ rc, 24);
			//a = a + (b ^ rc);
			b = std::rotl(b, 8) ^ rc;
			a = a + b;

			a = a ^ b;
			b = std::rotr(a + b, 17);
			b = b ^ rc;

			a = a + b;
			b = std::rotl(a ^ b, 16);
			b = b + rc;
			#else
			//Alzette ForwardLayer

			a += std::rotr(b, 31);
			b ^= std::rotr(a, 24);
			a ^= rc;

			a += std::rotr(b, 17);
			b ^= std::rotr(a, 17);
			a ^= rc;

			a += std::rotr(b, 0);
			b ^= std::rotr(a, 31);
			a ^= rc;

			a += std::rotr(b, 24);
			b ^= std::rotr(a, 16);
			a ^= rc;
			#endif
		}

		inline void NeoAlzette_BackwardLayer(uint32_t& a, uint32_t& b, const uint32_t rc)
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
			b = std::rotr(b, 16) ^ a;
			a = a - b;

			b = b ^ rc;
			b = std::rotl(b, 17) - a;
			a = a ^ b;

			a = a - b;
			b = std::rotr(b ^ rc, 8);
			//a = a - (b ^ rc);
			//b = b + std::rotr(a ^ rc, 24);
			//b = b - (a ^ rc);
			//a = a + std::rotl(b ^ rc, 17);

			a = a - rc;
			a = std::rotr(a, 24) ^ b;
			b = b - a;

			a = a ^ rc;
			a = std::rotl(a, 31) - b;
			b = b ^ a;
			#endif
		}

		// 生成所有轮次密钥状态的方法
		void LittleOaldresPuzzle_Cryptic::GenerateAndStoreKeyStates(const std::uint64_t key, const std::uint64_t number_once)
		{
			uint32_t round_constant_index = 0;
			for(size_t round = 0; round < rounds; round++)
			{
				KeyState& key_state = KeyStates[round];

				// Generate subkey
				key_state.subkey = key ^ prng(number_once ^ round);
				key_state.choice_function = prng(key_state.subkey ^ (key >> 1));
				key_state.bit_rotation_amount_a = prng(key_state.subkey ^ key_state.choice_function);
				// Select bit position 6 ~ 11
				key_state.bit_rotation_amount_b = (key_state.bit_rotation_amount_a >> 6) % 64;
				// Select bit position 0 ~ 5
				key_state.bit_rotation_amount_a %= 64;
				key_state.choice_function %= 4;
				
				key_state.round_constant_index = (round_constant_index >> 1) % 16;
				round_constant_index += 2;
			}
		}

		std::uint64_t LittleOaldresPuzzle_Cryptic::EncryptionCoreFunction(const std::uint64_t data, const std::uint64_t key, const std::uint64_t number_once)
		{
			// Generate and cache key state 生成并缓存密钥状态
			GenerateAndStoreKeyStates(key, number_once);

			std::uint64_t result = data;

			// Encryption using key states in forward order 正序使用密钥状态进行加密
			for (size_t round = 0; round < rounds; round++)
			{
				const KeyState& key_state = KeyStates[round];

				/*
					NeoAlzette ARX Layer (Forward)
				*/

				uint32_t left_value = result >> 32;
				uint32_t right_value = result & 0xFFFFFFFF;
				NeoAlzette_ForwardLayer(left_value, right_value, ROUND_CONSTANT[key_state.round_constant_index]);
				result = uint64_t(left_value) << 32 | uint64_t(right_value);

				/*
					Mix Linear Transform Layer (Forward)
				*/

				switch (key_state.choice_function)
				{
					case 0:
						result ^= key_state.subkey;
						break;
					case 1:
						result = ~result ^ key_state.subkey;
						break;
					case 2:
						//2^{6} = 64
						result = std::rotl(result, key_state.bit_rotation_amount_b);
						break;
					case 3:
						//2^{6} = 64
						result = std::rotr(result, key_state.bit_rotation_amount_b);
						break;
					default:
					{
						break; // or throw an exception
					}
				}

				//Random Bit Tweak (Nonlinear)
				result ^= (std::uint64_t(1) << (key_state.bit_rotation_amount_a % 64));

				//Add Round Key
				result += (key ^ key_state.subkey);
				result = std::rotr(result ^ key, 16);
				result ^= std::rotl(key + key_state.subkey, 48);
			}

			return result;
		}

		std::uint64_t LittleOaldresPuzzle_Cryptic::DecryptionCoreFunction(const std::uint64_t data, const std::uint64_t key, const std::uint64_t number_once)
		{
			// Generate and cache key state 生成并缓存密钥状态
			GenerateAndStoreKeyStates(key, number_once);

			std::uint64_t result = data;

			// Decryption using key states in backward order 反序使用密钥状态进行解密
			for (size_t round = rounds; round > 0; round--)
			{
				const KeyState& key_state = KeyStates[round - 1];

				//Subtract Round key
				result ^= std::rotl(key + key_state.subkey, 48);
				result = std::rotl(result, 16) ^ key;
				result -= (key ^ key_state.subkey);

				//Random Bit Tweak (Nonlinear)
				result ^= (std::uint64_t(1) << (key_state.bit_rotation_amount_a % 64));

				/*
					Mix Linear Transform Layer (Backward)
				*/

				switch (key_state.choice_function)
				{
					case 0:
						result ^= key_state.subkey;
						break;
					case 1:
						result = ~result ^ key_state.subkey;
						break;
					case 2:
						//2^{6} = 64
						result = std::rotr(result, key_state.bit_rotation_amount_b);
						break;
					case 3:
						//2^{6} = 64
						result = std::rotl(result, key_state.bit_rotation_amount_b);
						break;
					default:
					{
						break; // or throw an exception
					}
				}

				/*
					NeoAlzette ARX Layer (Backward)
				*/

				uint32_t left_value = result >> 32;
				uint32_t right_value = result & 0xFFFFFFFF;
				NeoAlzette_BackwardLayer(left_value, right_value, ROUND_CONSTANT[key_state.round_constant_index]);
				result = uint64_t(left_value) << 32 | uint64_t(right_value);
			}

			return result;
		}
	}
} // TwilightDreamOfMagical