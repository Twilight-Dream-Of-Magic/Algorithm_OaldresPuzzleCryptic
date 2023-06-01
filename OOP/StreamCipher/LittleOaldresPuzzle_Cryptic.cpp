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

		std::uint64_t LittleOaldresPuzzle_Cryptic::EncryptionCoreFunction(const std::uint64_t data, const std::uint64_t key, const std::uint64_t number_once)
		{
			std::uint64_t result = data;

			for(size_t round = 0; round < rounds; round++)
			{
				KeyState key_state = KeyStates[round];

				//Generate subkey

				key_state.subkey = key ^ prng(number_once ^ round);
				key_state.choise_function = prng(key_state.subkey ^ (key >> 1));
				key_state.bit_rotation_amount_a = prng(key_state.subkey ^ key_state.choise_function);
				//Select bit position 6 ~ 11
				key_state.bit_rotation_amount_b = (key_state.bit_rotation_amount_a >> 6) % 64;
				//Select bit position 0 ~ 5
				key_state.bit_rotation_amount_a %= 64;
				key_state.choise_function %= 4;
			}

			for(size_t round = 0; round < rounds; round++)
			{
				KeyState key_state = KeyStates[round];

				//Encryption core function

				switch ( key_state.choise_function )
				{
					case 0:
					{
						result = result ^ key_state.subkey;
						break;
					}
					case 1:
					{
						result = result ^ key_state.subkey;
						result = ~result;
						break;
					}

					case 2:
					{
						//2^{6} = 64
						result = std::rotl( result, key_state.bit_rotation_amount_b);
						break;
					}

					case 3:
					{
						//2^{6} = 64
						result = std::rotr( result, key_state.bit_rotation_amount_b);
						break;
					}
					default:
						break;
				}

				//Non-linear processing - random bit switching
				//非线性处理 - 随机比特位切换
				result ^= ( 1ULL << (key_state.bit_rotation_amount_a % 64) );

				result += (std::rotr(key, 3) ^ std::rotr(key_state.subkey, 11));
			}

			return result;
		}

		std::uint64_t LittleOaldresPuzzle_Cryptic::DecryptionCoreFunction(const std::uint64_t data, const std::uint64_t key, const std::uint64_t number_once)
		{
			std::uint64_t result = data;

			for(size_t round = 0; round < rounds; round++)
			{
				KeyState key_state = KeyStates[round];

				//Generate subkey

				key_state.subkey = key ^ prng(number_once ^ round);
				key_state.choise_function = prng(key_state.subkey ^ (key >> 1));
				key_state.bit_rotation_amount_a = prng(key_state.subkey ^ key_state.choise_function);
				//Select bit position 6 ~ 11
				key_state.bit_rotation_amount_b = (key_state.bit_rotation_amount_a >> 6) % 64;
				//Select bit position 0 ~ 5
				key_state.bit_rotation_amount_a %= 64;
				key_state.choise_function %= 4;
			}

			for(size_t round = rounds; round > 0; round--)
			{
				KeyState key_state = KeyStates[round - 1];

				//Decryption core function

				result -= (std::rotr(key, 3) ^ std::rotr(key_state.subkey, 11));

				//Non-linear processing - random bit switching
				//非线性处理 - 随机比特位切换
				result ^= ( 1ULL << (key_state.bit_rotation_amount_a % 64) );

				switch (key_state.choise_function)
				{
					case 0:
					{
						result = result ^ key_state.subkey;
						break;
					}
					case 1:
					{
						result = ~result;
						result = result ^ key_state.subkey;
						break;
					}
					case 2:
					{
						//2^{6} = 64
						result = std::rotr(result, key_state.bit_rotation_amount_b);
						break;
					}
					case 3:
					{
						//2^{6} = 64
						result = std::rotl(result, key_state.bit_rotation_amount_b);
						break;
					}
					default:
						break;
				}
			}

			return result;
		}
	}
} // TwilightDreamOfMagical