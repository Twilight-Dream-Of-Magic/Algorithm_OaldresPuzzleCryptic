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

		std::uint64_t LittleOaldresPuzzle_Cryptic::EncryptionCoreFunction(const std::uint64_t data, const std::uint64_t key, const std::uint64_t round)
		{
			std::uint64_t result;
			std::uint64_t choise_function;
			std::uint64_t bit_rotation_amount;
			std::uint64_t subkey;

			//Generate subkey

			subkey = key ^ prng(round);
			choise_function = prng(subkey ^ key) % 4;
			bit_rotation_amount = prng(subkey ^ choise_function) % 64;

			//Encryption core function

			switch ( choise_function )
			{
				case 0:
				{
					result = data ^ subkey;
					break;
				}
				case 1:
				{
					result = data ^ subkey;
					result = ~result;
					break;
				}

				case 2:
				{
					result = BaseOperation::rotate_left( data, bit_rotation_amount );
					break;
				}

				case 3:
				{
					result = BaseOperation::rotate_right( data, bit_rotation_amount );
					break;
				}
				default:
					break;
			}

			//Non-linear processing - random bit switching
			//非线性处理 - 随机比特位切换
			result ^= ( 1ULL << bit_rotation_amount );

			result += (BaseOperation::rotate_right(key, 3) ^ BaseOperation::rotate_right(subkey, 11));

			return result;
		}

		std::uint64_t LittleOaldresPuzzle_Cryptic::DecryptionCoreFunction(const std::uint64_t data, const std::uint64_t key, const std::uint64_t round)
		{
			std::uint64_t result;
			std::uint64_t choise_function;
			std::uint64_t bit_rotation_amount;
			std::uint64_t subkey;

			//Generate subkey

			subkey = key ^ prng(round);
			choise_function = prng(subkey ^ key) % 4;
			bit_rotation_amount = prng(subkey ^ choise_function) % 64;

			//Decryption core function

			result = data - (BaseOperation::rotate_right(key, 3) ^ BaseOperation::rotate_right(subkey, 11));

			//Non-linear processing - random bit switching
			//非线性处理 - 随机比特位切换
			result ^= ( 1ULL << bit_rotation_amount );

			switch (choise_function)
			{
				case 0:
				{
					result = result ^ subkey;
					break;
				}
				case 1:
				{
					result = ~result;
					result = result ^ subkey;
					break;
				}
				case 2:
				{
					result = BaseOperation::rotate_right(result, bit_rotation_amount);
					break;
				}
				case 3:
				{
					result = BaseOperation::rotate_left(result, bit_rotation_amount);
					break;
				}
				default:
					break;
			}

			return result;
		}
	}
} // TwilightDreamOfMagical