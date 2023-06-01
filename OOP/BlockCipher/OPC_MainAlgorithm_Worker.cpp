#include "OPC_MainAlgorithm_Worker.hpp"
#include "./Includes/KeyDerivationFunction/Scrypt.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	namespace SED::BlockCipher
	{
		void OPC_MainAlgorithm_Worker::SplitDataBlockToEncrypt(std::span<std::uint64_t> PlainText, std::span<const std::uint64_t> Keys)
		{
			using TwilightDreamOfMagical::CustomSecurity::CryptionMode2MCAC4_FDW;
			auto& DataBlockSize = AlgorithmCorePointer->StateDataPointer->OPC_QuadWord_DataBlockSize;
			auto& KeyBlockSize = AlgorithmCorePointer->StateDataPointer->OPC_QuadWord_KeyBlockSize;

			/*
				Tips 提示
				对于二进制计算机来说，一个数字a是modulo b，这相当于用b减1然后和a做比特AND运算 (b 应该是2的幂)。
				For a binary computer, a number a is modulo b, which is equivalent to subtracting 1 from b and then doing a bitwise AND operation with a (b should be a power of 2)
			*/

			if( ( PlainText.size() & (DataBlockSize - 1) ) != 0)
				my_cpp2020_assert(false, "StateData_Worker: The size of PlainText is not a multiple of OPC_QuadWord_DataBlockSize!", std::source_location::current());
			if( ( Keys.size() & (KeyBlockSize - 1) ) != 0)
				my_cpp2020_assert(false, "StateData_Worker: The size of (Encryption)Keys is not a multiple of OPC_QuadWord_KeyBlockSize!", std::source_location::current());

			volatile void* CheckPointer = nullptr;

			volatile std::size_t Word64Bit_Key_OffsetIndex = 0;

			auto& WordKeyDataVector = AlgorithmCorePointer->StateDataPointer->WordKeyDataVector;
			std::ranges::copy(Keys.begin(), Keys.begin() + WordKeyDataVector.size(), WordKeyDataVector.begin());
			Word64Bit_Key_OffsetIndex += KeyBlockSize;

			std::vector<std::uint64_t> RandomWordKeyDataVector(KeyBlockSize * 2, 0);

			volatile bool ConditionControlFlag = true;

			//生成代表"盐渍"的伪随机数
			//Generate a pseudo-random number representing "salted"
			std::mt19937_64 MersenneTwister64Bit;

			const std::size_t PlainTextSize = PlainText.size();
			for ( std::size_t DataBlockOffset = 0; DataBlockOffset < PlainTextSize; DataBlockOffset += DataBlockSize )
			{
				if(Word64Bit_Key_OffsetIndex < Keys.size())
				{
					std::span<const std::uint64_t> KeyByteSpan { Keys.begin() + Word64Bit_Key_OffsetIndex, Keys.begin() + Word64Bit_Key_OffsetIndex + KeyBlockSize };

					//使用你的主密钥数据
					//Use your master key data
					std::ranges::transform
						(
							KeyByteSpan.begin(),
							KeyByteSpan.end(),
							WordKeyDataVector.begin(),
							WordKeyDataVector.end(),
							WordKeyDataVector.begin(),
							[](const std::uint64_t& left, const std::uint64_t& right)
							{
								if(left == right)
									return ~(left + right);
								else
									return left ^ right;
							}
						);

					Word64Bit_Key_OffsetIndex += KeyBlockSize;

					//主密钥未使用时，应该更新WordKeyDataVector
					//The WordKeyDataVector should be updated when the master key is not used
					this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys(WordKeyDataVector);

					++(this->RoundSubkeysCounter);
				}
				else
				{
					using CommonSecurity::KeyDerivationFunction::Scrypt;
					using CommonToolkit::IntegerExchangeBytes::MessagePacking;
					using CommonToolkit::IntegerExchangeBytes::MessageUnpacking;

					//主密钥使用完毕之后，无需更新WordKeyDataVector，直接使用这个函数
					//After the used of the master key, no need to update the WordKeyDataVector, directly using this function

					if( ConditionControlFlag || ((this->RoundSubkeysCounter % (2048ULL * 4ULL)) == 0) )
					{
						for(std::size_t KeyRound = 0; KeyRound < 16; ++KeyRound)
						{
							//Bit-level data diffusion algorithm
							for (size_t i = 0; i < WordKeyDataVector.size(); i++)
							{
								std::uint64_t a = WordKeyDataVector[i] >> 32;
								std::uint64_t b = WordKeyDataVector[i] & 0xFFFFFFFF;

								//Apply bitwise operations to diffuse bits
								a ^= b;
								a = ~a;
								b ^= a;
								b = std::rotl(b, 19);
								a ^= b;
								a = std::rotl(a, 13);
								b ^= a;
								b = ~b;
								a ^= b;
								a = std::rotl(a, 27);
								b ^= a;
								b = std::rotl(b, 23);

								WordKeyDataVector[i] = (a << 32) | b;
							}

							std::vector<std::uint8_t> KeyBytes(KeyBlockSize * sizeof(std::uint64_t), 0);

							//Call Byte-level data confusion algorithm
							MessageUnpacking<std::uint64_t, std::uint8_t>( WordKeyDataVector, KeyBytes.data() );
							this->AlgorithmCorePointer->ByteSubstitution(KeyBytes, CryptionMode2MCAC4_FDW::MCA_ENCRYPTER);
							MessagePacking<std::uint64_t, std::uint8_t>( KeyBytes, WordKeyDataVector.data() );
						}

						this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys(WordKeyDataVector);
						ConditionControlFlag = false;

						++(this->RoundSubkeysCounter);
						continue;
					}

					if((this->RoundSubkeysCounter % 2048ULL) == 0)
					{
						std::array<std::uint64_t, 16> SaltWordData {};
						std::ranges::generate_n( SaltWordData.begin(), SaltWordData.size(), MersenneTwister64Bit );

						if((this->RoundSubkeysCounter % (2048ULL * 3ULL)) == 0)
						{
							std::array<std::uint8_t, 16 * sizeof( std::uint64_t )> SaltData {};
							MessageUnpacking<std::uint64_t, std::uint8_t>( SaltWordData, SaltData.data() );

							std::vector<std::uint8_t> MaterialKeys = MessageUnpacking<std::uint64_t, std::uint8_t>( RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() );
							Scrypt					  KDF_Object;
							std::vector<std::uint8_t> GeneratedSecureKeys = KDF_Object.GenerateKeys( MaterialKeys, SaltData, RandomWordKeyDataVector.size() * sizeof( std::uint64_t ), 1024, 8, 16 );
							MessagePacking<std::uint64_t, std::uint8_t>( GeneratedSecureKeys, RandomWordKeyDataVector.data() );

							//使用通过密钥派生函数的生成的数据，而不使用主密钥数据
							//Use the data generated by the key derivation function without using the master key data
							this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( RandomWordKeyDataVector );

							CheckPointer = memory_set_no_optimize_function<0x00>( SaltWordData.data(), SaltWordData.size() * sizeof( std::uint64_t ) );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( SaltData.data(), SaltData.size() );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( MaterialKeys.data(), MaterialKeys.size() );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedSecureKeys.data(), GeneratedSecureKeys.size() );
							CheckPointer = nullptr;
							GeneratedSecureKeys.clear();
							GeneratedSecureKeys.shrink_to_fit();
						}
						else if((this->RoundSubkeysCounter % (2048ULL * 2ULL)) == 0)
						{
							std::array<std::uint8_t, 16 * sizeof( std::uint64_t )> SaltData {};
							MessageUnpacking<std::uint64_t, std::uint8_t>( SaltWordData, SaltData.data() );

							std::vector<std::uint8_t> MaterialKeys = MessageUnpacking<std::uint64_t, std::uint8_t>( RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() );
							Scrypt					  KDF_Object;
							std::vector<std::uint8_t> GeneratedSecureKeys = KDF_Object.GenerateKeys( MaterialKeys, SaltData, RandomWordKeyDataVector.size() * sizeof( std::uint64_t ), 1024, 8, 16 );
							MessagePacking<std::uint64_t, std::uint8_t>( GeneratedSecureKeys, RandomWordKeyDataVector.data() );

							//使用通过密钥派生函数的生成的数据，而不使用主密钥数据
							//Use the data generated by the key derivation function without using the master key data
							this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( RandomWordKeyDataVector );
							std::seed_seq Seeds = std::seed_seq( RandomWordKeyDataVector.begin(), RandomWordKeyDataVector.end() );
							MersenneTwister64Bit.seed( Seeds );

							CheckPointer = memory_set_no_optimize_function<0x00>( SaltWordData.data(), SaltWordData.size() * sizeof( std::uint64_t ) );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( SaltData.data(), SaltData.size() );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( MaterialKeys.data(), MaterialKeys.size() );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedSecureKeys.data(), GeneratedSecureKeys.size() );
							CheckPointer = nullptr;
							GeneratedSecureKeys.clear();
							GeneratedSecureKeys.shrink_to_fit();
						}

						const std::vector<std::uint64_t> EmptyData {};
						this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( EmptyData );
					}

					++(this->RoundSubkeysCounter);
				}

				std::span<std::uint64_t> DataByteSpan { PlainText.begin() + DataBlockOffset, PlainText.begin() + DataBlockOffset + DataBlockSize };

				this->AlgorithmCorePointer->RoundFunction(DataByteSpan, CryptionMode2MCAC4_FDW::MCA_ENCRYPTER);
			}

			if(PlainText.size() == DataBlockSize)
				this->AlgorithmCorePointer->RoundFunction(PlainText, CryptionMode2MCAC4_FDW::MCA_ENCRYPTER);

			this->RoundSubkeysCounter = 0;
			CheckPointer = memory_set_no_optimize_function<0x00>(RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
		}

		void OPC_MainAlgorithm_Worker::SplitDataBlockToDecrypt( std::span<std::uint64_t> CipherText, std::span<const std::uint64_t> Keys )
		{
			using TwilightDreamOfMagical::CustomSecurity::CryptionMode2MCAC4_FDW;
			auto& DataBlockSize = AlgorithmCorePointer->StateDataPointer->OPC_QuadWord_DataBlockSize;
			auto& KeyBlockSize = AlgorithmCorePointer->StateDataPointer->OPC_QuadWord_KeyBlockSize;

			/*
				Tips 提示
				对于二进制计算机来说，一个数字a是modulo b，这相当于用b减1然后和a做比特AND运算 (b 应该是2的幂)。
				For a binary computer, a number a is modulo b, which is equivalent to subtracting 1 from b and then doing a bitwise AND operation with a (b should be a power of 2)
			*/

			if( ( CipherText.size() & (DataBlockSize - 1) ) != 0)
				my_cpp2020_assert(false, "StateData_Worker: The size of CipherText is not a multiple of OPC_QuadWord_DataBlockSize!", std::source_location::current());
			if( ( Keys.size() & (KeyBlockSize - 1) ) != 0)
				my_cpp2020_assert(false, "StateData_Worker: The size of (Decryption)Keys is not a multiple of OPC_QuadWord_KeyBlockSize!", std::source_location::current());

			volatile void* CheckPointer = nullptr;

			volatile std::size_t Word64Bit_Key_OffsetIndex = 0;

			auto& WordKeyDataVector = AlgorithmCorePointer->StateDataPointer->WordKeyDataVector;
			std::ranges::copy(Keys.begin(), Keys.begin() + WordKeyDataVector.size(), WordKeyDataVector.begin());
			Word64Bit_Key_OffsetIndex += KeyBlockSize;

			std::vector<std::uint64_t> RandomWordKeyDataVector(KeyBlockSize * 2, 0);

			volatile bool ConditionControlFlag = true;

			//生成代表"盐渍"的伪随机数
			//Generate a pseudo-random number representing "salted"
			std::mt19937_64 MersenneTwister64Bit;

			const std::size_t CipherTextSize = CipherText.size();
			for ( std::size_t DataBlockOffset = 0; DataBlockOffset < CipherTextSize; DataBlockOffset += DataBlockSize )
			{
				if(Word64Bit_Key_OffsetIndex < Keys.size())
				{
					std::span<const std::uint64_t> KeyByteSpan { Keys.begin() + Word64Bit_Key_OffsetIndex, Keys.begin() + Word64Bit_Key_OffsetIndex + KeyBlockSize };

					//使用你的主密钥数据
					//Use your master key data
					std::ranges::transform
						(
							KeyByteSpan.begin(),
							KeyByteSpan.end(),
							WordKeyDataVector.begin(),
							WordKeyDataVector.end(),
							WordKeyDataVector.begin(),
							[](const std::uint64_t& left, const std::uint64_t& right)
							{
								if(left == right)
									return ~(left + right);
								else
									return left ^ right;
							}
						);

					Word64Bit_Key_OffsetIndex += KeyBlockSize;

					//主密钥未使用时，应该更新WordKeyDataVector
					//The WordKeyDataVector should be updated when the master key is not used
					this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys(WordKeyDataVector);

					++(this->RoundSubkeysCounter);
				}
				else
				{
					using CommonSecurity::KeyDerivationFunction::Scrypt;
					using CommonToolkit::IntegerExchangeBytes::MessagePacking;
					using CommonToolkit::IntegerExchangeBytes::MessageUnpacking;

					//主密钥使用完毕之后，无需更新WordKeyDataVector，直接使用这个函数
					//After the used of the master key, no need to update the WordKeyDataVector, directly using this function

					if( ConditionControlFlag || ((this->RoundSubkeysCounter % (2048ULL * 4ULL)) == 0) )
					{
						for(std::size_t KeyRound = 0; KeyRound < 16; ++KeyRound)
						{
							//Bit-level data diffusion algorithm
							for (size_t i = 0; i < WordKeyDataVector.size(); i++)
							{
								std::uint64_t a = WordKeyDataVector[i] >> 32;
								std::uint64_t b = WordKeyDataVector[i] & 0xFFFFFFFF;

								//Apply bitwise operations to diffuse bits
								a ^= b;
								a = ~a;
								b ^= a;
								b = std::rotl(b, 19);
								a ^= b;
								a = std::rotl(a, 13);
								b ^= a;
								b = ~b;
								a ^= b;
								a = std::rotl(a, 27);
								b ^= a;
								b = std::rotl(b, 23);

								WordKeyDataVector[i] = (a << 32) | b;
							}

							std::vector<std::uint8_t> KeyBytes(KeyBlockSize * sizeof(std::uint64_t), 0);

							//Call Byte-level data confusion algorithm
							MessageUnpacking<std::uint64_t, std::uint8_t>( WordKeyDataVector, KeyBytes.data() );
							this->AlgorithmCorePointer->ByteSubstitution(KeyBytes, CryptionMode2MCAC4_FDW::MCA_ENCRYPTER);
							MessagePacking<std::uint64_t, std::uint8_t>( KeyBytes, WordKeyDataVector.data() );
						}

						this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys(WordKeyDataVector);
						ConditionControlFlag = false;

						++(this->RoundSubkeysCounter);
						continue;
					}

					if((this->RoundSubkeysCounter % 2048ULL) == 0)
					{
						std::array<std::uint64_t, 16> SaltWordData {};
						std::ranges::generate_n( SaltWordData.begin(), SaltWordData.size(), MersenneTwister64Bit );

						if((this->RoundSubkeysCounter % (2048ULL * 3ULL)) == 0)
						{
							std::array<std::uint8_t, 16 * sizeof( std::uint64_t )> SaltData {};
							MessageUnpacking<std::uint64_t, std::uint8_t>( SaltWordData, SaltData.data() );

							std::vector<std::uint8_t> MaterialKeys = MessageUnpacking<std::uint64_t, std::uint8_t>( RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() );
							Scrypt					  KDF_Object;
							std::vector<std::uint8_t> GeneratedSecureKeys = KDF_Object.GenerateKeys( MaterialKeys, SaltData, RandomWordKeyDataVector.size() * sizeof( std::uint64_t ), 1024, 8, 16 );
							MessagePacking<std::uint64_t, std::uint8_t>( GeneratedSecureKeys, RandomWordKeyDataVector.data() );

							//使用通过密钥派生函数的生成的数据，而不使用主密钥数据
							//Use the data generated by the key derivation function without using the master key data
							this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( RandomWordKeyDataVector );

							CheckPointer = memory_set_no_optimize_function<0x00>( SaltWordData.data(), SaltWordData.size() * sizeof( std::uint64_t ) );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( SaltData.data(), SaltData.size() );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( MaterialKeys.data(), MaterialKeys.size() );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedSecureKeys.data(), GeneratedSecureKeys.size() );
							CheckPointer = nullptr;
							GeneratedSecureKeys.clear();
							GeneratedSecureKeys.shrink_to_fit();
						}
						else if((this->RoundSubkeysCounter % (2048ULL * 2ULL)) == 0)
						{
							std::array<std::uint8_t, 16 * sizeof( std::uint64_t )> SaltData {};
							MessageUnpacking<std::uint64_t, std::uint8_t>( SaltWordData, SaltData.data() );

							std::vector<std::uint8_t> MaterialKeys = MessageUnpacking<std::uint64_t, std::uint8_t>( RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() );
							Scrypt					  KDF_Object;
							std::vector<std::uint8_t> GeneratedSecureKeys = KDF_Object.GenerateKeys( MaterialKeys, SaltData, RandomWordKeyDataVector.size() * sizeof( std::uint64_t ), 1024, 8, 16 );
							MessagePacking<std::uint64_t, std::uint8_t>( GeneratedSecureKeys, RandomWordKeyDataVector.data() );

							//使用通过密钥派生函数的生成的数据，而不使用主密钥数据
							//Use the data generated by the key derivation function without using the master key data
							this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( RandomWordKeyDataVector );
							std::seed_seq Seeds = std::seed_seq( RandomWordKeyDataVector.begin(), RandomWordKeyDataVector.end() );
							MersenneTwister64Bit.seed( Seeds );

							CheckPointer = memory_set_no_optimize_function<0x00>( SaltWordData.data(), SaltWordData.size() * sizeof( std::uint64_t ) );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( SaltData.data(), SaltData.size() );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( MaterialKeys.data(), MaterialKeys.size() );
							CheckPointer = nullptr;
							CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedSecureKeys.data(), GeneratedSecureKeys.size() );
							CheckPointer = nullptr;
							GeneratedSecureKeys.clear();
							GeneratedSecureKeys.shrink_to_fit();
						}

						const std::vector<std::uint64_t> EmptyData {};
						this->AlgorithmCorePointer->SecureSubkeyGeneratationModuleObject.GenerationSubkeys( EmptyData );
					}

					++(this->RoundSubkeysCounter);
				}

				std::span<std::uint64_t> DataByteSpan { CipherText.begin() + DataBlockOffset, CipherText.begin() + DataBlockOffset + DataBlockSize };

				this->AlgorithmCorePointer->RoundFunction(DataByteSpan, CryptionMode2MCAC4_FDW::MCA_DECRYPTER);
			}

			if(CipherText.size() == DataBlockSize)
				this->AlgorithmCorePointer->RoundFunction(CipherText, CryptionMode2MCAC4_FDW::MCA_DECRYPTER);

			this->RoundSubkeysCounter = 0;
			CheckPointer = memory_set_no_optimize_function<0x00>(RandomWordKeyDataVector.data(), RandomWordKeyDataVector.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
		}

		std::vector<std::uint8_t> OPC_MainAlgorithm_Worker::EncrypterMain(const std::vector<std::uint8_t>& PlainText, const std::vector<std::uint8_t>& Keys)
		{
			using CommonToolkit::IntegerExchangeBytes::MessagePacking;
			using CommonToolkit::IntegerExchangeBytes::MessageUnpacking;

			volatile void* CheckPointer = nullptr;

			std::vector<std::uint8_t> CipherText(PlainText);
			this->PaddingData(CipherText);

			auto Word64Bit_MasterKey = MessagePacking<std::uint64_t, std::uint8_t>(Keys.data(), Keys.size());
			auto Word64Bit_Data = MessagePacking<std::uint64_t, std::uint8_t>(CipherText.data(), CipherText.size());

			CheckPointer = memory_set_no_optimize_function<0x00>(CipherText.data(), CipherText.size());
			CheckPointer = nullptr;
			CipherText.clear();
			CipherText.shrink_to_fit();

			this->SplitDataBlockToEncrypt(Word64Bit_Data, Word64Bit_MasterKey);

			CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_MasterKey.data(), Word64Bit_MasterKey.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			Word64Bit_MasterKey.clear();
			Word64Bit_MasterKey.shrink_to_fit();

			CipherText = MessageUnpacking<std::uint64_t, std::uint8_t>(Word64Bit_Data.data(), Word64Bit_Data.size());

			CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_Data.data(), Word64Bit_Data.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			Word64Bit_Data.clear();
			Word64Bit_Data.shrink_to_fit();

			return CipherText;
		}

		std::vector<std::uint8_t> OPC_MainAlgorithm_Worker::DecrypterMain(const std::vector<std::uint8_t>& CipherText, const std::vector<std::uint8_t>& Keys)
		{
			using CommonToolkit::IntegerExchangeBytes::MessagePacking;
			using CommonToolkit::IntegerExchangeBytes::MessageUnpacking;

			volatile void* CheckPointer = nullptr;

			std::vector<std::uint8_t> PlainText(CipherText);

			auto Word64Bit_MasterKey = MessagePacking<std::uint64_t, std::uint8_t>(Keys.data(), Keys.size());
			auto Word64Bit_Data = MessagePacking<std::uint64_t, std::uint8_t>(PlainText.data(), PlainText.size());

			CheckPointer = memory_set_no_optimize_function<0x00>(PlainText.data(), PlainText.size());
			CheckPointer = nullptr;
			PlainText.clear();
			PlainText.shrink_to_fit();

			this->SplitDataBlockToDecrypt(Word64Bit_Data, Word64Bit_MasterKey);

			CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_MasterKey.data(), Word64Bit_MasterKey.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			Word64Bit_MasterKey.clear();
			Word64Bit_MasterKey.shrink_to_fit();

			PlainText = MessageUnpacking<std::uint64_t, std::uint8_t>(Word64Bit_Data.data(), Word64Bit_Data.size());

			CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_Data.data(), Word64Bit_Data.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			Word64Bit_Data.clear();
			Word64Bit_Data.shrink_to_fit();

			this->UnpaddingData(PlainText);

			return PlainText;
		}

		std::vector<std::uint8_t> OPC_MainAlgorithm_Worker::EncrypterMainWithoutPadding(const std::vector<std::uint8_t>& PlainText, const std::vector<std::uint8_t>& Keys)
		{
			using CommonToolkit::IntegerExchangeBytes::MessagePacking;
			using CommonToolkit::IntegerExchangeBytes::MessageUnpacking;

			volatile void* CheckPointer = nullptr;

			std::vector<std::uint8_t> CipherText(PlainText);

			auto Word64Bit_MasterKey = MessagePacking<std::uint64_t, std::uint8_t>(Keys.data(), Keys.size());
			auto Word64Bit_Data = MessagePacking<std::uint64_t, std::uint8_t>(CipherText.data(), CipherText.size());

			CheckPointer = memory_set_no_optimize_function<0x00>(CipherText.data(), CipherText.size());
			CheckPointer = nullptr;
			CipherText.clear();
			CipherText.shrink_to_fit();

			this->SplitDataBlockToEncrypt(Word64Bit_Data, Word64Bit_MasterKey);

			CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_MasterKey.data(), Word64Bit_MasterKey.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			Word64Bit_MasterKey.clear();
			Word64Bit_MasterKey.shrink_to_fit();

			CipherText = MessageUnpacking<std::uint64_t, std::uint8_t>(Word64Bit_Data.data(), Word64Bit_Data.size());

			CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_Data.data(), Word64Bit_Data.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			Word64Bit_Data.clear();
			Word64Bit_Data.shrink_to_fit();

			return CipherText;
		}

		std::vector<std::uint8_t> OPC_MainAlgorithm_Worker::DecrypterMainWithoutUnpadding(const std::vector<std::uint8_t>& CipherText, const std::vector<std::uint8_t>& Keys)
		{
			using CommonToolkit::IntegerExchangeBytes::MessagePacking;
			using CommonToolkit::IntegerExchangeBytes::MessageUnpacking;

			volatile void* CheckPointer = nullptr;

			std::vector<std::uint8_t> PlainText(CipherText);

			auto Word64Bit_MasterKey = MessagePacking<std::uint64_t, std::uint8_t>(Keys.data(), Keys.size());
			auto Word64Bit_Data = MessagePacking<std::uint64_t, std::uint8_t>(PlainText.data(), PlainText.size());

			CheckPointer = memory_set_no_optimize_function<0x00>(PlainText.data(), PlainText.size());
			CheckPointer = nullptr;
			PlainText.clear();
			PlainText.shrink_to_fit();

			this->SplitDataBlockToDecrypt(Word64Bit_Data, Word64Bit_MasterKey);

			CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_MasterKey.data(), Word64Bit_MasterKey.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			Word64Bit_MasterKey.clear();
			Word64Bit_MasterKey.shrink_to_fit();

			PlainText = MessageUnpacking<std::uint64_t, std::uint8_t>(Word64Bit_Data.data(), Word64Bit_Data.size());

			CheckPointer = memory_set_no_optimize_function<0x00>(Word64Bit_Data.data(), Word64Bit_Data.size() * sizeof(std::uint64_t));
			CheckPointer = nullptr;
			Word64Bit_Data.clear();
			Word64Bit_Data.shrink_to_fit();

			return PlainText;
		}
	}  // namespace SED::BlockCipher
}  // namespace TwilightDreamOfMagical::CustomSecurity