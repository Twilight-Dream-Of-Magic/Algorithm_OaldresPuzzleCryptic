#include "OaldresPuzzle_Cryptic.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		std::uint64_t OaldresPuzzle_Cryptic::LaiMasseyFramework( std::uint64_t WordData, std::uint64_t WordKeyMaterial, TwilightDreamOfMagical::CustomSecurity::CryptionMode2MCAC4_FDW ThisExecuteMode )
		{
			using CommonToolkit::IntegerExchangeBytes::ByteSwap::byteswap;
			using TwilightDreamOfMagical::CustomSecurity::CryptionMode2MCAC4_FDW;

			/*
				L' = H-Forward(L ⊕ F(L ⊕ R, K[++n]))
				R' = R ⊕ F(L ⊕ R, K[++n])

				L = H-Backward(L') ⊕ F(H-Backward(L') ⊕ R', K[--n])
				R = R' ⊕ F(H-Backward(L') ⊕ R', K[--n])

				H-Backward(L') = L ⊕ F(L ⊕ R, K[--n])
				H-Backward(L') ⊕ R' = L ⊕ F(L ⊕ R, K[--n]) ⊕ R ⊕ F(L ⊕ R, K[--n]) = L ⊕ R
			*/

			switch ( ThisExecuteMode )
			{
				case CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
				{
					if constexpr ( std::endian::native == std::endian::big )
					{
						WordData = byteswap( WordData );
					}

					//L,R = PlainText
					std::uint32_t LeftWordData = static_cast<std::uint32_t>( static_cast<std::uint64_t>( WordData & 0xFFFFFFFF00000000ULL ) >> static_cast<std::uint64_t>( 32 ) );
					std::uint32_t RightWordData = static_cast<std::uint32_t>( static_cast<std::uint64_t>( WordData & 0x00000000FFFFFFFFULL ) );

					const std::uint32_t TransformKey = SecureRoundSubkeyGeneratationModuleObject.CrazyTransformAssociatedWord( LeftWordData ^ RightWordData, WordKeyMaterial );

					//L'' = L' ⊕ TK
					LeftWordData ^= TransformKey;
					//R'' = R' ⊕ TK
					RightWordData ^= TransformKey;

					std::array<std::uint32_t, 2> HalfRoundDataArray = SecureRoundSubkeyGeneratationModuleObject.ForwardTransform( LeftWordData, RightWordData );

					//CipherText = L, R
					std::uint64_t ProcessedWordData = static_cast<std::uint64_t>( static_cast<std::uint64_t>( HalfRoundDataArray[ 0 ] ) << static_cast<std::uint64_t>( 32 ) | static_cast<std::uint64_t>( HalfRoundDataArray[ 1 ] ) );

					if constexpr ( std::endian::native == std::endian::big )
					{
						ProcessedWordData = byteswap( ProcessedWordData );
					}

					LeftWordData = 0;
					RightWordData = 0;
					//HalfRoundDataArray.fill(0);

					return ProcessedWordData;
				}
				case CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
				{
					if constexpr ( std::endian::native == std::endian::big )
					{
						WordData = byteswap( WordData );
					}

					//L,R = CipherText
					std::uint32_t LeftWordData = static_cast<std::uint32_t>( static_cast<std::uint64_t>( WordData & 0xFFFFFFFF00000000ULL ) >> static_cast<std::uint64_t>( 32 ) );
					std::uint32_t RightWordData = static_cast<std::uint32_t>( static_cast<std::uint64_t>( WordData & 0x00000000FFFFFFFFULL ) );

					std::array<std::uint32_t, 2> HalfRoundDataArray = SecureRoundSubkeyGeneratationModuleObject.BackwardTransform( LeftWordData, RightWordData );

					const std::uint32_t TransformKey = SecureRoundSubkeyGeneratationModuleObject.CrazyTransformAssociatedWord( HalfRoundDataArray[ 0 ] ^ HalfRoundDataArray[ 1 ], WordKeyMaterial );

					//R' = R'' ⊕ TK
					HalfRoundDataArray[ 1 ] ^= TransformKey;
					//L' = L'' ⊕ TK
					HalfRoundDataArray[ 0 ] ^= TransformKey;

					//PlainText = L, R
					std::uint64_t ProcessedWordData = static_cast<std::uint64_t>( static_cast<std::uint64_t>( HalfRoundDataArray[ 0 ] ) << static_cast<std::uint64_t>( 32 ) | static_cast<std::uint64_t>( HalfRoundDataArray[ 1 ] ) );

					if constexpr ( std::endian::native == std::endian::big )
					{
						ProcessedWordData = byteswap( ProcessedWordData );
					}

					LeftWordData = 0;
					RightWordData = 0;
					//HalfRoundDataArray.fill(0);

					return ProcessedWordData;
				}
				default:
					my_cpp2020_assert( false, "Invalid cipher base work mode !", std::source_location::current() );
			}

			return WordData;
		}

		void OaldresPuzzle_Cryptic::ByteSubstitution( std::span<std::uint8_t> EachRoundDatas, TwilightDreamOfMagical::CustomSecurity::CryptionMode2MCAC4_FDW ThisExecuteMode )
		{
			using TwilightDreamOfMagical::CustomSecurity::CryptionMode2MCAC4_FDW;

			if ( ( EachRoundDatas.size() & 7 ) != 0 )
				return;

			/*
				字节数据置换层
				Byte Data Substitution Layer
			*/
			switch ( ThisExecuteMode )
			{
				case CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
				{
					for ( std::uint64_t Index = 0; Index < EachRoundDatas.size(); Index += 8 )
					{
						EachRoundDatas[ Index ] = ForwardSubstitutionBox1[ EachRoundDatas[ Index ] ];
						EachRoundDatas[ Index + 1 ] = ForwardSubstitutionBox0[ EachRoundDatas[ Index + 1 ] ];
						EachRoundDatas[ Index + 2 ] = BackwardSubstitutionBox1[ EachRoundDatas[ Index + 2 ] ];
						EachRoundDatas[ Index + 3 ] = BackwardSubstitutionBox0[ EachRoundDatas[ Index + 3 ] ];

						EachRoundDatas[ Index + 4 ] = ForwardSubstitutionBox0[ EachRoundDatas[ Index + 4 ] ];
						EachRoundDatas[ Index + 5 ] = BackwardSubstitutionBox1[ EachRoundDatas[ Index + 5 ] ];
						EachRoundDatas[ Index + 6 ] = ForwardSubstitutionBox0[ EachRoundDatas[ Index + 6 ] ];
						EachRoundDatas[ Index + 7 ] = BackwardSubstitutionBox1[ EachRoundDatas[ Index + 7 ] ];
					}

					break;
				}
				case CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
				{
					for ( std::uint64_t Index = 0; Index < EachRoundDatas.size(); Index += 8 )
					{
						EachRoundDatas[ Index ] = BackwardSubstitutionBox1[ EachRoundDatas[ Index ] ];
						EachRoundDatas[ Index + 1 ] = BackwardSubstitutionBox0[ EachRoundDatas[ Index + 1 ] ];
						EachRoundDatas[ Index + 2 ] = ForwardSubstitutionBox1[ EachRoundDatas[ Index + 2 ] ];
						EachRoundDatas[ Index + 3 ] = ForwardSubstitutionBox0[ EachRoundDatas[ Index + 3 ] ];

						EachRoundDatas[ Index + 4 ] = BackwardSubstitutionBox0[ EachRoundDatas[ Index + 4 ] ];
						EachRoundDatas[ Index + 5 ] = ForwardSubstitutionBox1[ EachRoundDatas[ Index + 5 ] ];
						EachRoundDatas[ Index + 6 ] = BackwardSubstitutionBox0[ EachRoundDatas[ Index + 6 ] ];
						EachRoundDatas[ Index + 7 ] = ForwardSubstitutionBox1[ EachRoundDatas[ Index + 7 ] ];
					}

					break;
				}

				default:
					my_cpp2020_assert( false, "Invalid cipher base work mode !", std::source_location::current() );
			}
		}

		void OaldresPuzzle_Cryptic::RoundFunction( std::span<std::uint64_t> EachRoundDatas, TwilightDreamOfMagical::CustomSecurity::CryptionMode2MCAC4_FDW ThisExecuteMode )
		{
			using CommonToolkit::IntegerExchangeBytes::MessagePacking;
			using CommonToolkit::IntegerExchangeBytes::MessageUnpacking;
			using TwilightDreamOfMagical::CustomSecurity::CryptionMode2MCAC4_FDW;

			if ( EachRoundDatas.size() != StateDataPointer->OPC_QuadWord_DataBlockSize )
				return;

			/*
				每轮数据的数据变换函数
				Data transformation function for each round data
			*/
			switch ( ThisExecuteMode )
			{
				case CryptionMode2MCAC4_FDW::MCA_ENCRYPTER:
				{
					auto& GeneratedRoundSubkeyVector = this->SecureRoundSubkeyGeneratationModuleObject.UseRoundSubkeyVectorReference();

					std::vector<std::uint8_t> BytesData( EachRoundDatas.size() * sizeof( std::uint64_t ), 0 );

					std::size_t KeyIndex = 0;

					//生成用于轮函数的子密钥(不是原来子密钥！)
					//Generate a subkey for the round function (not the original subkey!)

					SecureRoundSubkeyGeneratationModuleObject.GenerationRoundSubkeys();

					for ( std::size_t RoundCounter = 0; RoundCounter < 16; ++RoundCounter )
					{
					DoEncryptionDataBlock:

						//L[0], R[0] --> L[N + 1], R[N + 1]
						//K[0] --> K[N]
						//正向应用RoundIndex (Index, KeyIndex) 和加密函数
						//Forward apply RoundIndex (Index, KeyIndex) and the encryption function
						for ( std::uint64_t Index = 0; Index < EachRoundDatas.size(); Index++ )
						{
							EachRoundDatas[ Index ] = this->LaiMasseyFramework( EachRoundDatas[ Index ], GeneratedRoundSubkeyVector[ KeyIndex ], ThisExecuteMode );

							if ( KeyIndex < GeneratedRoundSubkeyVector.size() )
								++KeyIndex;
						}

						if ( KeyIndex < GeneratedRoundSubkeyVector.size() )
						{
							goto DoEncryptionDataBlock;
						}
						else
						{
							KeyIndex = 0;
						}

						//非线性字节数据代换(编码函数)
						//Nonlinear byte data substitution (encoding function)

						MessageUnpacking<std::uint64_t, std::uint8_t>( EachRoundDatas, BytesData.data() );

						this->ByteSubstitution( BytesData, ThisExecuteMode );

						MessagePacking<std::uint64_t, std::uint8_t>( BytesData, EachRoundDatas.data() );

						//向右循环移动元素
						//Circularly move elements to the right
						//std::ranges::rotate(EachRoundDatas.begin(), EachRoundDatas.begin() + 1, EachRoundDatas.end());
					}

					KeyIndex = 0;

					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>( BytesData.data(), BytesData.size() );
					if ( CheckPointer != BytesData.data() )
					{
						std::cout << "Force Memory Fill Has Been \"Optimization\" !" << std::endl;
						throw std::runtime_error( "" );
					}
					CheckPointer = nullptr;

					break;
				}
				case CryptionMode2MCAC4_FDW::MCA_DECRYPTER:
				{
					auto& GeneratedRoundSubkeyVector = this->SecureRoundSubkeyGeneratationModuleObject.UseRoundSubkeyVectorReference();

					std::vector<std::uint8_t> BytesData( EachRoundDatas.size() * sizeof( std::uint64_t ), 0 );

					std::size_t KeyIndex = GeneratedRoundSubkeyVector.size();

					//生成用于轮函数的子密钥(不是原来子密钥！)
					//Generate a subkey for the round function (not the original subkey!)

					SecureRoundSubkeyGeneratationModuleObject.GenerationRoundSubkeys();

					for ( std::size_t RoundCounter = 0; RoundCounter < 16; ++RoundCounter )
					{
						//向左循环移动元素
						//Circularly move elements to the left
						//std::ranges::rotate(EachRoundDatas.begin(), EachRoundDatas.end() - 1, EachRoundDatas.end());

						//非线性字节数据代换(解码函数)
						//Nonlinear byte data substitution (decoding function)

						MessageUnpacking<std::uint64_t, std::uint8_t>( EachRoundDatas, BytesData.data() );

						this->ByteSubstitution( BytesData, ThisExecuteMode );

						MessagePacking<std::uint64_t, std::uint8_t>( BytesData, EachRoundDatas.data() );

					DoDecryptionDataBlock:

						//L[N + 1], R[N + 1] --> L[0], R[0]
						//K[N] --> K[0]
						//反向应用RoundIndex (Index, KeyIndex) 和解密函数
						//Backward apply RoundIndex (Index, KeyIndex) and the decryption function
						for ( std::uint64_t Index = EachRoundDatas.size(); Index > 0; Index-- )
						{
							EachRoundDatas[ Index - 1 ] = this->LaiMasseyFramework( EachRoundDatas[ Index - 1 ], GeneratedRoundSubkeyVector[ KeyIndex - 1 ], ThisExecuteMode );

							if ( KeyIndex - 1 > 0 )
								--KeyIndex;
						}

						if ( KeyIndex - 1 > 0 )
						{
							goto DoDecryptionDataBlock;
						}
						else
						{
							KeyIndex = GeneratedRoundSubkeyVector.size();
						}
					}

					KeyIndex = 0;

					volatile void* CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>( BytesData.data(), BytesData.size() );
					if ( CheckPointer != BytesData.data() )
					{
						std::cout << "Force Memory Fill Has Been \"Optimization\" !" << std::endl;
						throw std::runtime_error( "" );
					}
					CheckPointer = nullptr;

					break;
				}

				default:
					my_cpp2020_assert( false, "Invalid cipher base work mode !", std::source_location::current() );
			}
		}
	}  // namespace SED::BlockCipher
}  // namespace TwilightDreamOfMagical::CustomSecurity
