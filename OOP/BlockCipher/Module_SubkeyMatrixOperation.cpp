#include "Module_SubkeyMatrixOperation.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		namespace ImplementationDetails
		{
			void Module_SubkeyMatrixOperation::ApplyWordDataInitialVector( std::span<const std::uint32_t> WordDataInitialVector )
			{
				auto& RandomQuadWordMatrix = StateDataPointer->RandomQuadWordMatrix;

				//初始采样Word数据 (使用32Bit字 - 数据初始向量)
				//Initial sampling of Word data (Use 32Bit Word Data - Initial Vector)

				std::vector<std::uint32_t> Word32Bit_ExpandedInitialVector = MixTransformationUtilObject.Word32Bit_ExpandKey( WordDataInitialVector );

				volatile std::size_t Index = Word32Bit_ExpandedInitialVector.size();

				std::size_t MatrixRow = RandomQuadWordMatrix.rows();
				std::size_t MatrixColumn = RandomQuadWordMatrix.cols();

			Use32BitData:

				while ( MatrixRow > 0 )
				{
					while ( MatrixColumn > 0 )
					{
						if ( Index == 0 )
							break;

						volatile std::uint64_t RandomValue = Word32Bit_ExpandedInitialVector[ Index - 1 ];
						// Apply a rotation that is relatively prime to 64 (e.g., 5, 7, 11, 13, 17, etc.)
						auto&& RotatedBits = std::rotl( RandomValue, 7 );

						auto& MatrixValue = RandomQuadWordMatrix( MatrixRow - 1, MatrixColumn - 1 );

						//Random bits
						MatrixValue -= RandomValue ^ ( RandomValue & RotatedBits );

						//Switch bit
						MatrixValue ^= ( static_cast<std::uint64_t>( 1 ) << ( RandomValue & std::numeric_limits<std::uint64_t>::digits - 1 ) );

						RandomValue += MatrixValue;
						MatrixValue += RandomValue * 2 + MatrixValue;

						--Index;

						--MatrixColumn;
					}
					--MatrixRow;

					MatrixColumn = RandomQuadWordMatrix.cols();
				}

				if ( MatrixRow == 0 && MatrixColumn == 0 && Index > 0 )
				{
					MatrixRow = RandomQuadWordMatrix.rows();
					MatrixColumn = RandomQuadWordMatrix.cols();

					goto Use32BitData;
				}

				volatile void* CheckPointer = nullptr;

				CheckPointer = memory_set_no_optimize_function<0x00>( Word32Bit_ExpandedInitialVector.data(), Word32Bit_ExpandedInitialVector.size() * sizeof( std::uint32_t ) );
				CheckPointer = nullptr;
			}

			void Module_SubkeyMatrixOperation::InitializationState( std::span<const std::uint64_t> Key )
			{
				volatile void* CheckPointer = nullptr;

				auto& BernoulliDistribution = StateDataPointer->BernoulliDistributionObject;
				auto& RandomQuadWordMatrix = StateDataPointer->RandomQuadWordMatrix;
				auto& LFSR_Object = *( StateDataPointer->LFSR_ClassicPointer );

				std::vector<std::uint8_t> ByteKeys = CommonToolkit::IntegerExchangeBytes::MessageUnpacking<std::uint64_t, std::uint8_t>( Key.data(), Key.size() );

				//通过材料置换框0进行字节数据置换操作
				//Byte data substitution operation via material substitution box 0
				std::ranges::transform( ByteKeys.begin(), ByteKeys.end(), ByteKeys.begin(), [ this ]( const std::uint8_t& byte ) -> std::uint8_t { return MixTransformationUtilObject.MaterialSubstitutionBox0[ MixTransformationUtilObject.MaterialSubstitutionBox0[ byte ] ]; } );

				std::vector<std::uint32_t> Word32Bit_Key = CommonToolkit::IntegerExchangeBytes::MessagePacking<std::uint32_t, std::uint8_t>( ByteKeys.data(), ByteKeys.size() );

				CheckPointer = memory_set_no_optimize_function<0x00>( ByteKeys.data(), ByteKeys.size() );
				CheckPointer = nullptr;
				ByteKeys.resize( 0 );

				//初始采样Word数据 (使用32Bit字 - 密钥向量)
				//Initial sampling of Word data (Use 32Bit Word - Key Vector)
				std::vector<std::uint32_t> Word32Bit_ExpandedKey = MixTransformationUtilObject.Word32Bit_ExpandKey( Word32Bit_Key );

				std::span<std::uint32_t> Word32Bit_ExpandedKeySpan( Word32Bit_ExpandedKey.begin(), Word32Bit_ExpandedKey.end() );

				std::vector<std::uint32_t> Word32Bit_Random( Word32Bit_ExpandedKey.size() / 4, 0 );

				//处理采样Word数据
				//Processing Sampled Word Data
				for ( std::size_t Index = 0, OffsetIndex_WordsMemorySpan = 0; OffsetIndex_WordsMemorySpan + 4 < Word32Bit_ExpandedKeySpan.size() && Index < Word32Bit_Random.size(); OffsetIndex_WordsMemorySpan += 4, ++Index )
				{
					std::span<std::uint32_t> Word32Bit_ExpandedKeySubSpan = Word32Bit_ExpandedKeySpan.subspan( OffsetIndex_WordsMemorySpan, 4 );
					std::uint32_t			 RandomWord = MixTransformationUtilObject.Word32Bit_KeyWithStreamCipherFunction( Word32Bit_ExpandedKeySubSpan ) ^ Word32Bit_ExpandedKeySubSpan[ 3 ];
					Word32Bit_Random[ Index ] = RandomWord;
					RandomWord = 0;
				}

				ByteKeys = CommonToolkit::IntegerExchangeBytes::MessageUnpacking<std::uint32_t, std::uint8_t>( Word32Bit_Random.data(), Word32Bit_Random.size() );

				CheckPointer = memory_set_no_optimize_function<0x00>( Word32Bit_ExpandedKey.data(), Word32Bit_ExpandedKey.size() * sizeof( std::uint32_t ) );
				CheckPointer = nullptr;
				Word32Bit_ExpandedKey.resize( 0 );
				CheckPointer = memory_set_no_optimize_function<0x00>( Word32Bit_Random.data(), Word32Bit_Random.size() * sizeof( std::uint32_t ) );
				CheckPointer = nullptr;
				Word32Bit_Random.resize( 0 );
				CheckPointer = memory_set_no_optimize_function<0x00>( Word32Bit_Key.data(), Word32Bit_Key.size() * sizeof( std::uint32_t ) );
				CheckPointer = nullptr;
				Word32Bit_Key.resize( 0 );

				//通过材料置换框1进行字节数据置换操作
				//Byte data substitution operation via material substitution box 1
				std::ranges::transform( ByteKeys.begin(), ByteKeys.end(), ByteKeys.begin(), [ this ]( const std::uint8_t& byte ) -> std::uint8_t { return MixTransformationUtilObject.MaterialSubstitutionBox1[ MixTransformationUtilObject.MaterialSubstitutionBox1[ byte ] ]; } );

				std::vector<std::uint64_t> Word64Bit_ProcessedKey = CommonToolkit::IntegerExchangeBytes::MessagePacking<std::uint64_t, std::uint8_t>( ByteKeys.data(), ByteKeys.size() );

				CheckPointer = memory_set_no_optimize_function<0x00>( ByteKeys.data(), ByteKeys.size() );
				CheckPointer = nullptr;
				ByteKeys.resize( 0 );

				volatile bool												 Word64Bit_KeyUsed = false;
				std::array<bool, std::numeric_limits<std::uint64_t>::digits> RandomBitsArray {};
				for ( std::size_t row = 0; row < RandomQuadWordMatrix.rows(); ++row )
				{
					for ( std::size_t column = 0; column < RandomQuadWordMatrix.cols(); ++column )
					{
						if ( column + 1 == Word64Bit_ProcessedKey.size() || column + 1 == RandomQuadWordMatrix.cols() )
							Word64Bit_KeyUsed = true;

						if ( Word64Bit_KeyUsed == false )
							RandomQuadWordMatrix( row, column ) -= Word64Bit_ProcessedKey[ column ];
						else
						{
							while ( column < RandomQuadWordMatrix.cols() )
							{
								volatile std::uint64_t RandomNumber = 0;

								for ( auto& RandomBit : RandomBitsArray )
								{
									RandomNumber = static_cast<std::uint64_t>( BernoulliDistribution( LFSR_Object ) ) ^ LFSR_Object();
									RandomBit = static_cast<bool>( RandomNumber & 1 );
								}

								for ( std::size_t BitIndex = 0; BitIndex < std::numeric_limits<std::uint64_t>::digits; BitIndex++ )
								{
									if ( RandomBitsArray[ BitIndex ] )
										RandomNumber |= ( static_cast<std::uint64_t>( RandomBitsArray[ BitIndex ] ) << BitIndex );
									else
										BitIndex++;
								}

								RandomQuadWordMatrix( row, column ) += RandomNumber;

								RandomNumber = 0;

								++column;
							}

							if ( column + 1 < Word64Bit_ProcessedKey.size() )
							{
								Word64Bit_KeyUsed = false;
							}
						}
					}
				}

				CheckPointer = memory_set_no_optimize_function<0x00>( RandomBitsArray.data(), RandomBitsArray.size() );
				CheckPointer = nullptr;

				MixTransformationUtilObject.RegenerationRandomMaterialSubstitutionBox();
			}

			void Module_SubkeyMatrixOperation::UpdateState()
			{
				//http://eigen.tuxfamily.org/dox/group__TutorialReductionsVisitorsBroadcasting.html

				auto& RandomQuadWordMatrix = StateDataPointer->RandomQuadWordMatrix;
				auto& TransformedSubkeyMatrix = StateDataPointer->TransformedSubkeyMatrix;
				auto& NLFSR_Object = *( StateDataPointer->NLFSR_ClassicPointer );
				auto& SDP_Object = *( StateDataPointer->SDP_ClassicPointer );

				Eigen::Matrix<std::uint64_t, 1, Eigen::Dynamic> RandomWordVector = Eigen::Matrix<std::uint64_t, 1, Eigen::Dynamic>::Zero( 1, StateDataPointer->OPC_KeyMatrix_Columns );

				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1> RandomWordVector2 = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>::Zero( StateDataPointer->OPC_KeyMatrix_Rows, 1 );

				//Vector[index] = RandomNumber......
				//Vector2[index] = RandomNumber......

				volatile std::size_t BaseNumber = 0;

				for ( auto Rows : RandomWordVector.rowwise() )
				{
					for ( auto& RoundSubkeyMatrixValue : Rows )
					{
						RoundSubkeyMatrixValue = NLFSR_Object.unpredictable_bits( BaseNumber & 1, 64 );
						++BaseNumber;
					}
				}

				for ( auto Columns : RandomWordVector2.colwise() )
				{
					for ( auto& RoundSubkeyMatrixValue : Columns )
					{
						RoundSubkeyMatrixValue = NLFSR_Object.unpredictable_bits( BaseNumber & 1, 63 );
						++BaseNumber;
					}
				}

				BaseNumber = 0;

				//Affine Transformation
				//https://en.wikipedia.org/wiki/Affine_transformation
				//仿射变换
				//https://zh.wikipedia.org/zh-cn/%E4%BB%BF%E5%B0%84%E5%8F%98%E6%8D%A2
				//LeftMatrix = <Matrix, Vector>(row wise) + Vector2
				//RightMatrix = <Matrix, Vector2>(column wise) - Vector

				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic> LeftMatrix = RandomQuadWordMatrix.array().rowwise() * RandomWordVector.array();
				LeftMatrix.colwise() += RandomWordVector2;

				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic> RightMatrix = RandomQuadWordMatrix.array().colwise() * RandomWordVector2.array();
				RightMatrix.rowwise() -= RandomWordVector;

				//Version 1:
				//RandomQuadWordMatrix = RandomQuadWordMatrix ⊕ (LeftMatrix ⊕ RightMatrix)

				//Version 2:
				//A = LeftMatrix ⊕ (RandomQuadWordMatrix ∧ TransformedSubkeyMatrix)
				//B = RightMatrix ⊕ (RandomQuadWordMatrix ∨ TransformedSubkeyMatrix)
				//RandomQuadWordMatrix = RandomQuadWordMatrix ⊕ ((A >>> 1) + (B <<< 63))

				std::uint64_t A = 0;
				std::uint64_t B = 0;
				for ( std::size_t MatrixRow = 0; MatrixRow < LeftMatrix.rows() && MatrixRow < RightMatrix.rows(); ++MatrixRow )
				{
					for ( std::size_t MatrixColumn = 0; MatrixColumn < LeftMatrix.cols() && MatrixColumn < RightMatrix.cols(); ++MatrixColumn )
					{
						A = LeftMatrix( MatrixRow, MatrixColumn ) ^ ( RandomQuadWordMatrix( MatrixRow, MatrixColumn ) & TransformedSubkeyMatrix( MatrixRow, MatrixColumn ) );
						B = RightMatrix( MatrixRow, MatrixColumn ) ^ ( RandomQuadWordMatrix( MatrixRow, MatrixColumn ) | TransformedSubkeyMatrix( MatrixRow, MatrixColumn ) );
						RandomQuadWordMatrix( MatrixRow, MatrixColumn ) ^= std::rotr( A, 1 ) + std::rotl( B, 63 );
					}
				}

				RandomWordVector.setZero();
				RandomWordVector2.setZero();
				LeftMatrix.setZero();
				RightMatrix.setZero();

				for ( auto Rows : RandomWordVector.rowwise() )
				{
					for ( auto& RoundSubkeyMatrixValue : Rows )
					{
						RoundSubkeyMatrixValue = SDP_Object( std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max() );
					}
				}

				for ( auto Columns : RandomWordVector2.colwise() )
				{
					for ( auto& RoundSubkeyMatrixValue : Columns )
					{
						RoundSubkeyMatrixValue = SDP_Object( std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max() );
					}
				}

				//Tensor product
				//https://en.wikipedia.org/wiki/Tensor_product
				//张量积
				//https://zh.wikipedia.org/zh/%E5%BC%A0%E9%87%8F%E7%A7%AF
				//张量积通常不符合交换律
				//Tensor products usually do not conform to the exchange law
				//<VectorA, VectorB> ≠ <VectorB, VectorA>

				//克罗内克积
				//https://zh.wikipedia.org/wiki/%E5%85%8B%E7%BD%97%E5%86%85%E5%85%8B%E7%A7%AF
				//Kronecker product
				//https://en.wikipedia.org/wiki/Kronecker_product
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic> KroneckerProductMatrix = Eigen::kroneckerProduct( RandomWordVector, RandomWordVector2 ).eval();
				std::uint64_t												 DotProduct = RandomWordVector2.dot( RandomWordVector );

				TransformedSubkeyMatrix = RandomQuadWordMatrix * ( KroneckerProductMatrix * DotProduct );

				KroneckerProductMatrix.setZero();
				DotProduct = 0;
				RandomWordVector.setZero();
				RandomWordVector2.setZero();

				StateDataPointer->ShuffleMatrixOffsetWithRandomIndices();
			}
		}  // namespace ImplementationDetails
	}	   // namespace SED::BlockCipher
}  // namespace TwilightDreamOfMagical::CustomSecurity