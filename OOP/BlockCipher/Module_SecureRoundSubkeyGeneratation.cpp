#include "Module_SecureRoundSubkeyGeneratation.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		namespace ImplementationDetails
		{
			void Module_SecureRoundSubkeyGeneratation::OPC_MatrixTransformation()
			{
				//https://eigen.tuxfamily.org/dox/group__TutorialSTL.html

				auto& RandomQuadWordMatrix = StateDataPointer->RandomQuadWordMatrix;
				auto& TransformedSubkeyMatrix = StateDataPointer->TransformedSubkeyMatrix;

				#if 1
				//先把“和/差”各自 materialize，避免在乘法里重复遍历/转置
				const auto TransformedSubkeyMatrixTranspose = TransformedSubkeyMatrix.transpose();
				const auto RandomQuadWordMatrixTranspose    = RandomQuadWordMatrix.transpose();

				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic> LHS =
					(RandomQuadWordMatrix + TransformedSubkeyMatrixTranspose).eval();
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic> RHS =
					(TransformedSubkeyMatrix - RandomQuadWordMatrixTranspose).eval();

				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic> TemporaryIntegerMartix;
				// 避免 (X*Y).adjoint() 产生“巨大临时” —— 用 (Y^T * X^T)
				TemporaryIntegerMartix.noalias() = RHS.transpose() * LHS.transpose();
				// 注：整数域里 adjoint == transpose；这么写能直接让 Eigen 走两次 GEMM，而不是先乘后整体转置。

				// 链式乘：把更可复用的右侧先做出来，再一次性与 Temporary 相乘并累加
				const auto RightOnce = (RandomQuadWordMatrix * TransformedSubkeyMatrix).eval();
				this->GeneratedRoundSubkeyMatrix.noalias() += TemporaryIntegerMartix * RightOnce;
				#else
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic> TemporaryIntegerMartix = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>::Zero( StateDataPointer->OPC_KeyMatrix_Rows, StateDataPointer->OPC_KeyMatrix_Columns );

				//TemporaryIntegerMartix = ( RandomQuadWordMatrix + transpose(TransformedSubkeyMatrix) ) * ( TransformedSubkeyMatrix - transpose(RandomQuadWordMatrix) ) -> adjoint()
				TemporaryIntegerMartix.noalias() = ( ( RandomQuadWordMatrix + TransformedSubkeyMatrix.transpose() ) * ( TransformedSubkeyMatrix - RandomQuadWordMatrix.transpose() ) ).adjoint();
				this->GeneratedRoundSubkeyMatrix.noalias() += TemporaryIntegerMartix * RandomQuadWordMatrix * TransformedSubkeyMatrix;
				#endif
				/*
					注意，如果这段代码被注释掉，虽然可以显著提高OaldresPuzzle-Cryptic算法的运行速度。
					但是，它有可能被外部破解者用汇编调试器分析出来，所以为了安全起见，请仔细考虑之后再选择修改！!
					Note that if this code is commented out, it can significantly improve the running speed of the OaldresPuzzle-Cryptic algorithm though.
					However, it could be analyzed by an external cracker with an assembly debugger, so please consider carefully before choosing to modify it for safety reasons!!!
				*/
				//确保状态矩阵被安全的清理
				//Ensure that the status matrix is securely cleaned
				TemporaryIntegerMartix.setZero();
			}

			#if 0

			void GenerateDiffusionLayerPermuteIndices()
			{
				std::array<std::unordered_set<std::uint32_t>, 16> DiffusionLayerMatrixIndex
				{
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
					std::unordered_set<std::uint32_t>{},
				};

				std::array<std::uint32_t, 32> ArrayIndexData
				{
					//0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
					25,9,27,18,11,2,26,7,12,24,5,17,6,1,10,3,21,30,8,20,0,29,4,13,19,14,23,16,22,31,28,15
				};

				std::vector<std::uint32_t> VectorIndexData(ArrayIndexData.begin(), ArrayIndexData.end());

				CommonSecurity::RNG_ISAAC::isaac64<8> CSPRNG;
				CommonSecurity::RND::UniformIntegerDistribution<std::uint32_t> UniformDistribution;

				for(std::size_t Round = 0; Round < 10223; ++Round)
				{
					for(std::size_t X = 0; X < DiffusionLayerMatrixIndex.size(); ++X )
					{
						std::unordered_set<std::uint32_t> HashSet;
						while(HashSet.size() != 16)
						{
							std::uint32_t RandomIndex = UniformDistribution(CSPRNG) % 32;
							while (RandomIndex >= VectorIndexData.size())
							{
								RandomIndex = UniformDistribution(CSPRNG) % 32;
							}
							HashSet.insert(VectorIndexData[RandomIndex]);
							VectorIndexData.erase(VectorIndexData.begin() + RandomIndex);

							if(VectorIndexData.empty())
							{
								CommonSecurity::ShuffleRangeData(ArrayIndexData.begin(), ArrayIndexData.end(), CSPRNG);
								VectorIndexData = std::vector<std::uint32_t>(ArrayIndexData.begin(), ArrayIndexData.end());
							}
						}
						DiffusionLayerMatrixIndex[X] = HashSet;

						if(VectorIndexData.empty())
						{
							CommonSecurity::ShuffleRangeData(ArrayIndexData.begin(), ArrayIndexData.end(), CSPRNG);
							VectorIndexData = std::vector<std::uint32_t>(ArrayIndexData.begin(), ArrayIndexData.end());
						}
					}
				}

				for( std::size_t X = DiffusionLayerMatrixIndex.size(); X > 0; --X )
				{
					for(const auto& Value : DiffusionLayerMatrixIndex[X - 1] )
						std::cout << "KeyStateX" << "[" << Value << "]" << ", ";

					std::cout << "\n";
				}

				std::cout << std::endl;

				for(std::size_t Round = 0; Round < 10223; ++Round)
				{
					for(std::size_t X = DiffusionLayerMatrixIndex.size(); X > 0; --X )
					{
						std::unordered_set<std::uint32_t> HashSet;
						while(HashSet.size() != 16)
						{
							std::uint32_t RandomIndex = UniformDistribution(CSPRNG) % 32;
							while (RandomIndex >= VectorIndexData.size())
							{
								RandomIndex = UniformDistribution(CSPRNG) % 32;
							}
							HashSet.insert(VectorIndexData[RandomIndex]);
							VectorIndexData.erase(VectorIndexData.begin() + RandomIndex);

							if(VectorIndexData.empty())
							{
								CommonSecurity::ShuffleRangeData(ArrayIndexData.begin(), ArrayIndexData.end(), CSPRNG);
								VectorIndexData = std::vector<std::uint32_t>(ArrayIndexData.begin(), ArrayIndexData.end());
							}
						}
						DiffusionLayerMatrixIndex[X - 1] = HashSet;

						if(VectorIndexData.empty())
						{
							CommonSecurity::ShuffleRangeData(ArrayIndexData.begin(), ArrayIndexData.end(), CSPRNG);
							VectorIndexData = std::vector<std::uint32_t>(ArrayIndexData.begin(), ArrayIndexData.end());
						}
					}
				}

				for( std::size_t X = 0; X < DiffusionLayerMatrixIndex.size(); ++X )
				{
					for(const auto& Value : DiffusionLayerMatrixIndex[X] )
						std::cout << "KeyStateX" << "[" << Value << "]" << ", ";

					std::cout << "\n";
				}

				std::cout << std::endl;
			}

			#endif

			void Module_SecureRoundSubkeyGeneratation::GenerationRoundSubkeys()
			{
				volatile void* CheckPointer = nullptr;

				if ( this->MatrixTransformationCounter == 0 )
				{
					CheckPointer = memory_set_no_optimize_function<0x00>( GeneratedRoundSubkeyVector.data(), GeneratedRoundSubkeyVector.size() * sizeof( std::uint64_t ) );
					CheckPointer = nullptr;

					GeneratedRoundSubkeyMatrix.setZero();
				}

				this->OPC_MatrixTransformation();

				//密钥白化
				//Key whitening
				//https://en.wikipedia.org/wiki/Key_whitening

				std::size_t KeyVectorIndex = 0;
				while ( KeyVectorIndex < GeneratedRoundSubkeyVector.size() )
				{
					GeneratedRoundSubkeyVector[ KeyVectorIndex ] ^= GeneratedRoundSubkeyMatrix.array()( KeyVectorIndex );
					++KeyVectorIndex;
				}

				std::vector<std::uint64_t> TransformedRoundSubkeyVector( StateDataPointer->OPC_KeyMatrix_Rows * StateDataPointer->OPC_KeyMatrix_Columns, 0 );

				std::span<std::uint64_t>	   NewRoundSubkeyVectorSpan( TransformedRoundSubkeyVector.begin(), TransformedRoundSubkeyVector.end() );
				std::span<const std::uint64_t> RoundSubkeyVectorSpan( GeneratedRoundSubkeyVector.begin(), GeneratedRoundSubkeyVector.end() );

				/*
						比特数据扩散层
						Bits data diffusion layer

						数据雪崩效应进行扩散
						Data avalanche effect for diffusion
					*/
				for ( std::size_t Index = 0; Index < RoundSubkeyVectorSpan.size(); Index += 32 )
				{
					std::span<const std::uint64_t> KeyStateX = RoundSubkeyVectorSpan.subspan( Index, 32 );
					std::span<std::uint64_t>	   KeyStateY = NewRoundSubkeyVectorSpan.subspan( Index, 32 );

					/*

					该排列的常数Index来源于,上面注释的GenerateDiffusionLayerPermuteIndices(函数/算法).
					The constant Index of this alignment comes from, the (function/algorithm) annotated above.

					伪代码:
					Pseudocode:

					MatrixA, MatrixB from KeyStateX
					VectorA, VectorB from KeyStateY
					VectorA is KeyStateY[0] ... KeyStateY[15]
					VectorB is KeyStateY[16] ... KeyStateY[31]

					//把长向量当成一个矩阵的视图来看
					//View the long vector as a matrix
					KeyStateMatrixX = ViewRangeMatrix(KeyStateX)
					KeyStateMatrixY = ViewRangeMatrix(KeyStateY)

					VectorA, VectorB = Split(KeyStateMatrixY)
					MatrixA, MatrixB = Split(KeyStateMatrixX)
					StateMatrixY[Index] = BinaryDiffusion(MatrixA, MatrixB, VectorA, VectorB)
						Vectorα = BinaryMultiplicationWithGaloisFiniteField(VectorA, MatrixA)
						Vectorβ = BinaryMultiplicationWithGaloisFiniteField(VectorB, MatrixB)
						Vectorα, Vectorβ ∈ GaloisFiniteField(power(2, 64))
						return Concat(Vectorα, Vectorβ)

					*/

					KeyStateY[ 0 ] = KeyStateX[ 24 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 12 ];
					KeyStateY[ 1 ] = KeyStateX[ 19 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 16 ];
					KeyStateY[ 2 ] = KeyStateX[ 4 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 25 ];
					KeyStateY[ 3 ] = KeyStateX[ 11 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 9 ];
					KeyStateY[ 4 ] = KeyStateX[ 21 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 1 ];
					KeyStateY[ 5 ] = KeyStateX[ 15 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 14 ];
					KeyStateY[ 6 ] = KeyStateX[ 16 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 3 ];
					KeyStateY[ 7 ] = KeyStateX[ 12 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 7 ];
					KeyStateY[ 8 ] = KeyStateX[ 7 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 21 ];
					KeyStateY[ 9 ] = KeyStateX[ 19 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 11 ];
					KeyStateY[ 10 ] = KeyStateX[ 25 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 28 ];
					KeyStateY[ 11 ] = KeyStateX[ 0 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 2 ];
					KeyStateY[ 12 ] = KeyStateX[ 9 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 22 ];
					KeyStateY[ 13 ] = KeyStateX[ 12 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 15 ];
					KeyStateY[ 14 ] = KeyStateX[ 7 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 8 ];
					KeyStateY[ 15 ] = KeyStateX[ 20 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 5 ];

					KeyStateY[ 16 ] = KeyStateX[ 7 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 21 ];
					KeyStateY[ 17 ] = KeyStateX[ 19 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 11 ];
					KeyStateY[ 18 ] = KeyStateX[ 25 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 28 ];
					KeyStateY[ 19 ] = KeyStateX[ 0 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 2 ];
					KeyStateY[ 20 ] = KeyStateX[ 9 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 22 ];
					KeyStateY[ 21 ] = KeyStateX[ 12 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 15 ];
					KeyStateY[ 22 ] = KeyStateX[ 7 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 8 ];
					KeyStateY[ 23 ] = KeyStateX[ 20 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 5 ];
					KeyStateY[ 24 ] = KeyStateX[ 31 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 30 ];
					KeyStateY[ 25 ] = KeyStateX[ 0 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 19 ];
					KeyStateY[ 26 ] = KeyStateX[ 18 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 13 ];
					KeyStateY[ 27 ] = KeyStateX[ 17 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 6 ];
					KeyStateY[ 28 ] = KeyStateX[ 27 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 4 ] ^ KeyStateX[ 13 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 10 ];
					KeyStateY[ 29 ] = KeyStateX[ 28 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 31 ] ^ KeyStateX[ 21 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 20 ];
					KeyStateY[ 30 ] = KeyStateX[ 13 ] ^ KeyStateX[ 5 ] ^ KeyStateX[ 3 ] ^ KeyStateX[ 19 ] ^ KeyStateX[ 25 ] ^ KeyStateX[ 8 ] ^ KeyStateX[ 18 ] ^ KeyStateX[ 28 ] ^ KeyStateX[ 22 ] ^ KeyStateX[ 7 ] ^ KeyStateX[ 11 ] ^ KeyStateX[ 10 ] ^ KeyStateX[ 14 ] ^ KeyStateX[ 2 ] ^ KeyStateX[ 17 ] ^ KeyStateX[ 31 ];
					KeyStateY[ 31 ] = KeyStateX[ 21 ] ^ KeyStateX[ 6 ] ^ KeyStateX[ 30 ] ^ KeyStateX[ 12 ] ^ KeyStateX[ 20 ] ^ KeyStateX[ 24 ] ^ KeyStateX[ 23 ] ^ KeyStateX[ 26 ] ^ KeyStateX[ 29 ] ^ KeyStateX[ 0 ] ^ KeyStateX[ 9 ] ^ KeyStateX[ 1 ] ^ KeyStateX[ 15 ] ^ KeyStateX[ 27 ] ^ KeyStateX[ 16 ] ^ KeyStateX[ 4 ];
				}

				GeneratedRoundSubkeyVector = TransformedRoundSubkeyVector;

				CheckPointer = memory_set_no_optimize_function<0x00>( TransformedRoundSubkeyVector.data(), TransformedRoundSubkeyVector.size() * sizeof( std::uint64_t ) );
				CheckPointer = nullptr;

				++( this->MatrixTransformationCounter );
			}

			std::array<std::uint32_t, 2> Module_SecureRoundSubkeyGeneratation::ForwardTransform( std::uint32_t LeftWordData, std::uint32_t RightWordData )
			{
				//Pseudo-Hadamard Transformation (Forward)
				auto A = LeftWordData + RightWordData;
				auto B = LeftWordData + RightWordData * 2;

				B ^= std::rotl( A, 1 );
				A ^= std::rotr( B, 63 );

				return { A, B };
			}

			std::array<std::uint32_t, 2> Module_SecureRoundSubkeyGeneratation::BackwardTransform( std::uint32_t LeftWordData, std::uint32_t RightWordData )
			{
				LeftWordData ^= std::rotr( RightWordData, 63 );
				RightWordData ^= std::rotl( LeftWordData, 1 );

				//Pseudo-Hadamard Transformation (Backward)
				auto B = RightWordData - LeftWordData;
				auto A = 2 * LeftWordData - RightWordData;

				return { A, B };
			}

			std::uint32_t Module_SecureRoundSubkeyGeneratation::CrazyTransformAssociatedWord( std::uint32_t AssociatedWordData, const std::uint64_t WordKeyMaterial )
			{
				std::array<std::uint32_t, 2> BitReorganizationWord { 0, 0 };

				auto& [ WordA, WordB ] = BitReorganizationWord;

				//将64位（字）的密钥材料的左右两半应用于2个32位（字）的数据
				//Apply the left and right halves of the 64-bit (word) key material to the 2 32-bit (word) data
				const std::uint32_t LeftWordKey = static_cast<std::uint32_t>( static_cast<std::uint64_t>( WordKeyMaterial & 0xFFFFFFFF00000000ULL ) >> static_cast<std::uint64_t>( 32 ) );
				const std::uint32_t RightWordKey = static_cast<std::uint32_t>( static_cast<std::uint64_t>( WordKeyMaterial & 0x00000000FFFFFFFFULL ) );

				//Unidirectional function（单射函数）
				//2个内存字的非线性单射变换函数（相当于应用不可逆元的字节替换盒?）
				//根据每一轮的数据和密钥，会产生不同的结果
				//Non-linear one-shot transformation function for 2 memory words (equivalent to applying a byte substitution box of irreversible elements?)
				//Depending on the data and key of each round, different results are produced

				const std::uint64_t PseudoRandomValue = ( ( WordKeyMaterial ^ static_cast<std::uint64_t>( AssociatedWordData ) ) << 32 ) | ( ( ~WordKeyMaterial ^ static_cast<std::uint64_t>( AssociatedWordData ) ) >> 32 );

				//对伪随机值进行位移操作，生成两个32位无符号整数(WordC, WordD)
				//Perform bit shifts on the pseudo-random value to generate two 32-bit unsigned integers(WordC, WordD)
				const unsigned s = static_cast<unsigned>(WordKeyMaterial & 63u);
				std::uint32_t WordC = static_cast<std::uint32_t>((PseudoRandomValue << s) >> 32);
				std::uint32_t WordD = static_cast<std::uint32_t>( PseudoRandomValue >> s);

				//混合AssociatedWordData, LeftWordKey, RightWordKey的数据给WordC, WordD
				//Mix the data of AssociatedWordData, LeftWordKey, RightWordKey to WordC, WordD
				WordC = ( AssociatedWordData | LeftWordKey ) & WordC;
				WordD = ( AssociatedWordData & RightWordKey ) | WordD;

				WordA ^= WordC;
				WordB ^= WordD;

				//使用比特旋转和伪随机值，做混合WordA, WordB, LeftWordKey, RightWordKey的数据给WordA, WordB
				//Use bit rotation and pseudo-random values to do mix WordA, WordB, LeftWordKey, RightWordKey data to WordA, WordB
				WordA = std::rotl( WordA + LeftWordKey, PseudoRandomValue % 32 );
				WordB = std::rotr( WordB + RightWordKey, PseudoRandomValue % 32 );

				//混合WordA, WordB, LeftWordKey, RightWordKey, WordC, WordD, AssociatedWordData的数据给WordC, WordD
				//Mix the data of WordA, WordB, LeftWordKey, RightWordKey, WordC, WordD, AssociatedWordData to WordC, WordD
				WordC = ( WordB & ~LeftWordKey ) ^ ( WordD | AssociatedWordData );
				WordD = ( WordA & ~RightWordKey ) ^ ( WordC | AssociatedWordData );

				WordA ^= WordC;
				WordB ^= WordD;

				//访问一个引用在共同密钥状态数据中，被洗牌的表示矩阵Rows和Columns的元素的数组
				//Accesses an array that references the elements of the representation matrix Rows and Columns that are shuffled in the common key state data.
				auto& MatrixOffsetWithRandomIndices = StateDataPointer->MatrixOffsetWithRandomIndices;
				auto& TransformedRoundSubkeyMatrix = this->GeneratedRoundSubkeyMatrix;

				//用转换后的WordA和WordB值获取轮密钥矩阵中的行和列索引
				//Obtain row and column indices into the round subkey matrix using the transformed WordA and WordB values
				const std::uint32_t& Row = MatrixOffsetWithRandomIndices[ WordA % MatrixOffsetWithRandomIndices.size() ];
				const std::uint32_t& Column = MatrixOffsetWithRandomIndices[ WordB % MatrixOffsetWithRandomIndices.size() ];

				//const std::uint32_t& Row = WordA % TransformedRoundSubkeyMatrix.rows();
				//const std::uint32_t& Column = WordB % TransformedRoundSubkeyMatrix.cols();

				//计算移位和旋转量以提取轮密钥位
				//Compute shift and rotate amounts to extract the round subkey bit
				std::uint32_t ShiftAmount = ( WordA + WordB ), ShiftAmount2 = ( WordA + WordB * 2 );
				std::uint32_t RotateAmount = ( Column - Row ), RotateAmount2 = ( 2 * Row - Column );

				std::uint64_t RoundSubkey = TransformedRoundSubkeyMatrix.coeff( Row, Column );

				//在RoundSubkey中均匀地选择两个比特，无论那是0还是1
				//In RoundSubkey evenly select two bits, whether that is 0 or 1.
				std::uint64_t RoundSubkeyBit = ( RoundSubkey >> ShiftAmount % 64 ) & 1;
				std::uint64_t RoundSubkeyBit2 = ( RoundSubkey >> ShiftAmount2 % 64 ) & 1;

				//把选中的两个比特位用比特旋转左或者右，然后变成一个比特掩码
				//Take the two selected bits and rotate them left or right with bits and turn them into a bit mask.
				std::uint64_t LeftRotatedMask = std::rotl( RoundSubkeyBit, RotateAmount % 64 );
				std::uint64_t RightRotatedMask = std::rotr( RoundSubkeyBit2, RotateAmount2 % 64 );

				//计算合并的比特掩码，如果它是0，就需要重新生成比特掩码
				//Compute the merged bitmask, if it is 0, you need to regenerate the bitmask
				std::uint64_t BitMask = LeftRotatedMask ^ RightRotatedMask;
				if ( BitMask == 0 )
				{
					BitMask |= ( 1ULL << ( ( Row + Column ) * 2 % 64 ) );
				}
				RoundSubkey &= ~BitMask;

				//将64位（字）的密钥材料的左右两半应用于2个32位（字）的数据
				//Apply the left and right halves of the 64-bit (word) key material to the 2 32-bit (word) data
				WordA ^= static_cast<std::uint32_t>( static_cast<std::uint64_t>( RoundSubkey & 0xFFFFFFFF00000000ULL ) >> static_cast<std::uint64_t>( 32 ) );
				WordB ^= static_cast<std::uint32_t>( static_cast<std::uint64_t>( RoundSubkey & 0x00000000FFFFFFFFULL ) );

				AssociatedWordData ^= ( WordA ^ WordB );

				return AssociatedWordData;
			}
		}  // namespace ImplementationDetails
	}	   // namespace SED::BlockCipher
}  // namespace TwilightDreamOfMagical::CustomSecurity