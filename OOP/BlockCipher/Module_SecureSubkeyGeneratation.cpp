#include "Module_SecureSubkeyGeneratation.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		namespace ImplementationDetails
		{
			Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>
			TDOM_HashModule::SecureHash
			(
				const Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>& RandomQuadWordMatrix,
				const Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>& IntegerVector
			)
			{
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>
				RandomQuadWordMatrixA = Eigen::Matrix<std::uint64_t,Eigen::Dynamic, Eigen::Dynamic>::Zero(RandomQuadWordMatrix.rows(), RandomQuadWordMatrix.cols());
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>
				IntegerVectorA = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>::Zero(IntegerVector.rows(), 1);
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>
				RandomQuadWordMatrixB = Eigen::Matrix<std::uint64_t,Eigen::Dynamic, Eigen::Dynamic>::Zero(RandomQuadWordMatrix.rows(), RandomQuadWordMatrix.cols());
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>
				IntegerVectorB = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>::Zero(IntegerVector.rows(), 1);

				//Element is 64 bits data, split into high and low 32 bits Data and stored as 64 bits data
				//元素为64位数据，拆分为高低32位数据，存储为64位数据
				for (std::size_t Index = 0; Index < RandomQuadWordMatrix.rows() * RandomQuadWordMatrix.cols(); ++Index)
				{
					std::uint64_t value = RandomQuadWordMatrix.array()(Index);
					RandomQuadWordMatrixA.array()(Index) = value >> 32;
					RandomQuadWordMatrixB.array()(Index) = value & 0xFFFFFFFF;
				}

				for (std::size_t Index = 0; Index < IntegerVector.rows(); ++Index)
				{
					std::uint64_t value = IntegerVector(Index);
					IntegerVectorA.array()(Index) = value >> 32;
					IntegerVectorB.array()(Index) = value & 0xFFFFFFFF;
				}

				//Matrix-vector multiplication using split 32-bit data in stored 64-bit data without any computational overflow
				//在存储的 64 位数据中使用拆分的 32 位数据进行矩阵-向量乘法，没有任何计算溢出
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>
				ResultA = RandomQuadWordMatrixA * IntegerVectorA;
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>
				ResultB = RandomQuadWordMatrixB * IntegerVectorB;

				std::span<std::uint64_t> SpanVectorA(ResultA.data(), ResultA.data() + ResultA.size());
				std::span<std::uint64_t> SpanVectorB(ResultB.data(), ResultB.data() + ResultB.size());

				std::vector<std::uint64_t> CustomHashed(IntegerVector.rows());
				std::span<std::uint64_t> SpanCustomHashed {CustomHashed};
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>
				Hashed = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>::Zero(IntegerVector.rows(), 1);

				CustomSecureHashObject.SpongeHash(SpanVectorA, SpanCustomHashed.subspan(0, IntegerVector.rows() / 2));
				CustomSecureHashObject.SpongeHash(SpanVectorB, SpanCustomHashed.subspan(IntegerVector.rows() / 2, IntegerVector.rows() / 2));

				std::uint64_t HashedValue = 0;
				//After splitting, the matrix-vector multiplication results on both sides are combined using this addition.
				//If there is a calculation overflow, it is guaranteed to use a large prime number for modulo, and the result will not overflow.
				//拆分后，把两边矩阵-向量的乘法结果，使用这个加法合并。
				//如果有计算溢出，保证使用大素数进行取模，则结果不会溢出。
				for(std::size_t row = 0; row < IntegerVector.rows(); ++row)
				{
					//(A + B) mod LargePrimeNumber = ((A mod LargePrimeNumber) + (B mod LargePrimeNumber)) mod LargePrimeNumber
					HashedValue = ( ResultA( row ) % LargePrimeNumber ) + ( ResultB( row ) % LargePrimeNumber ) % LargePrimeNumber;
					Hashed( row ) = ( CustomHashed[ row ] % LargePrimeNumber ) + ( HashedValue % LargePrimeNumber ) % LargePrimeNumber;
				}

				//确保状态矩阵和向量被安全的清理
				//Ensure that the status matrix and vector is securely cleaned
				RandomQuadWordMatrixA.setZero();
				RandomQuadWordMatrixB.setZero();
				IntegerVectorA.setZero();
				IntegerVectorB.setZero();
				ResultA.setZero();
				ResultB.setZero();
				return Hashed;
			}

			void Module_SecureSubkeyGeneratation::LatticeCryptographyAndHash
			(
				std::span<const std::uint64_t> Input,
				std::span<std::uint64_t> Output
			)
			{
				auto& SDP_Object = *(StateDataPointer->SDP_ClassicPointer);
				auto& Rows = StateDataPointer->OPC_KeyMatrix_Rows;
				auto& Columns = StateDataPointer->OPC_KeyMatrix_Columns;
				auto& HashObject = *(this->HashObjectPointer);

				//被哈希过的向量
				//A vector hashed with the result of the hash function
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>
				HashMixedIntegerVector = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>::Zero(Rows, 1);

				//InputX = Input
				::memcpy(HashMixedIntegerVector.data(), Input.data(), Input.size() * sizeof(std::uint64_t));

				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>
				PseudoRandomNumberMatrix = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>::Zero(Rows, Columns);

				//计算哈希过的向量数据替换原向量数据
				//Compute hashed vector data to replace original vector data
				for(std::size_t Index = 0; Index < Rows * Columns; ++Index)
					PseudoRandomNumberMatrix.array()(Index) = SDP_Object(std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max());

				//OutputY = SecureHash(A, InputX)
				HashMixedIntegerVector.noalias() = HashObject.SecureHash( PseudoRandomNumberMatrix, HashMixedIntegerVector ).eval();

				//Mixed = InputX + OutputY (mod LargePrimeNumber)
				//原向量数据和哈希过的向量数据做具有大模数的大整数的加法，然后变成一个被哈希混合过的向量
				//The original vector data and the hashed vector data are added with a large integer with a large modulus, and then become a hash-mixed vector
				for ( std::size_t index = 0; index < HashMixedIntegerVector.size(); index++ )
				{
					const std::uint64_t& a = Input[index % Input.size()];
					const std::uint64_t& b = HashMixedIntegerVector( index );
					std::uint64_t& c = Output[index];

					if ( c == 0 )
						c = ( a + b >= TDOM_HashModule::LargePrimeNumber ) ? a + b - TDOM_HashModule::LargePrimeNumber : a + b;
					else
					{
						std::uint64_t d = ( a + b >= TDOM_HashModule::LargePrimeNumber ) ? a + b - TDOM_HashModule::LargePrimeNumber : a + b;
						c = ( c + d >= TDOM_HashModule::LargePrimeNumber ) ? c + d - TDOM_HashModule::LargePrimeNumber : c + d;
					}
				}

				//确保状态向量被安全的清理
				//Ensure that the status vector is securely cleaned
				HashMixedIntegerVector.setZero();
			}

			void Module_SecureSubkeyGeneratation::GenerationSubkeys(std::span<const std::uint64_t> WordKeyDataVector)
			{
				auto& KeyBlockSize = StateDataPointer->OPC_QuadWord_KeyBlockSize;
				auto& Rows = StateDataPointer->OPC_KeyMatrix_Rows;

				/*
					比特数据混淆层
					Bits Data Confusion Layer
				*/
				if(!WordKeyDataVector.empty())
				{
					my_cpp2020_assert(WordKeyDataVector.size() % KeyBlockSize == 0, "", std::source_location::current());
					std::vector<std::uint64_t> WordKeyResistQC(Rows, 0);
					this->LatticeCryptographyAndHash(WordKeyDataVector, WordKeyResistQC);
					this->SubkeyMatrixOperationObject.InitializationState(WordKeyResistQC);
					memory_set_no_optimize_function<0x00>(WordKeyResistQC.data(), WordKeyResistQC.size() * sizeof(std::uint64_t));
				}

				this->SubkeyMatrixOperationObject.UpdateState();
			}

		}
	}
}