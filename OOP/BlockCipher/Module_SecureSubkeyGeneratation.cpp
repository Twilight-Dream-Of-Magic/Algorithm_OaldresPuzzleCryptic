#include "Module_SecureSubkeyGeneratation.hpp"
#include "ExtraIncludes/MontgomeryScalarEigen.hpp"

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
				const Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1>&              IntegerVector
			)
			{
				using TwilightDreamOfMagical::PrimeField::Montgomery64;
				using TwilightDreamOfMagical::PrimeField::MontgomeryComputationScope;
				using TwilightDreamOfMagical::PrimeField::MontgomeryPrimeFieldContext;

				// 1) 建立 64 位蒙哥马利域上下文（模数为 LargePrimeNumber）。
				//    Create 64-bit Montgomery field context (modulus = LargePrimeNumber).
				MontgomeryPrimeFieldContext prime_field_context(TDOM_HashModule::LargePrimeNumber);

				// 2) 开启作用域：将上下文注入到自定义标量的线程局部环境。
				//    Enter scope: inject the context into the custom scalar's thread-local environment.
				MontgomeryComputationScope scope(prime_field_context);

				// 3) 将普通矩阵/向量映射为“蒙哥马利域内部表示”。入域只做一次，后续全在域内完成。
				//    Map plain matrix/vector to Montgomery representation. Enter the field once; stay inside for the whole product.
				Eigen::Matrix<Montgomery64, Eigen::Dynamic, Eigen::Dynamic> matrix_in_field(RandomQuadWordMatrix.rows(),
																							RandomQuadWordMatrix.cols());
				Eigen::Matrix<Montgomery64, Eigen::Dynamic, 1>              vector_in_field(IntegerVector.rows());

				// 入域矩阵（每个元素先取模再转为域内表示）。
				// Map matrix to field (reduce then convert to Montgomery form).
				for (ptrdiff_t row = 0; row < matrix_in_field.rows(); ++row)
					for (ptrdiff_t col = 0; col < matrix_in_field.cols(); ++col)
						matrix_in_field(row, col) = Montgomery64::FromStandard(RandomQuadWordMatrix(row, col));

				// 入域向量。
				// Map vector to field.
				for (ptrdiff_t index = 0; index < vector_in_field.rows(); ++index)
					vector_in_field(index) = Montgomery64::FromStandard(IntegerVector(index));

				// 4) 直接调用 Eigen 乘法核：此时 “*” 与 “+” 均为蒙哥马利域操作（无除法）。
				//    Call Eigen's GEMV: now '*' and '+' are Montgomery ops (division-free modular arithmetic).
				//    y_m = A_m * x_m  (all in Montgomery domain)
				Eigen::Matrix<Montgomery64, Eigen::Dynamic, 1> vector_product_in_field = (matrix_in_field * vector_in_field).eval();

				// 5) 出域：把域内结果转换为普通余数 [0, p)。
				//    Leave the field: convert back to standard residues in [0, p).
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1> product_vector(vector_product_in_field.rows());
				for (ptrdiff_t row = 0; row < vector_product_in_field.rows(); ++row)
					product_vector(row) = vector_product_in_field(row).ToStandard();

				// 6) 将 y 作为输入喂给海绵函数，得到等长的杂合向量 h。
				//    Feed y into the sponge to get an equal-length mixed vector h.
				std::span<std::uint64_t> span_product(product_vector.data(), static_cast<size_t>(product_vector.size()));

				std::vector<std::uint64_t> sponge_hashed(static_cast<size_t>(IntegerVector.rows()));
				std::span<std::uint64_t>   span_sponge_hashed(sponge_hashed.data(), sponge_hashed.size());

				// 约定：海绵的 rate 为 64 比特；每吸收/挤压一个 64 位字后立刻搅拌（实现已在自定义哈希内部保证）。
				// Convention: sponge rate is 64 bits; each 64-bit word absorbed/squeezed is followed by a state permutation (guaranteed inside your hash).
				CustomSecureHashObject.SpongeHash(span_product, span_sponge_hashed);

				// 7) 逐元素做 y + h (mod p)；使用“条件减法”实现常时间模加。
				//    Compute y + h (mod p) element-wise; use conditional subtraction (branchless-friendly) for constant-time style add.
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, 1> hashed_result(IntegerVector.rows());
				for (ptrdiff_t row = 0; row < hashed_result.rows(); ++row)
				{
					const std::uint64_t a = product_vector(row);
					const std::uint64_t b = sponge_hashed[static_cast<size_t>(row)];
					const std::uint64_t sum = a + b;
					hashed_result(row) = (sum >= TDOM_HashModule::LargePrimeNumber || sum < a)
										 ? (sum - TDOM_HashModule::LargePrimeNumber)
										 : sum;
				}

				// 8) 清理局部敏感状态。注意：形参是 const，不能也不需要清空外部传入对象。
				//    Wipe local sensitive state. Note: parameters are const; do NOT zero external inputs.
				
				// 域内矩阵/向量（Montgomery64 按字节清零）
				memory_set_no_optimize_function<0x00>( matrix_in_field.data(), static_cast<size_t>( matrix_in_field.size() ) * sizeof( Montgomery64 ) );
				memory_set_no_optimize_function<0x00>( vector_in_field.data(), static_cast<size_t>( vector_in_field.size() ) * sizeof( Montgomery64 ) );

				// 乘积（域内）也顺手抹掉（如果还在作用域内）
				memory_set_no_optimize_function<0x00>( vector_product_in_field.data(), static_cast<size_t>(vector_product_in_field.size()) * sizeof(Montgomery64) );

				// 海绵输出与标准余数向量
				memory_set_no_optimize_function<0x00>( sponge_hashed.data(), sponge_hashed.size() * sizeof( std::uint64_t ) );
				memory_set_no_optimize_function<0x00>( product_vector.data(), static_cast<size_t>( product_vector.size() ) * sizeof( std::uint64_t ) );

				// 9) 返回哈希混合后的向量。
				//    Return the hash-mixed vector.
				return hashed_result;
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
				//The pseudo-random matrix elements are generated by a double-pendulum simulation random number generator, which maps to the prime field Z_p.
				for ( std::size_t ElementIndex = 0; ElementIndex < Rows * Columns; ++ElementIndex )
				{
					std::uint64_t Raw64 = 0;
					do
					{
						Raw64 = SDP_Object( std::numeric_limits<std::uint64_t>::min(), std::numeric_limits<std::uint64_t>::max() );
					} while ( Raw64 >= TDOM_HashModule::UnbiasedThreshold );
					PseudoRandomNumberMatrix.data()[ ElementIndex ] = Raw64 % TDOM_HashModule::LargePrimeNumber;  // Z_p [0, p-1]
				}

				//OutputY = SecureHash(A, InputX)
				HashMixedIntegerVector.noalias() = HashObject.SecureHash( PseudoRandomNumberMatrix, HashMixedIntegerVector ).eval();

				//Mixed = InputX + OutputY (mod LargePrimeNumber)
				//原向量数据和哈希过的向量数据做具有大模数的大整数的加法，然后变成一个被哈希混合过的向量
				//The original vector data and the hashed vector data are added with a large integer with a large modulus, and then become a hash-mixed vector
				for ( std::size_t index = 0; index < (size_t)HashMixedIntegerVector.size(); index++ )
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