#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_MODULES_OALDRESPUZZLE_CRYPTIC_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_MODULES_OALDRESPUZZLE_CRYPTIC_HPP

#include <eigen/Eigen/Dense>
#include <eigen/unsupported/Eigen/KroneckerProduct>
#include <eigen/unsupported/Eigen/FFT>

#include "../../BitRotation.hpp"
#include "../../RandomNumberDistribution.hpp"
#include "Includes/PRNGs.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::BlockCipher
	{
		/*
			Implementation of Custom Data Encrypting Worker and Decrypting Worker
			自定义加密和解密数据工作器的实现

			OaldresPuzzle-Cryptic (Type 2)
			隐秘的奥尔德雷斯之谜 (类型 2)
		*/

		using LinearFeedbackShiftRegister = CSPRNG::FeedbackShiftRegister::LinearFeedbackShiftRegister;
		using NonlinearFeedbackShiftRegister = CSPRNG::FeedbackShiftRegister::NonlinearFeedbackShiftRegister;
		using SimulateDoublePendulum = CSPRNG::ChaoticTheory::SimulateDoublePendulum;

		//Give the class type forward declaration
		class OPC_MainAlgorithm_Worker;

		namespace ImplementationDetails
		{
			//Give the class type forward declaration
			class SubkeyMatrixOperation;
			class MixTransformationUtil;

			class CommonStateData
			{

			private:

				/*
					BlockSize / KeySize (QuadWord)
				*/

				friend class Module_MixTransformationUtil;
				friend class Module_SubkeyMatrixOperation;

				friend class Module_SecureSubkeyGeneratation;
				friend class Module_SecureRoundSubkeyGeneratation;

				friend class TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::OPC_MainAlgorithm_Worker;

				//自定义的随机数生成器
				//Customized random number generator
				std::unique_ptr<LinearFeedbackShiftRegister> LFSR_Pointer = nullptr;
				std::unique_ptr<NonlinearFeedbackShiftRegister> NLFSR_Pointer = nullptr;
				std::unique_ptr<SimulateDoublePendulum> SDP_Pointer = nullptr;

				LinearFeedbackShiftRegister* LFSR_ClassicPointer = nullptr;
				NonlinearFeedbackShiftRegister* NLFSR_ClassicPointer = nullptr;
				SimulateDoublePendulum* SDP_ClassicPointer = nullptr;

				//Bernoulli distribution
				//伯努利分布
				CommonSecurity::RND::BernoulliDistribution BernoulliDistributionObject = CommonSecurity::RND::BernoulliDistribution(0.5);

				//索引数的容器(将会被乱序洗牌)
				//Containers of indices number (will be shuffled in disorder)
				//用在单向变换函数的步骤中，会根据当前乱序数作为“RandomIndex”，访问生成的子密钥(来自变换后的密钥矩阵)和生成的轮函数的子密钥
				//In the step used for the one-way transform function, the generated subkey (from the transformed key matrix) and the generated subkey of the wheel function are accessed based on the current random number as "RandomIndex".
				std::vector<std::uint32_t> MatrixOffsetWithRandomIndices;

				//Word(32 Bit)数据的初始向量，用于关联Word数据的密钥
				//Initial vector of Word(32 Bit) data, used to associate the key of Word data
				std::vector<std::uint32_t> WordDataInitialVector;

				//Word(64 Bit)数据的密钥向量，用于生成子密钥的材料
				//Key vector for Word (64 Bit) data, material for generating subkeys
				std::vector<std::uint64_t> WordKeyDataVector;

				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic> RandomQuadWordMatrix;

				//变换的子密钥矩阵(来自变换的RandomQuadWordMatrix)
				//Generated subkey (from the transformed key matrix)
				Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic> TransformedSubkeyMatrix;

				void ShuffleMatrixOffsetWithRandomIndices()
				{
					auto& NLFSR_Object = *(NLFSR_ClassicPointer);
					CommonSecurity::ShuffleRangeData(MatrixOffsetWithRandomIndices.begin(), MatrixOffsetWithRandomIndices.end(), NLFSR_Object);
				}

			public:

				const std::size_t OPC_QuadWord_DataBlockSize;
				const std::size_t OPC_QuadWord_KeyBlockSize;

				const std::size_t OPC_KeyMatrix_Rows;
				const std::size_t OPC_KeyMatrix_Columns;

				void LFSR_Seed(std::uint64_t LFSR_SeedNumber)
				{
					if(LFSR_SeedNumber == 0)
						LFSR_SeedNumber = 1;

					this->LFSR_ClassicPointer->seed(LFSR_SeedNumber);
				}

				void NLFSR_Seed(std::uint64_t NLFSR_SeedNumber)
				{
					if(NLFSR_SeedNumber == 0)
						NLFSR_SeedNumber = 1;

					this->NLFSR_ClassicPointer->seed(NLFSR_SeedNumber);
				}

				void SDP_Seed(std::uint64_t SDP_SeedNumber)
				{
					this->SDP_ClassicPointer->seed(SDP_SeedNumber);
				}

				CommonStateData
				(
					std::size_t OPC_QuadWord_DataBlockSize,
					std::size_t OPC_QuadWord_KeyBlockSize,
					std::span<const std::uint8_t> InitialBytes_MemorySpan,
					std::uint64_t LFSR_SeedNumber = 1,
					std::uint64_t NLFSR_SeedNumber = 1,
					std::uint64_t SDP_SeedNumber = 0xB7E151628AED2A6AULL
				)
				:
					OPC_QuadWord_DataBlockSize(OPC_QuadWord_DataBlockSize), OPC_QuadWord_KeyBlockSize(OPC_QuadWord_KeyBlockSize),
					OPC_KeyMatrix_Rows(OPC_QuadWord_KeyBlockSize * 2), OPC_KeyMatrix_Columns(OPC_QuadWord_KeyBlockSize * 2),
					LFSR_Pointer(std::make_unique<LinearFeedbackShiftRegister>(LFSR_SeedNumber)),
					NLFSR_Pointer(std::make_unique<NonlinearFeedbackShiftRegister>(NLFSR_SeedNumber)),
					SDP_Pointer(std::make_unique<SimulateDoublePendulum>(SDP_SeedNumber))
				{
					//OPC_DataBlockSize必须是16的倍数，而且必须不能小于2（128 Bit / 8 Bit(1 Byte) == 16 Byte = 16 Byte / 8 Byte(1 QuadWords) == 2 QuadWords）
					my_cpp2020_assert
					(
						(OPC_QuadWord_DataBlockSize % 2) == 0 && OPC_QuadWord_DataBlockSize >= 2,
						"StateData_Worker(CommonStateData): OPC_DataBlockSize must be a multiple of 2 quad-words and must not be less than 2 quad-words (128Bit)!",
						std::source_location::current()
					);

					//OPC_KeyBlockSize必须是32的倍数，而且必须不能小于4 (256 Bit / 8 Bit(1 Byte) == 32 Byte = 32 Byte / 8 Byte(1 QuadWords) == 4 QuadWords），否则不符合后量子标准的数据安全性！
					my_cpp2020_assert
					(
						(OPC_QuadWord_KeyBlockSize % 4) == 0 && OPC_QuadWord_KeyBlockSize >= 4,
						"StateData_Worker(CommonStateData): OPC_KeyBlockSize must be a multiple of 4 quad-words and must not be less than 4 quad-words (256Bit), otherwise it does not meet the post-quantum standard of data security!",
						std::source_location::current()
					);

					//OPC_KeyBlockSize必须是OPC_DataBlockSize的任意倍数。
					my_cpp2020_assert
					(
						OPC_QuadWord_KeyBlockSize > OPC_QuadWord_DataBlockSize && (OPC_QuadWord_KeyBlockSize % OPC_QuadWord_DataBlockSize) == 0,
						"StateData_Worker(CommonStateData): OPC_KeyBlockSize must be any multiple of OPC_DataBlockSize !", std::source_location::current()
					);

					my_cpp2020_assert
					(
						LFSR_SeedNumber != 0 && NLFSR_SeedNumber != 0,
						"Invalid custom random number generator for (LFSR or NLFSR) number seeding!",
						std::source_location::current()
					);

					if(InitialBytes_MemorySpan.size() % (OPC_QuadWord_DataBlockSize * sizeof(std::uint64_t)) != 0)
						my_cpp2020_assert(false, "The InitialBytes_MemorySpan size of the referenced data is not a multiple of (OPC_DataBlockSize * sizeof(std::uint64_t)) byte!", std::source_location::current());

					if(SDP_SeedNumber < 0x2540BE400)
						my_cpp2020_assert(false, "The numbers that are too small represent bit sequence seeds that will not allow chaotic systems that simulate the physical phenomena of a two-segment pendulum to work properly!", std::source_location::current());

					this->LFSR_ClassicPointer = this->LFSR_Pointer.get();
					this->NLFSR_ClassicPointer = this->NLFSR_Pointer.get();
					this->SDP_ClassicPointer = this->SDP_Pointer.get();

					this->WordDataInitialVector = CommonToolkit::IntegerExchangeBytes::MessagePacking<std::uint32_t, std::uint8_t>(InitialBytes_MemorySpan.data(), InitialBytes_MemorySpan.size());

					this->WordKeyDataVector = std::vector<std::uint64_t>(OPC_QuadWord_KeyBlockSize, 0);
					this->MatrixOffsetWithRandomIndices = std::vector<std::uint32_t>(OPC_QuadWord_KeyBlockSize * 2, 0);
					for(std::size_t index = 0, value = 0; index < OPC_QuadWord_KeyBlockSize * 2; ++index)
					{
						this->MatrixOffsetWithRandomIndices[index] = value;
						++value;
					}

					RandomQuadWordMatrix = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>::Zero(OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns);
					TransformedSubkeyMatrix = Eigen::Matrix<std::uint64_t, Eigen::Dynamic, Eigen::Dynamic>::Zero(OPC_KeyMatrix_Rows, OPC_KeyMatrix_Columns);
#if 0

					//OPC - Quadword Cyclone Mixer (Experimental)
					for(std::size_t index = 0; index < RandomQuadWordMatrix.size(); index += 4)
					{
						auto& A = RandomQuadWordMatrix.array()(index);
						auto& B = RandomQuadWordMatrix.array()(index + 1);
						auto& C = RandomQuadWordMatrix.array()(index + 2);
						auto& D = RandomQuadWordMatrix.array()(index + 3);

						A = (*LFSR_Pointer)();
						B = (*NLFSR_Pointer)();
						C = (*LFSR_Pointer)();
						D = (*NLFSR_Pointer)();

						// Mixing operations
						for ( size_t round = 0; round < 20; round++ )
						{
							D += B;
							A += C;

							//GCD(17, 42) = 1
							B = std::rotl(B, 17);
							C = std::rotl(C, 24);

							//GCD(12, 19) = 1
							D ^= A;
							A = std::rotr(A, 12);
							D = std::rotr(D, 19);
							A ^= D;

							C = A;
							B = D;
							A = B;
							D = C;

							A -= C;
							B -= D;

							//GCD(37, 45) = 1
							B = std::rotl(B, 37);
							D = std::rotl(D, 45);

							C += D;
							B ^= (~C);
							A += B;

							//GCD(9, 2) = 1
							A = std::rotr(A, 9);
							C = std::rotr(C, 2);

							B -= A;
							C ^= (~B);
							D -= C;
						}
					}

#endif
				}

				~CommonStateData()
				{
					volatile void* CheckPointer = nullptr;

					this->LFSR_Pointer.reset();
					this->NLFSR_Pointer.reset();
					this->SDP_Pointer.reset();

					CheckPointer = memory_set_no_optimize_function<0x00>(this->MatrixOffsetWithRandomIndices.data(), this->MatrixOffsetWithRandomIndices.size() * sizeof(std::uint32_t));
					my_cpp2020_assert(CheckPointer == this->MatrixOffsetWithRandomIndices.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
					CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(this->WordDataInitialVector.data(), this->WordDataInitialVector.size() * sizeof(std::uint32_t));
					my_cpp2020_assert(CheckPointer == this->WordDataInitialVector.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
					CheckPointer = nullptr;

					CheckPointer = memory_set_no_optimize_function<0x00>(this->WordKeyDataVector.data(), this->WordKeyDataVector.size() * sizeof(std::uint64_t));
					my_cpp2020_assert(CheckPointer == this->WordKeyDataVector.data(), "Force Memory Fill Has Been \"Optimization\" !", std::source_location::current());
					CheckPointer = nullptr;

					this->TransformedSubkeyMatrix.setZero();
				}
			};
		}
	}
}


#endif //ALGORITHM_OALDRESPUZZLECRYPTIC_MODULES_OALDRESPUZZLE_CRYPTIC_HPP
