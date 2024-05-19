#pragma once

namespace CommonSecurity::RC4
{
	// Stream cipher - Rivest Cipher 4
	class RivestCipher4
	{

	private:
		std::array<std::uint8_t, 256> KeyState{};
		std::uint32_t LeftIndex = 0;
		std::uint32_t RightIndex = 0;

	public:

		//Pseudo-random generation algorithm (PRGA)
		virtual std::vector<std::uint8_t> GenerateKeyStream(std::size_t Count)
		{
			std::vector<std::uint8_t> KeyStream;

			for (std::uint64_t Round = 0; Round < Count; ++Round)
			{
				LeftIndex = (LeftIndex + 1) % 256;
				RightIndex = (RightIndex + KeyState[LeftIndex]) % 256;
				std::swap(KeyState[LeftIndex], KeyState[RightIndex]);

				KeyStream.push_back(KeyState[LeftIndex] + KeyState[RightIndex] % 256);
			}

			return KeyStream;
		}

		//Key-scheduling algorithm (KSA)
		virtual void KeyScheduling(std::span<const std::uint8_t> Keys)
		{
			while (LeftIndex < 256)
			{
				RightIndex = (RightIndex + KeyState[LeftIndex] + Keys[LeftIndex % Keys.size()]) % 256;
				std::swap(KeyState[LeftIndex], KeyState[RightIndex]);
				++LeftIndex;
			}

			LeftIndex = 0;
			RightIndex = 0;
		}

		explicit RivestCipher4()
		{
			std::uint8_t ByteData = 0;
			for (auto& Key : KeyState)
			{
				Key = ByteData;
				++ByteData;
			}
			ByteData = 0;
		}

		virtual ~RivestCipher4() = default;
	};
}

namespace UnitTester
{
	inline std::random_device random_device_object;
	inline std::mt19937_64 RandomGeneraterByReallyTime(CommonSecurity::GenerateSecureRandomNumberSeed<std::uint32_t>(random_device_object));
	inline CommonSecurity::RND::UniformIntegerDistribution<std::size_t> UniformNumberDistribution(0, 255);

	//随机生成一个长度为n的向量
	std::vector<std::uint8_t> GanerateRandomValueVector(std::size_t size)
	{
		std::vector<std::uint8_t> byte_data(size);
		for (std::size_t index = 0; index < size; index++) {
			byte_data[index] = UniformNumberDistribution(RandomGeneraterByReallyTime);
		}
		return byte_data;
	}

	class PasscoderDataDifferentialTester
	{

	protected:

		//计算两个向量之间的汉明距离（不同比特数）
		std::size_t hamming_distance(std::span<const std::uint8_t> byte_data1, std::span<const std::uint8_t> byte_data2)
		{
			std::size_t bit_distance = 0;
			for (std::size_t i = 0; i < byte_data1.size(); i++)
			{
				// 异或后计算1的个数
				bit_distance += std::popcount(static_cast<std::uint32_t>(byte_data1[i] ^ byte_data2[i]));
			}
			return bit_distance;
		}

		//将一个向量中的某一比特位反转
		std::vector<std::uint8_t> flip_bit(const std::vector<std::uint8_t>& byte_data, std::size_t position)
		{
			std::size_t byte_position = position / 8;
			std::size_t bit_positions = position % 8;

			std::vector<std::uint8_t> byte_data_copy(byte_data);

			// 异或操作反转位
			byte_data_copy[byte_position] ^= (1 << bit_positions);
			return byte_data_copy;
		}

		//计算平均比特数和方差
		std::pair<double, double> AverageBitsAndVariance(std::span<const std::size_t> data_changes)
		{
			double mean = std::accumulate(data_changes.begin(), data_changes.end(), 0.0) / data_changes.size();
			double variance = 0;
			for (std::size_t i = 0; i < data_changes.size(); i++) {
				variance += ::pow(data_changes[i] - mean, 2);
			}
			variance /= data_changes.size();

			return std::pair<double, double>{ mean, variance };
		}

		virtual std::vector<std::uint8_t> CallEncrypter(const std::vector<std::uint8_t>& PlainData, const std::vector<std::uint8_t>& Keys) = 0;

		virtual std::vector<std::uint8_t> CallDecrypter(const std::vector<std::uint8_t>& CipherData, const std::vector<std::uint8_t>& Keys) = 0;

	public:

		/*
			The Confusion and Diffusivity Tests:

			- Confusion Test:
			  * For Encryption: Measures how much the ciphertext changes when the key is changed while keeping the plaintext fixed.
			  * For Decryption: Measures how much the guessed plaintext changes when the key is changed, keeping the ciphertext fixed.

			- Diffusivity Test:
			  * For Encryption: Measures how much the ciphertext changes when the plaintext is changed while keeping the key fixed.
			  * For Decryption: Measures how much the guessed plaintext changes when the ciphertext is changed, keeping the key fixed.

			To calculate the confusion and diffusivity coefficients, we use the mean and variance of the number of bit changes in the output for each test.

			- Confusion Coefficient:
			  * Calculated as the mean of the number of bit changes in the output (either encrypted or guessed plaintext) when the key is changed divided by the total number of bits in the output.
			  * The variance of the number of bit changes for the confusion test measures how much the output changes on average when a single bit in the key is changed.

			- Diffusivity Coefficient:
			  * Calculated as the mean of the number of bit changes in the output (either encrypted or guessed plaintext) when the plaintext/ciphertext is changed divided by the total number of bits in the output.
			  * The variance for the diffusivity test measures how much the output changes on average when a single bit in the plaintext/ciphertext is changed.

			混淆性和扩散测试:

			- 混淆性测试:
			  * 加密时: 在保持明文固定的情况下，当密钥发生改变时，密文的变化程度。
			  * 解密时: 在保持密文固定的情况下，当密钥发生改变时，猜测的明文的变化程度。

			- 扩散性测试:
			  * 加密时: 在保持密钥固定的情况下，当明文发生变化时，密文的变化程度。
			  * 解密时: 在保持密钥固定的情况下，当密文发生变化时，猜测的明文的变化程度。

			为了计算混淆系数和扩散系数，我们使用输出中比特位变化数量的平均值和方差。

			- 混淆系数:
			  * 计算方法是: 当密钥发生改变时，输出中(加密或猜测的明文)的比特位变化数的平均值除以输出中的总比特位数。
			  * 混淆性测试中: 输出中比特位数变化的方差衡量了当密钥中的一个比特位被改变时，输出的平均变化程度。

			- 扩散系数:
			  * 计算方法是: 当明文/密文发生变化时，输出中(加密或猜测的明文)的比特位变化数的平均值除以输出中的比特总位数。
			  * 扩散性测试中: 输出中比特位数变化的方差衡量了当明文/密文中的一个比特位被改变时，输出的平均变化程度。
		*/

		void plain_for_cipher_diffusivity(const std::vector<std::uint8_t>& plain, const std::vector<std::uint8_t>& key, std::size_t trials)
		{
			if((plain.size() == 0) || (key.size() == 0) || (trials == 0))
				return;

			if(key.size() < 64 || key.size() % 64 != 0)
				return;
			
			// 存储每次试验中明文改变时密文改变的比特数
			std::vector<std::size_t> plain_changes(trials);

			// 对初始明文和初始密钥进行加密，得到初始密文
			std::vector<std::uint8_t> cipher = CallEncrypter(plain, key);

			// 对每一次加密试验进行循环
			for (std::size_t i = 0; i < trials; i++)
			{
				std::cout << "\rTesting ...... " << "(" << i + 1 << "/" << trials << ")";

				// 随机选择一个比特位置，将明文中的该位反转，得到新的明文
				std::size_t plain_pos = UniformNumberDistribution(RandomGeneraterByReallyTime) % (plain.size() * std::numeric_limits<std::uint8_t>::digits);
				std::vector<std::uint8_t> new_plain = flip_bit(plain, plain_pos);

				// 对新的明文和初始密钥进行加密，得到新的密文
				std::vector<std::uint8_t> new_cipher = CallEncrypter(new_plain, key);

				// 计算新旧密文之间的汉明距离，存入plain_changes向量中
				std::size_t plain_change = hamming_distance(cipher, new_cipher);
				plain_changes[i] = plain_change;
			}
			std::cout << std::endl;

			// 计算平均比特数和方差
			auto results = AverageBitsAndVariance(plain_changes);

			std::cout << "Cipher Diffusivity test (Difference testing based on changed plaintext data):\n";
			std::cout << "Mean number of bit changes: " << results.first << std::endl;
			std::cout << "Variance of number of bit changes: " << results.second << std::endl;

			std::cout << "密文扩散性测试 (基于明文的变化):\n";
			std::cout << "比特位数变化的平均数量: " << results.first << std::endl;
			std::cout << "比特位数变化的方差: " << results.second << std::endl;
		}

		void key_for_cipher_confusability(const std::vector<std::uint8_t>& plain, const std::vector<std::uint8_t>& key, std::size_t trials)
		{
			if((plain.size() == 0) || (key.size() == 0) || (trials == 0))
				return;

			if(key.size() < 64 || key.size() % 64 != 0)
				return;
			
			// 存储每次试验中密钥改变时密文改变的比特数
			std::vector<std::size_t> key_changes(trials);

			// 对初始明文和初始密钥进行加密，得到初始密文
			std::vector<std::uint8_t> cipher = CallEncrypter(plain, key);

			// 对每一次加密试验进行循环
			for (std::size_t i = 0; i < trials; i++)
			{
				std::cout << "\rTesting ...... " << "(" << i + 1 << "/" << trials << ")";

				// 随机选择一个比特位置，将密钥中的该位反转，得到新的密钥
				std::size_t key_pos = UniformNumberDistribution(RandomGeneraterByReallyTime) % (key.size() * std::numeric_limits<std::uint8_t>::digits);
				std::vector<std::uint8_t> new_key = flip_bit(key, key_pos);

				// 对新的明文和初始密钥进行加密，得到新的密文
				std::vector<std::uint8_t> new_cipher = CallEncrypter(plain, new_key);

				// 计算新旧密文之间的汉明距离，存入key_changes向量中
				std::size_t key_change = hamming_distance(cipher, new_cipher);
				key_changes[i] = key_change;
			}
			std::cout << std::endl;

			// 计算平均比特数和方差
			auto results = AverageBitsAndVariance(key_changes);

			std::cout << "Cipher Confusion test (Difference testing based on changed key data):\n";
			std::cout << "Mean number of bit changes: " << results.first << std::endl;
			std::cout << "Variance of number of bit changes: " << results.second << std::endl;

			std::cout << "密文混淆性测试 (基于密钥的变化):\n";
			std::cout << "比特位数变化的平均数量: " << results.first << std::endl;
			std::cout << "比特位数变化的方差: " << results.second << std::endl;
		}

		void cipher_for_plain_diffusivity(const std::vector<std::uint8_t>& plain, const std::vector<std::uint8_t>& key, std::size_t trials)
		{
			if((plain.size() == 0) || (key.size() == 0) || (trials == 0))
				return;

			if(key.size() < 64 || key.size() % 64 != 0)
				return;

			// 存储每次试验中密文改变时明文改变的比特数
			std::vector<std::size_t> plain_changes(trials);

			// 对初始明文和初始密钥进行加密，得到初始密文
			std::vector<std::uint8_t> cipher = CallEncrypter(plain, key);

			// 对每一次解密试验进行循环
			for (std::size_t i = 0; i < trials; i++)
			{
				std::cout << "\rTesting ...... " << "(" << i + 1 << "/" << trials << ")";

				// 随机选择一个比特位置，将密文中的该位反转，得到新的密文
				std::size_t cipher_pos = UniformNumberDistribution(RandomGeneraterByReallyTime) % (cipher.size() * std::numeric_limits<std::uint8_t>::digits);
				std::vector<std::uint8_t> new_cipher = flip_bit(cipher, cipher_pos);

				// 对新的密文和初始密钥进行解密，得到新的明文
				std::vector<std::uint8_t> new_plain = CallDecrypter(new_cipher, key);

				// 计算新旧明文之间的汉明距离，存入cipher_changes向量中
				std::size_t cipher_change = hamming_distance(plain, new_plain);
				plain_changes[i] = cipher_change;
			}
			std::cout << std::endl;

			// 计算平均比特数和方差
			auto results = AverageBitsAndVariance(plain_changes);

			std::cout << "Plain Diffusivity test (Difference testing based on changed ciphertext data):\n";
			std::cout << "Mean number of bit changes: " << results.first << std::endl;
			std::cout << "Variance of number of bit changes: " << results.second << std::endl;

			std::cout << "明文扩散性测试 (基于密文的变化):\n";
			std::cout << "比特位数变化的平均数量: " << results.first << std::endl;
			std::cout << "比特位数变化的方差: " << results.second << std::endl;
		}

		void key_for_plain_confusability(const std::vector<std::uint8_t>& plain, const std::vector<std::uint8_t>& key, std::size_t trials)
		{
			if((plain.size() == 0) || (key.size() == 0) || (trials == 0))
				return;

			if(key.size() < 64 || key.size() % 64 != 0)
				return;
			
			// 存储每次试验中密钥改变时明文改变的比特数
			std::vector<std::size_t> key_changes(trials);

			// 对初始明文和初始密钥进行加密，得到初始密文
			std::vector<std::uint8_t> cipher = CallEncrypter(plain, key);

			// 对每一次解密试验进行循环
			for (std::size_t i = 0; i < trials; i++)
			{
				std::cout << "\rTesting ...... " << "(" << i + 1 << "/" << trials << ")";

				// 随机选择一个比特位置，将密钥中的该位反转，得到新的密钥
				std::size_t key_pos = UniformNumberDistribution(RandomGeneraterByReallyTime) % (key.size() * std::numeric_limits<std::uint8_t>::digits);
				std::vector<std::uint8_t> new_key = flip_bit(key, key_pos);

				// 对密文和新密钥进行解密，得到新的明文
				std::vector<std::uint8_t> new_plain = CallDecrypter(cipher, new_key);

				// 计算新旧明文之间的汉明距离，存入key_changes向量中
				std::size_t key_change = hamming_distance(plain, new_plain);
				key_changes[i] = key_change;
			}
			std::cout << std::endl;

			// 计算平均比特数和方差
			auto results = AverageBitsAndVariance(key_changes);

			std::cout << "Plain Confusability test (Difference testing based on changed key data):\n";
			std::cout << "Mean number of bit changes: " << results.first << std::endl;
			std::cout << "Variance of number of bit changes: " << results.second << std::endl;

			std::cout << "明文混淆性测试 (基于密钥的变化):\n";
			std::cout << "比特位数变化的平均数量: " << results.first << std::endl;
			std::cout << "比特位数变化的方差: " << results.second << std::endl;
		}

		PasscoderDataDifferentialTester() = default;
		virtual ~PasscoderDataDifferentialTester() = default;
	};

	class TesterCustomOaldresPuzzleCryptic : public PasscoderDataDifferentialTester
	{
		
	private:

		//Word(32 Bit)数据的初始向量，用于关联Word数据的密钥
		//Initial vector of Word(32 Bit) data, used to associate the key of Word data
		std::vector<std::uint8_t> ByteDataInitialVector;

		std::uint64_t LFSR_SeedNumber = 0;
		std::uint64_t NLFSR_SeedNumber = 0;
		std::uint64_t SDP_SeedNumber = 0;

		std::random_device PRNG_Device;

		std::vector<std::uint8_t> CallEncrypter(const std::vector<std::uint8_t>& PlainData, const std::vector<std::uint8_t>& Keys) override final
		{
			using namespace Cryptograph::OaldresPuzzle_Cryptic::Version2;

			std::unique_ptr<ImplementationDetails::CommonStateData<16, 32>> CommonStateDataUniquePointer = std::make_unique<ImplementationDetails::CommonStateData<16, 32>>(ByteDataInitialVector, LFSR_SeedNumber, NLFSR_SeedNumber);
			CommonStateDataUniquePointer->SDP_Seed(SDP_SeedNumber);
			std::unique_ptr<MainAlgorithm_Worker<16, 32>> OPC_Worker_Pointer = std::make_unique<MainAlgorithm_Worker<16, 32>>( *(CommonStateDataUniquePointer.get()) );

			std::vector<std::uint8_t> CipherData = OPC_Worker_Pointer->EncrypterMain(PlainData, Keys);

			return CipherData;
		}

		std::vector<std::uint8_t> CallDecrypter(const std::vector<std::uint8_t>& CipherData, const std::vector<std::uint8_t>& Keys) override final
		{
			using namespace Cryptograph::OaldresPuzzle_Cryptic::Version2;

			std::unique_ptr<ImplementationDetails::CommonStateData<16, 32>> CommonStateDataUniquePointer = std::make_unique<ImplementationDetails::CommonStateData<16, 32>>(ByteDataInitialVector, LFSR_SeedNumber, NLFSR_SeedNumber);
			CommonStateDataUniquePointer->SDP_Seed(SDP_SeedNumber);
			std::unique_ptr<MainAlgorithm_Worker<16, 32>> OPC_Worker_Pointer = std::make_unique<MainAlgorithm_Worker<16, 32>>( *(CommonStateDataUniquePointer.get()) );

			std::vector<std::uint8_t> PlainData = OPC_Worker_Pointer->DecrypterMain(CipherData, Keys);

			return PlainData;
		}

	public:

		explicit TesterCustomOaldresPuzzleCryptic
		(
			std::span<std::uint8_t> InitialBytes_MemorySpan,
			std::uint64_t LFSR_SeedNumber,
			std::uint64_t NLFSR_SeedNumber,
			std::uint64_t SDP_SeedNumber
		)
			:
			PasscoderDataDifferentialTester(),
			ByteDataInitialVector(InitialBytes_MemorySpan.begin(), InitialBytes_MemorySpan.end()), 
			LFSR_SeedNumber(LFSR_SeedNumber), NLFSR_SeedNumber(NLFSR_SeedNumber), SDP_SeedNumber(SDP_SeedNumber)
		{
			if(InitialBytes_MemorySpan.size() % sizeof(std::uint8_t) != 0)
				my_cpp2020_assert(false, "The InitialBytes_MemorySpan size of the referenced data is not a multiple of (sizeof(std::uint8_t)) byte!", std::source_location::current());
		}

		virtual ~TesterCustomOaldresPuzzleCryptic() = default;
	};

	/*
		Autocorrelation is a method that can be used to analyze the randomness of a sequence of numbers or bytes.
		It measures how similar a sequence is to a delayed version of itself, and can be used to identify patterns or repeating structures in the data.
	*/
	double ByteDataAutoCorrelation(const std::vector<std::uint8_t>& data, std::size_t round)
	{
		std::vector<double> auto_correlation_datas(round+1, 0.0);

		// Compute the mean of the data
		double mean = 0.0;
		for (std::uint8_t x : data)
		{
			mean += static_cast<double>(x);
		}
		mean /= static_cast<double>(data.size());

		// Compute the variance of the data
		double var = 0.0;
		for (std::uint8_t x : data)
		{
			var += (static_cast<double>(x) - mean) * (static_cast<double>(x) - mean);
		}
		var /= static_cast<double>(data.size());

		// Compute the autocorrelation for each lag value
		for (std::size_t lag = 0; lag <= round; lag++)
		{
			double sum = 0.0;
			for (std::size_t i = 0; i < data.size() - lag - 1; i++) {
				sum += (static_cast<double>(data[i]) - mean) * (static_cast<double>(data[i+lag]) - mean);
			}
			auto_correlation_datas[lag] = sum / ((data.size() - lag - 1) * var);
		}

		 // Compute the average autocorrelation
		double average = 0.0;
		for (double value : auto_correlation_datas) {
			average += value;
		}
		average /= static_cast<double>(auto_correlation_datas.size());

		return average;
	}

	/*
		This function takes a ciphertext as input and returns a dictionary containing the frequency of each byte in the ciphertext, expressed as a percentage of the total number of bytes.
		You can use this function to compare the frequency distribution of the ciphertext to the expected distribution for random data.
		If the distribution of the ciphertext is significantly different from the expected distribution, this may indicate that the ciphertext is not sufficiently random.
	*/
	void ByteFrequencyAnalysis(std::span<std::uint8_t> data)
	{
		// Initialize an array to count the frequency of each byte
		std::array<std::uint32_t, 256> freq = {0};

		// Count the frequency of each byte in the input data
		for (size_t i = 0; i < data.size(); i++)
		{
			freq[data[i]]++;
		}

		// Print the frequency of each byte in the input data
		for (std::size_t i = 0; i < 256; i++)
		{
			if (freq[i] > 0) {
				std::cout << "Byte 0x" << std::hex << i << ": " << freq[i] << std::endl;
			}
		}
	}

	template <typename DataType> 
	requires CommonToolkit::IsIterable::IsIterable<DataType>
	double ShannonInformationEntropy(DataType& data)
	{
		//H
		double entropy { 0.0 };

		#if 1

		std::size_t frequencies_count { 0 };

		std::map<std::ranges::range_value_t<DataType>, std::size_t> map;

		for (const auto& item : data)
		{
			map[item]++;
		}

		std::size_t size = std::size(data);

		for (auto iterator = map.cbegin(); iterator != map.cend(); ++iterator)
		{
			double probability_x = static_cast<double>(iterator->second) / static_cast<double>(size);
			entropy -= probability_x * std::log2(probability_x);
			++frequencies_count;
		}

		if (frequencies_count > 256)
		{
			return -1.0;
		}

		return entropy < 0.0 ? -entropy : entropy;

		#else

		DataType copy_data(data);

		std::sort(std::begin(copy_data), std::end(copy_data));

		const std::size_t copy_data_size = std::size(copy_data);
		std::size_t hide_function = 1;
		for (std::size_t index = 1; index < copy_data_size; ++index)
		{
			if (copy_data[index] == copy_data[index - 1])
				++hide_function;
			else
			{
				const double hide_function_size = static_cast<double>(hide_function) / copy_data_size;
				entropy -= hide_function_size * std::log2(hide_function_size);
				hide_function = 1;
			}
		}

		return entropy;

		#endif
	}
	
	void UsedAlgorithmByteDataDifferences(std::string AlgorithmName, std::span<const std::uint8_t> BeforeByteData, std::span<const std::uint8_t> AfterByteData)
	{
		std::size_t DifferentByteCounter = 0;

		std::size_t CountBitOneA = 0;
		std::size_t CountBitOneB = 0;

		for
		(
			auto IteratorBegin = (BeforeByteData).begin(), IteratorEnd = (BeforeByteData).end(),
			IteratorBegin2 = (AfterByteData).begin(), IteratorEnd2 = (AfterByteData).end();
			IteratorBegin != IteratorEnd && IteratorBegin2 != IteratorEnd2;
			++IteratorBegin, ++IteratorBegin2
		)
		{
			if(*IteratorBegin != *IteratorBegin2)
				++DifferentByteCounter;

				CountBitOneA += std::popcount( static_cast<std::uint8_t>(*IteratorBegin) );
				CountBitOneB += std::popcount( static_cast<std::uint8_t>(*IteratorBegin2) );
		}

		std::cout << "Applying this symmetric encryption and decryption algorithm " << "[" << AlgorithmName << "]" << std::endl;
		std::cout << "The result is that a difference of ("<< DifferentByteCounter << ") bytes happened !" << std::endl;
		std::cout << "Difference ratio is: " << static_cast<double>(DifferentByteCounter * 100.0) / static_cast<double>( BeforeByteData.size() ) << "%" << std::endl;

		std::cout << "The result is that a hamming distance difference of ("  << ( CountBitOneA > CountBitOneB ? "+" : "-" ) << ( CountBitOneA > CountBitOneB ? CountBitOneA - CountBitOneB : CountBitOneB - CountBitOneA ) <<  ") bits happened !" << std::endl;
		std::cout << "Difference ratio is: " << static_cast<double>(CountBitOneA * 100.0) / static_cast<double>(CountBitOneB) << "%" << std::endl;
	}

	#if 0

	inline void Test_BlockCryptograph_CustomOaldresPuzzleCryptic()
	{
		using namespace Cryptograph::OaldresPuzzle_Cryptic::Version1;
		
		std::vector<std::byte> Key;

		std::chrono::duration<double> TimeSpent;

		std::vector<std::byte> RandomBytesData;

		for(auto CurrentByteData : CommonRandomDataObject.RandomClassicBytesData)
		{
			RandomBytesData.push_back( static_cast<std::byte>(CurrentByteData) );
		}

		#ifdef _WIN32
		std::system("pause");
		#else
		std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
		#endif

		std::chrono::time_point<std::chrono::system_clock> generatePasswordStartTime = std::chrono::system_clock::now();

		std::cout << "KEY" << std::endl;
		for (std::uint32_t index = 0; index < 256; index++)
		{
			auto integer = static_cast<std::uint32_t>(UniformNumberDistribution(RandomGeneraterByReallyTime));
			std::byte temporaryData{ static_cast<std::byte>(integer) };
			//std::cout << std::to_integer<signed int>(temporaryData) << " ";
			Key.push_back(temporaryData);
		}
		std::cout << "\n";

		std::chrono::time_point<std::chrono::system_clock> generatePasswordEndTime = std::chrono::system_clock::now();
		TimeSpent = generatePasswordEndTime - generatePasswordStartTime;
		std::cout << "The time spent generating the password: " << TimeSpent.count() << "s" << std::endl;

		#ifdef _WIN32
		std::system("pause");
		#else
		std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
		#endif

		std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();

		Encrypter encrypter;

		auto EncryptedBytesData = encrypter.Main(RandomBytesData, Key);

		std::cout << "BytesData - Encrypted" << std::endl;

		/*for (auto& byte_value : BytesData)
		{
			std::cout << std::to_integer<signed int>(byte_value) << " ";
		}
		std::cout << "\n";*/

		std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		#ifdef _WIN32
		std::system("pause");
		#else
		std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
		#endif

		std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();

		Decrypter decrypter;
		auto DecryptedBytesData = decrypter.Main(EncryptedBytesData, Key);

		std::cout << "BytesData - Decrypted" << std::endl;

		/*for (auto& byte_value : BytesData)
		{
			std::cout << std::to_integer<signed int>(byte_value) << " ";
		}
		std::cout << "\n";*/

		std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		#ifdef _WIN32
		std::system("pause");
		#else
		std::system("read -p Press\\ Any\\ Key\\ To\\ Continue");
		#endif
		std::cout << "\n";

		if(RandomBytesData != DecryptedBytesData)
		{
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}
		else
		{
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;

			UsedAlgorithmByteDataDifferences("OaldresPuzzle-Cryptic", RandomBytesData, EncryptedBytesData);

			auto ShannonInformationEntropyValue0 = ShannonInformationEntropy(EncryptedBytesData);
			std::cout << "Encrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue0 << std::endl;
			auto ShannonInformationEntropyValue1 = ShannonInformationEntropy(DecryptedBytesData);
			std::cout << "Decrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue1 << std::endl;
			
			if(ShannonInformationEntropyValue0 > ShannonInformationEntropyValue1)
				std::cout << "Difference of entropy degree of sequential data :" << ShannonInformationEntropyValue0 - ShannonInformationEntropyValue1  << std::endl;

			if(EncryptedBytesData.size() >= static_cast<std::uint32_t>(std::pow(2, 8)))
			{
				auto ByteDataSecurityTestData = EncryptedBytesData;
				ByteDataSecurityTestData.resize(256);
				std::vector<std::uint8_t> ByteDataSecurityTestData0;
				Cryptograph::CommonModule::Adapters::classicByteFromByte(ByteDataSecurityTestData, ByteDataSecurityTestData0);
				Test_ByteSubstitutionBoxToolkit(ByteDataSecurityTestData0);
			}
		}
	}

	#endif

	inline void Test_BlockCryptograph_CustomOaldresPuzzleCryptic_2
	(
		const std::vector<std::uint8_t>& PlainData,
		const std::vector<std::uint8_t>& Keys,
		const std::vector<std::uint8_t>& InitialVector,
		std::uint64_t LFSR_Seed = 1,
		std::uint64_t NLFSR_Seed = 1,
		std::uint64_t SDP_Seed = 0xB7E151628AED2A6AULL
	)
	{
		using namespace Cryptograph::OaldresPuzzle_Cryptic::Version2;

		std::chrono::duration<double> TimeSpent;

		std::unique_ptr<ImplementationDetails::CommonStateData<16, 32>> CommonStateDataUniquePointer = std::make_unique<ImplementationDetails::CommonStateData<16, 32>>(InitialVector, LFSR_Seed, NLFSR_Seed, SDP_Seed);
		std::unique_ptr<MainAlgorithm_Worker<16, 32>> OPC_Worker_Pointer = std::make_unique<MainAlgorithm_Worker<16, 32>>( *(CommonStateDataUniquePointer.get()) );

		//10485760 10MB
		//209715200 200MB
		
		//RandomGeneraterByReallyTime = std::mt19937_64(123456);

		std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();
		
		std::vector<std::uint8_t> CipherData;
		if(PlainData.size() % 16 != 0)
			CipherData = OPC_Worker_Pointer->EncrypterMain(PlainData, Keys);
		else
			CipherData = OPC_Worker_Pointer->EncrypterMainWithoutPadding(PlainData, Keys);

		std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		/*
			重置密码器状态
			Reset cipher state
		*/
		OPC_Worker_Pointer.reset();
		CommonStateDataUniquePointer.reset();

		std::ofstream OuputTestFile("./OaldresPuzzle_Cryptic-Version2.TestCipherData.bin", std::ios::out | std::ios::binary | std::ios::trunc);
		if(OuputTestFile.is_open())
		{
			OuputTestFile.write(reinterpret_cast<char*>(CipherData.data()), CipherData.size());
		}
		OuputTestFile.close();

		CommonStateDataUniquePointer = std::make_unique<ImplementationDetails::CommonStateData<16, 32>>(InitialVector, LFSR_Seed, NLFSR_Seed, SDP_Seed);
		OPC_Worker_Pointer = std::make_unique<MainAlgorithm_Worker<16, 32>>( *(CommonStateDataUniquePointer.get()) );

		std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();

		std::vector<std::uint8_t> ProcessData;
		if(PlainData.size() % 16 != 0)
			ProcessData = OPC_Worker_Pointer->DecrypterMain(CipherData, Keys);
		else
			ProcessData = OPC_Worker_Pointer->DecrypterMainWithoutUnpadding(CipherData, Keys);

		std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		OPC_Worker_Pointer.reset();

		volatile bool IsSameData = true;

		for(volatile std::size_t DataIndex = 0; DataIndex < ProcessData.size(); ++DataIndex)
		{
			if(PlainData[DataIndex] != ProcessData[DataIndex])
			{
				IsSameData = false;
				break;
			}
		}

		if(IsSameData)
		{
			std::cout << "The data after this operation is correct!" << std::endl;
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;

			UsedAlgorithmByteDataDifferences("CustomBlockCryptograph - OaldresPuzzle_Cryptic By Twilight-Dream", PlainData, CipherData);

			auto ShannonInformationEntropyValue0 = ShannonInformationEntropy(CipherData);
			std::cout << "Encrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue0 << std::endl;
			auto ShannonInformationEntropyValue1 = ShannonInformationEntropy(ProcessData);
			std::cout << "Decrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue1 << std::endl;
			
			if(ShannonInformationEntropyValue0 > ShannonInformationEntropyValue1)
				std::cout << "Difference of entropy degree of sequential data :" << ShannonInformationEntropyValue0 - ShannonInformationEntropyValue1  << std::endl;

			auto AutoCorrelationValue = ByteDataAutoCorrelation(CipherData, 64);
				std::cout << "The rate of 64 rounds of autocorrelated data :" << ShannonInformationEntropyValue1 << std::endl;
		}
		else
		{
			std::cout << "The data after this operation is incorrect!" << std::endl;
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}

		CipherData.clear();
		ProcessData.clear();

		CipherData.shrink_to_fit();
		ProcessData.shrink_to_fit();

		/*std::vector<std::uint8_t> InitialVector(2048, std::uint8_t{0x00});

		std::unique_ptr<ImplementationDetails::CommonStateData<16, 32>> CommonStateDataUniquePointer = std::make_unique<ImplementationDetails::CommonStateData<16, 32>>(InitialVector, 12, 34);
		std::unique_ptr<StateData_Worker<16, 32>> OPC_Worker_Pointer = std::make_unique<StateData_Worker<16, 32>>( *(CommonStateDataUniquePointer.get()) );
		
		OPC_Worker_Pointer->LaiMasseyFrameworkTest();*/
	}

	inline void Test_BlockCryptograph_CustomOaldresPuzzleCryptic_2_CornerCases
	(
		const std::vector<std::uint8_t>& PlainData,
		const std::vector<std::uint8_t>& Keys,
		const std::vector<std::uint8_t>& InitialVector,
		std::uint64_t LFSR_Seed = 1,
		std::uint64_t NLFSR_Seed = 1,
		std::uint64_t SDP_Seed = 0xB7E151628AED2A6AULL
	)
	{
		using namespace Cryptograph::OaldresPuzzle_Cryptic::Version2;

		std::chrono::duration<double> TimeSpent;

		std::unique_ptr<ImplementationDetails::CommonStateData<16, 32>> CommonStateDataUniquePointer = std::make_unique<ImplementationDetails::CommonStateData<16, 32>>(InitialVector, LFSR_Seed, NLFSR_Seed, SDP_Seed);
		std::unique_ptr<MainAlgorithm_Worker<16, 32>> OPC_Worker_Pointer = std::make_unique<MainAlgorithm_Worker<16, 32>>( *(CommonStateDataUniquePointer.get()) );

		std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();

		//按照顺序加密两次
		//Encrypt twice in order
		std::vector<std::uint8_t> CipherData = OPC_Worker_Pointer->EncrypterMainWithoutPadding(PlainData, Keys);

		/*
			重置密码器状态
			Reset cipher state
		*/
		OPC_Worker_Pointer.reset();
		CommonStateDataUniquePointer.reset();

		CommonStateDataUniquePointer = std::make_unique<ImplementationDetails::CommonStateData<16, 32>>(InitialVector, LFSR_Seed, NLFSR_Seed, SDP_Seed);
		OPC_Worker_Pointer = std::make_unique<MainAlgorithm_Worker<16, 32>>( *(CommonStateDataUniquePointer.get()) );

		CipherData = OPC_Worker_Pointer->EncrypterMainWithoutPadding(CipherData, Keys);

		std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
		std::cout << "The time spent encrypting the data: " << TimeSpent.count() << "s" << std::endl;

		/*
			重置密码器状态
			Reset cipher state
		*/
		OPC_Worker_Pointer.reset();
		CommonStateDataUniquePointer.reset();

		std::ofstream OuputTestFile("./OaldresPuzzle_Cryptic-Version2_CornerCases.TestCipherData.bin", std::ios::out | std::ios::binary | std::ios::trunc);
		if(OuputTestFile.is_open())
		{
			OuputTestFile.write(reinterpret_cast<char*>(CipherData.data()), CipherData.size());
		}
		OuputTestFile.close();

		CommonStateDataUniquePointer = std::make_unique<ImplementationDetails::CommonStateData<16, 32>>(InitialVector, LFSR_Seed, NLFSR_Seed, SDP_Seed);
		OPC_Worker_Pointer = std::make_unique<MainAlgorithm_Worker<16, 32>>( *(CommonStateDataUniquePointer.get()) );

		std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();

		//按照逆序解密两次
		//Decrypt twice in reverse order
		std::vector<std::uint8_t> ProcessData = OPC_Worker_Pointer->DecrypterMainWithoutUnpadding(CipherData, Keys);

		/*
			重置密码器状态
			Reset cipher state
		*/
		OPC_Worker_Pointer.reset();
		CommonStateDataUniquePointer.reset();

		CommonStateDataUniquePointer = std::make_unique<ImplementationDetails::CommonStateData<16, 32>>(InitialVector, LFSR_Seed, NLFSR_Seed, SDP_Seed);
		OPC_Worker_Pointer = std::make_unique<MainAlgorithm_Worker<16, 32>>( *(CommonStateDataUniquePointer.get()) );

		ProcessData = OPC_Worker_Pointer->DecrypterMainWithoutUnpadding(ProcessData, Keys);

		std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();
		TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
		std::cout << "The time spent decrypting the data: " << TimeSpent.count() << "s" << std::endl;

		OPC_Worker_Pointer.reset();

		volatile bool IsSameData = true;

		for(volatile std::size_t DataIndex = 0; DataIndex < ProcessData.size(); ++DataIndex)
		{
			if(PlainData[DataIndex] != ProcessData[DataIndex])
			{
				IsSameData = false;
				break;
			}
		}

		if(IsSameData)
		{
			std::cout << "The data after this operation is correct!" << std::endl;
			std::cout << "Yeah! \nThe module is normal work!" << std::endl;

			UsedAlgorithmByteDataDifferences("CustomBlockCryptograph - OaldresPuzzle_Cryptic By Twilight-Dream", PlainData, CipherData);

			auto ShannonInformationEntropyValue0 = ShannonInformationEntropy(CipherData);
			std::cout << "Encrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue0 << std::endl;
			auto ShannonInformationEntropyValue1 = ShannonInformationEntropy(ProcessData);
			std::cout << "Decrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue1 << std::endl;
			
			if(ShannonInformationEntropyValue0 > ShannonInformationEntropyValue1)
				std::cout << "Difference of entropy degree of sequential data :" << ShannonInformationEntropyValue0 - ShannonInformationEntropyValue1  << std::endl;

			auto AutoCorrelationValue = ByteDataAutoCorrelation(CipherData, 64);
				std::cout << "The rate of 64 rounds of autocorrelated data :" << ShannonInformationEntropyValue1 << std::endl;
		}
		else
		{
			std::cout << "The data after this operation is incorrect!" << std::endl;
			std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
		}

		CipherData.clear();
		ProcessData.clear();
		
		CipherData.shrink_to_fit();
		ProcessData.shrink_to_fit();
	}

	inline void Tester_BlockCryptograph_CustomOaldresPuzzleCryptic()
	{
		std::vector<std::uint8_t> InitialVector(4096, std::uint8_t{0x00});
		TesterCustomOaldresPuzzleCryptic Tester_OPC(InitialVector, 12, 34, 0xB7E151628AED2A6AULL);

		/*
			A low mean number of bit changes and a low variance would indicate that the cipher is not providing enough confusion, while a high mean number of bit changes and a high variance could indicate that the cipher is too confusing and may not provide enough diffusion.
			In general, a good cipher should provide a good balance between confusion and diffusion to ensure the security of the encrypted data.

			In this case, the high variance indicates that there is some variation in the number of bit changes, which could be due to the specific properties of the plaintext used in the test. However, the mean number of bit changes is still quite high, which indicates that the cipher is providing a good level of confusion.
		*/

		#if 0

		// 随机生成一个初始明文和初始密钥
		std::vector<std::uint8_t> PlainData = GanerateRandomValueVector(1048579);
		std::vector<std::uint8_t> Keys = GanerateRandomValueVector(5120);

		#else

		std::vector<std::uint8_t> PlainData(1048579, std::uint8_t{0x00});
		std::vector<std::uint8_t> Keys(5120, std::uint8_t{0x00});
		
		//RandomGeneraterByReallyTime = std::mt19937_64(123456);

		//for(auto& Data : PlainData )
		//{
		//	Data = static_cast<std::uint8_t>( RandomGeneraterByReallyTime() % 256 );
		//	//Data = static_cast<std::uint8_t>(1);
		//}

		//for(auto& Key : Keys )
		//{
		//	Key = static_cast<std::uint8_t>( RandomGeneraterByReallyTime() % 256 );
		//	//Key = static_cast<std::uint8_t>(2);
		//}

		#endif

		//Test Encryption
		Tester_OPC.plain_for_cipher_diffusivity(PlainData, Keys, 1024);
		Tester_OPC.key_for_cipher_confusability(PlainData, Keys, 1024);

		//Test Decryption
		Tester_OPC.cipher_for_plain_diffusivity(PlainData, Keys, 1024);
		Tester_OPC.key_for_plain_confusability(PlainData, Keys, 1024);
	}
}