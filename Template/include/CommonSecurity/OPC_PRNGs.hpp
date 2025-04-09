namespace CommonSecurity
{
	//https://zh.wikipedia.org/wiki/%E6%B7%B7%E6%B2%8C%E7%90%86%E8%AE%BA
	//https://en.wikipedia.org/wiki/Chaos_theory
	namespace RNG_ChaoticTheory
	{
		//模拟双段摆锤物理系统，根据二进制密钥生成伪随机数
		//Simulate a two-segment pendulum physical system to generate pseudo-random numbers based on a binary key
		//https://zh.wikipedia.org/wiki/%E5%8F%8C%E6%91%86
		//https://en.wikipedia.org/wiki/Double_pendulum
		//https://www.researchgate.net/publication/345243089_A_Pseudo-Random_Number_Generator_Using_Double_Pendulum
		//https://github.com/robinsandhu/DoublePendulumPRNG/blob/master/prng.cpp
		class SimulateDoublePendulum
		{

		private:

			using result_type = std::uint64_t;

			std::array<long double, 2> BackupTensions {};
			std::array<long double, 2> BackupVelocitys {};
			std::array<long double, 10> SystemData {};

			static constexpr long double gravity_coefficient = 9.8;
			static constexpr long double hight = 0.002;

			void run_system(bool is_initialize_mode, std::uint64_t time)
			{
				const long double& length1 = this->SystemData[0];
				const long double& length2 = this->SystemData[1];
				const long double& mass1 = this->SystemData[2];
				const long double& mass2 = this->SystemData[3];
				long double& tension1 = this->SystemData[4];
				long double& tension2 = this->SystemData[5];

				long double& velocity1 = this->SystemData[8];
				long double& velocity2 = this->SystemData[9];

				for(std::uint64_t counter = 0; counter < time; ++counter)
				{
					long double denominator = 2 * mass1 + mass2 - mass2 * ::cos(2 * tension1 - 2 * tension2);
					
					long double alpha1 = -1 * gravity_coefficient * (2 * mass1 + mass2) * ::sin(tension1)
						- mass2 * gravity_coefficient * ::sin(tension1 - 2 * tension2)
						- 2 * ::sin(tension1 - tension2) * mass2 
						* (velocity2 * velocity2 * length2 + velocity1 * velocity1 * length1 * ::cos(tension1 - tension2));
					
					alpha1 /= length1 * denominator;

					long double alpha2 = 2 * ::sin(tension1 - tension2)
						* (velocity1 * velocity1 * length1 * (mass1 + mass2) + gravity_coefficient * (mass1 + mass2) * ::cos(tension1) + velocity2 * velocity2 * length2 * mass2 * ::cos(tension1 - tension2) );

					alpha2 /= length2 * denominator;

					velocity1 += hight * alpha1;
					velocity2 += hight * alpha2;
					tension1 += hight * velocity1;
					tension2 += hight * velocity2;
				}

				if(is_initialize_mode)
				{
					this->BackupTensions[0] = tension1;
					this->BackupTensions[1] = tension2;

					this->BackupVelocitys[0] = velocity1;
					this->BackupVelocitys[1] = velocity2;
				}
			}

			void initialize(std::vector<std::int8_t>& binary_key_sequence)
			{
				if(binary_key_sequence.empty())
					my_cpp2020_assert(false, "RNG_ChaoticTheory::SimulateDoublePendulum: This binary key sequence must be not empty!", std::source_location::current());

				const std::size_t binary_key_sequence_size = binary_key_sequence.size();
				std::vector<std::vector<std::int8_t>> binary_key_sequence_2d(4, std::vector<std::int8_t>());
				for(std::size_t index = 0; index < binary_key_sequence_size / 4; index++)
				{
					binary_key_sequence_2d[0].push_back(binary_key_sequence[index]);
					binary_key_sequence_2d[1].push_back(binary_key_sequence[binary_key_sequence_size / 4 + index]);
					binary_key_sequence_2d[2].push_back(binary_key_sequence[binary_key_sequence_size / 2 + index]);
					binary_key_sequence_2d[3].push_back(binary_key_sequence[binary_key_sequence_size * 3 / 4 + index]);
				}

				std::vector<std::vector<std::int8_t>> binary_key_sequence_2d_param(7, std::vector<std::int8_t>());
				std::int32_t key_outer_round_count = 0;
				std::int32_t key_inner_round_count = 0;
				while (key_outer_round_count < 64)
				{
					while (key_inner_round_count < binary_key_sequence_size / 4)
					{
						binary_key_sequence_2d_param[0].push_back(binary_key_sequence_2d[0][key_inner_round_count] ^ binary_key_sequence_2d[1][key_inner_round_count]);
						binary_key_sequence_2d_param[1].push_back(binary_key_sequence_2d[0][key_inner_round_count] ^ binary_key_sequence_2d[2][key_inner_round_count]);
						binary_key_sequence_2d_param[2].push_back(binary_key_sequence_2d[0][key_inner_round_count] ^ binary_key_sequence_2d[3][key_inner_round_count]);
						binary_key_sequence_2d_param[3].push_back(binary_key_sequence_2d[1][key_inner_round_count] ^ binary_key_sequence_2d[2][key_inner_round_count]);
						binary_key_sequence_2d_param[4].push_back(binary_key_sequence_2d[1][key_inner_round_count] ^ binary_key_sequence_2d[3][key_inner_round_count]);
						binary_key_sequence_2d_param[5].push_back(binary_key_sequence_2d[2][key_inner_round_count] ^ binary_key_sequence_2d[3][key_inner_round_count]);
						binary_key_sequence_2d_param[6].push_back(binary_key_sequence_2d[0][key_inner_round_count]);
						
						++key_inner_round_count;
						++key_outer_round_count;
						if(key_outer_round_count >= 64)
						{
							break;
						}
					}
					key_inner_round_count = 0;
				}
				key_outer_round_count = 0;

				long double& radius = this->SystemData[6];
				long double& current_binary_key_sequence_size = this->SystemData[7];

				for (std::int32_t i = 0; i < 64; i++)
				{
					for (std::int32_t j = 0; j < 6; j++)
					{
						if(binary_key_sequence_2d_param[j][i] == 1)
							this->SystemData[j] += 1 * ::powl(2.0, 0 - i);
					}
					if(binary_key_sequence_2d_param[6][i] == 1)
						radius += 1 * ::powl(2.0, 4 - i);
				}
				
				current_binary_key_sequence_size = static_cast<long double>(binary_key_sequence_size);

				//This is initialize mode
				this->run_system(true, static_cast<std::uint64_t>(::round(radius * current_binary_key_sequence_size)));
			}

			//交错串接
			//Interleaved concatenate one-by-one bits
			std::int64_t concat(std::int32_t a, std::int32_t b)
			{
				std::string result_binary_string;
				for (int i = 0; i < 32; i++)
				{
					result_binary_string.push_back((b % 2) == 1 ? '1' : '0');
					b /= 2;
					result_binary_string.push_back((a % 2) == 1 ? '1' : '0');
					a /= 2;
				}
				std::bitset<64> concate_bitset(result_binary_string);
				std::int64_t c = static_cast<std::int64_t>(concate_bitset.to_ullong());
				return c;
			}

			std::int64_t generate()
			{
				//This is generate mode
				this->run_system(false, 1);

				long double temporary_floating_a = 0.0;
				long double temporary_floating_b = 0.0;

				std::int64_t left_number = 0, right_number = 0;

				temporary_floating_a = this->SystemData[0] * ::sin(this->SystemData[4]) + this->SystemData[1] * ::sin(this->SystemData[5]);
				temporary_floating_b = -(this->SystemData[0]) * ::sin(this->SystemData[4]) - this->SystemData[1] * ::sin(this->SystemData[5]);

				left_number = ::floor(::fmod(temporary_floating_a * 1000, 1.0) * 4294967296);
				right_number = ::floor(::fmod(temporary_floating_b * 1000, 1.0) * 4294967296);

				return this->concat(static_cast<std::int32_t>(left_number), static_cast<std::int32_t>(right_number));
			}

		public:

			static constexpr result_type min()
			{ 
				return 0LL;
			}

			static constexpr result_type max()
			{ 
				return 0xFFFFFFFFFFFFFFFFLL;
			};

			std::vector<result_type> operator()(std::size_t generated_count, std::uint64_t min_number, std::uint64_t max_number)
			{
				std::int64_t modulus = static_cast<std::int64_t>(max_number) - static_cast<std::int64_t>(min_number) + 1;

				std::vector<result_type> random_numbers(generated_count, 0);
				for (auto& random_number : random_numbers)
				{
					std::int64_t temporary_random_number = this->generate();

					if(modulus != 0)
						temporary_random_number %= modulus;

					if(temporary_random_number < 0)
						temporary_random_number += modulus;

					random_number = static_cast<result_type>(static_cast<std::int64_t>(min_number) + temporary_random_number);
				}

				return random_numbers;
			}

			result_type operator()(std::uint64_t min_number, std::uint64_t max_number)
			{
				std::int64_t modulus = static_cast<std::int64_t>(max_number) - static_cast<std::int64_t>(min_number) + 1;

				result_type random_number = 0;
				std::int64_t temporary_random_number = this->generate();

				if(modulus != 0)
					temporary_random_number %= modulus;

				if(temporary_random_number < 0)
					temporary_random_number += modulus;

				random_number = static_cast<result_type>(static_cast<std::int64_t>(min_number) + temporary_random_number);

				return random_number;
			}

			void reset()
			{
				this->SystemData[4] = this->BackupTensions[0];
				this->SystemData[5] = this->BackupTensions[1];
				this->SystemData[8] = this->BackupVelocitys[0];
				this->SystemData[9] = this->BackupVelocitys[1];
			}

			void seed_with_binary_string(std::string binary_key_sequence_string)
			{
				std::vector<int8_t> binary_key_sequence;
				std::string_view view_only_string(binary_key_sequence_string);
				const char binary_zero_string = '0';
				const char binary_one_string = '1';
				for(const char& data : view_only_string)
				{
					if(data != binary_zero_string && data != binary_one_string)
						continue;

					binary_key_sequence.push_back(data == binary_zero_string ? 0 : 1);
				}

				if(binary_key_sequence.empty())
					return;
				else
					this->initialize(binary_key_sequence);
			}

			template<typename SeedNumberType>
			requires std::signed_integral<SeedNumberType> || std::unsigned_integral<SeedNumberType> || std::same_as<SeedNumberType, std::string>
			void seed(SeedNumberType seed_value)
			{
				if constexpr(std::same_as<SeedNumberType, std::int32_t>)
					this->seed_with_binary_string(UtilTools::DataFormating::Decimal_Binary::FromLongIntegerToBinaryString(seed_value, seed_value < 0));
				else if constexpr(std::same_as<SeedNumberType, std::int64_t>)
					this->seed_with_binary_string(UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(seed_value, seed_value < 0));
				else if constexpr(std::same_as<SeedNumberType, std::uint32_t>)
					this->seed_with_binary_string(UtilTools::DataFormating::Decimal_Binary::FromUnsignedLongIntegerToBinaryString(seed_value));
				else if constexpr(std::same_as<SeedNumberType, std::uint64_t>)
					this->seed_with_binary_string(UtilTools::DataFormating::Decimal_Binary::FromUnsignedLongLongIntegerToBinaryString(seed_value));
				else if constexpr(std::same_as<std::remove_cvref_t<SeedNumberType>, std::string>)
					this->seed_with_binary_string(seed_value);
					
			}

			explicit SimulateDoublePendulum(auto number)
			{
				using SeedNumberType = decltype(number);
				this->seed<SeedNumberType>(number);
			}

			~SimulateDoublePendulum()
			{
				this->BackupVelocitys.fill(0.0);
				this->BackupTensions.fill(0.0);
				this->SystemData.fill(0.0);
			}
		};
	}

	namespace RNG_FeedbackShiftRegister
	{
		//一种使用线性反馈移位寄存器算法的随机数发生器
		//A random number generator using linear feedback shift register algorithm
		class LinearFeedbackShiftRegister
		{

		public:
			
			using result_type = std::uint64_t;
			
		private:
			
			/*
				数组位置0是当前的随机数
				数组位置1是当前的随机数的种子
				Array position 0 is the current random number
				Array position 1 is the current random number seed
			*/
			std::array<result_type, 2> state {};

		public:

			result_type generate_bits(std::size_t bits_size)
			{
				result_type& NumberA = state[0];
				result_type& NumberB = state[1];

				result_type current_random_bit = 0;
				
				//多项式的初始值可以是：128,126,101,99
				//The initial values of the polynomial can be: 128,126,101,99
				result_type answer = 128;
				for (std::size_t round_counter = 0; round_counter < bits_size; ++round_counter)
				{
					//计算二进制的伪随机比特序列
					//Compute pseudo-random bit sequences in binary
					//这个多项式是 : x^128 + x^41 + x^39 + x + 1
					//This polynomial is : x^128 + x^41 + x^39 + x + 1
					//举一个例子，这个多项式的最高系数是128
					//As an example, the highest coefficient of this polynomial is 128.
					std::uint64_t&& irreducible_primitive_polynomial = NumberB ^ (NumberA >> 23) ^ (NumberA >> 25) ^ (NumberA >> 63);

					//只保留一个二进制的随机比特位
					//Only one binary random bit is retained
					current_random_bit = irreducible_primitive_polynomial & 0x01; //Feedback bit

					//左移答案的比特位
					//Shift the bits of the answer to the left
					answer <<= 1;

					//用当前随机位切换答案位
					//Toggle the answer bit with the current random bit
					answer ^= current_random_bit;
					
					//右移状态寄存器比特位
					//Shift the bits of the status register to the right
					NumberB >>= 1;
					NumberB |= (NumberA & 0x01) << 63;
					NumberA >>= 1;
					NumberA |= current_random_bit << 63;
				}
				return answer;
			}

			result_type operator() (void) 
			{ 
				return this->generate_bits(63);
			}

			static constexpr result_type min()  
			{ 
				return 0ULL;
			}

			static constexpr result_type max()  
			{ 
				return 0xFFFFFFFFFFFFFFFFULL;
			};

			void seed(result_type seed) 
			{ 
				*this = LinearFeedbackShiftRegister(seed);
			}

			void discard(std::size_t round_number)
			{
				for (std::size_t round_counter = 0; round_counter < round_number; ++round_counter)
					this->generate_bits(64);
			}

			#ifndef BOOST_RANDOM_NO_STREAM_OPERATORS

			/**  Writes a @c rand48 to a @c std::ostream. */
			template<class CharT, class Traits>
			friend std::basic_ostream<CharT, Traits>&
			operator<<(std::basic_ostream<CharT, Traits>& os, const LinearFeedbackShiftRegister& lfsr)
			{ os << lfsr.state[0]; os << ","; os << lfsr.state[1]; return os; }

			/** Reads a @c rand48 from a @c std::istream. */
			template<class CharT, class Traits>
			friend std::basic_istream<CharT, Traits>&
			operator>>(std::basic_istream<CharT, Traits>& is, LinearFeedbackShiftRegister& lfsr)
			{ char command; is >> lfsr.state[0]; is >> command; is >> lfsr.state[1]; return is; }

			#endif

			LinearFeedbackShiftRegister(result_type seed)
			{
				state[0] = 0;
				state[1] = seed;
				this->generate_bits(64);
				this->generate_bits(64);
			}

			LinearFeedbackShiftRegister() : LinearFeedbackShiftRegister(1)
			{

			}

			LinearFeedbackShiftRegister(LinearFeedbackShiftRegister const &lfsr)
			{
				state[0] = lfsr.state[0];
				state[1] = lfsr.state[1];
			}

			~LinearFeedbackShiftRegister()
			{
				state[0] = 0;
				state[1] = 0;
			}
		};

		#define SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION 2

		//一种使用非线性反馈移位寄存器算法的随机数发生器
		//A random number generator using non-linear feedback shift register algorithm
		class NonlinearFeedbackShiftRegister
		{
				
		public:
			
			using result_type = std::uint64_t;
			
		private:

			#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

			/*
				数组位置0是当前的随机数的种子
				数组位置1是当前的随机数
				Array position 0 is the current random number seed
				Array position 1 is the current random number
			*/
			std::array<result_type, 2> state {};

			#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

			/*
				数组位置0是当前的随机数的种子
				数组位置1是当前的随机数
				Array position 0 is is the current random number seed
				Array position 1,2,3 the current random number
			*/
			std::array<result_type, 4> state {};

			#endif
			
			//应用不可约的本源多项式的复杂性质生成非线性的随机比特流的数字
			//Apply complex properties of irreducible primitive polynomials to generate nonlinear random bit streams of numbers
			result_type random_bits(std::uint64_t& state_number, std::uint64_t irreducible_polynomial_count, const std::uint8_t bit)
			{
				//二进制多项式数据源：https://users.ece.cmu.edu/~koopman/lfsr/index.html
				//Binary polynomial data source : https://users.ece.cmu.edu/~koopman/lfsr/index.html
				//x is 2, for example: x ^ 3 = 2 * 2 * 2;

				auto feedback_function = [&state_number](uint64_t feedback) -> void
				{
					uint64_t lowest_bit = state_number & 0x01;    // 提取最低位
					state_number >>= 1;                           // 右移
					state_number ^= (~lowest_bit + 1) & feedback; // 如果最低位为1，则与 feedback 异或
				};
				
				switch (irreducible_polynomial_count)
				{
					case 0:
					{
						//Primitive polynomial degree is 24
						//x^23 + x^10 + x^9 + x^8 + x^6 + x^4 + x^3 + 1
						feedback_function(0x80'0759ULL);

						break;
					}
					case 1:
					{
						//Primitive polynomial degree is 55
						//x^54 - x^10 - x^9 - x^8 - x^7 - x^6 - x^5 - x^4 - x^3 - x^2
						feedback_function(0x40'0000'0000'07FCULL);

						break;
					}
					case 2:
					{
						//Primitive polynomial degree is 48
						//x^47 + x^11 + x^10 + x^8 + x^5 + x^4 + x^3 + 1
						feedback_function(0x8000'0000'0D39ULL);

						break;
					}
					case 3:
					{
						//Primitive polynomial degree is 31
						//x^30 - x^9 - x^8 - x^7 - x^5 - x^4 - x^3 - x^2 - x - 1
						feedback_function(0x4000'03BFULL);

						break;
					}
					case 4:
					{
						//Primitive polynomial degree is 64
						//x^63 + x^12 + x^9 + x^8 + x^5 + x^2
						feedback_function(0x8000'0000'0000'1324ULL);

						break;
					}
					case 5:
					{
						//Primitive polynomial degree is 27
						//x^26 - x^10 - x^3 - x^2 - x - 1
						feedback_function(0x400'040FULL);

						break;
					}
					case 6:
					{
						//Primitive polynomialdegree is 7
						//x^6 + 1
						feedback_function(0x41ULL);

						break;
					}
					case 7:
					{
						//Primitive polynomial degree is 16
						//x^15 - x^10 - x^7 - x^5 - x^4 - x^3 - x^2 - x
						feedback_function(0x84BEULL);

						break;
					}
					default:
					{
						//Primitive polynomial degree is 42
						//x^41 + x^11 + x^10 + x^8 + x^6 + x^5 + x^4 + x^3 + x^2 + x
						feedback_function(0x200'0000'0D7EULL);

						break;
					}
				}

				return state_number ^ bit;
			}

		public:

			/*
				Reference URL:
				http://www.numberworld.org/constants.html
				https://www.exploringbinary.com/pi-and-e-in-binary/
				https://oeis.org/A001113
				https://oeis.org/A001622
				https://oeis.org/A000796
				
				斐波那契数列的值的组合
				Combination of the values of the Fibonacci sequence
				123581321345589144 == 0x1B70C8E97AD5F98

				PI π ≈ 3.1415926535897932384626433832795028841971693993751058209749445923078
				圆周率是一个数学常数，为一个圆的周长和其直径的比率
				Circumference is a mathematical constant that is the ratio of the circumference of a circle to its diameter
				Binary format: 11.0010010000111111011010101000100010000101101000110000100011010011
				二进制数字被剥离了浮点部分，并转换为十六进制，即 0x243F6A8885A308D3
				The binary numbers are stripped of the floating point portion and converted to hexadecimal, i.e: 0x243F6A8885A308D3

				e ≈ 2.7182818284590452353602874713526624977572470936999595749669676277240
				欧拉数是自然对数的基数，不要与欧拉-马斯切罗尼常数混淆
				The Euler number is the base of the natural logarithm, not to be confused with the Euler-Mascheroni constant
				Binary format: 10.1011011111100001010100010110001010001010111011010010101001101010
				二进制数字被剥离了浮点部分，并转换为十六进制，即 0xB7E151628AED2A6A
				The binary numbers are stripped of the floating point portion and converted to hexadecimal, i.e: 0xB7E151628AED2A6A

				phi ≈ 1.618033988749894848204586834365638618033988749894848204586834365638
				在数学中，如果两个量的比值与这两个量中较大的一个的比值相同，那么这两个量就处于黄金比例。
				用代数法表示，对于a和b的数量，a>b>0
				其中希腊字母phi表示黄金比例。
				常数phi满足二次方程 phi^2 = phi+1，是一个无理数，其值为phi =（ 1 + sqrt（5））/ 2
				In mathematics, two quantities are in the golden ratio if their ratio is the same as the ratio of their sum to the larger of the two quantities. Expressed algebraically, for quantities.
				Expressed algebraically, for quantities a and b with a>b>0
				where the Greek letter phi denotes the golden ratio.
				The constant phi satisfies the quadratic equation phi^2 = phi + 1, and is an irrational number with a value of phi = (1 + sqrt(5)) / 2
				Binary format: 01.1001111000110111011110011011100101111111010010100111110000010101
				二进制数字被剥离了浮点部分，并转换为十六进制，即 0x9E3779B97F4A7C15A
				The binary numbers are stripped of the floating point portion and converted to hexadecimal, i.e: 0x9E3779B97F4A7C15
			*/
			result_type generate_chaotic_number(std::size_t algorithm_execute_count)
			{
				/*
					Hamming weights (number of bits with 1)
					汉明权重(比特位为1的数量)
					std::popcount(Value);
				*/

				//32
				constexpr std::uint64_t FibonacciSequence = 0x1B70C8E97AD5F98ULL;
				//27
				constexpr std::uint64_t CircumferenceSequence = 0x243F6A8885A308D3ULL;
				//38
				constexpr std::uint64_t GoldenRatioSequence = 0x9E3779B97F4A7C15ULL;
				//32
				constexpr std::uint64_t EulerNumberSequence = 0xB7E151628AED2A6AULL;

				using CommonSecurity::GaloisFiniteField256;
				using CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange;
				MemoryDataFormatExchange memory_data_format_exchanger;
				GaloisFiniteField256<std::uint8_t>& GF256_Instance = GaloisFiniteField256<std::uint8_t>::get_instance();

				std::span<std::uint8_t> ByteSpan = memory_data_format_exchanger.Unpacker_8Byte(FibonacciSequence);
				const std::vector<std::uint8_t> FibonacciSequenceBytes(ByteSpan.begin(), ByteSpan.end());
				
				ByteSpan = memory_data_format_exchanger.Unpacker_8Byte(CircumferenceSequence);
				const std::vector<std::uint8_t> CircumferenceSequenceBytes(ByteSpan.begin(), ByteSpan.end());
				
				ByteSpan = memory_data_format_exchanger.Unpacker_8Byte(GoldenRatioSequence);
				const std::vector<std::uint8_t> GoldenRatioSequenceBytes(ByteSpan.begin(), ByteSpan.end());
				
				ByteSpan = memory_data_format_exchanger.Unpacker_8Byte(EulerNumberSequence);
				const std::vector<std::uint8_t> EulerNumberSequenceBytes(ByteSpan.begin(), ByteSpan.end());
				
				constexpr std::uint64_t Number2Power64Modulus = std::numeric_limits<result_type>::digits - static_cast<result_type>(1);
				
				/*
					Designed by: Twilight-Dream
					设计者：Twilight-Dream
				*/

				#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

				/*
					Method of random number quality test:
					https://www.pcg-random.org/posts/how-to-test-with-practrand.html
					
					Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS ~/PractRand/[PRNG-TEST]
					# g++ -std=c++20 -O3 -Wall -o my-nlfsr_test ./my-nlfsr.cpp -static

					Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS ~/PractRand/[PRNG-TEST]
					# ./my-nlfsr_test-version1.exe | ./RNG_test.exe stdin64 -tlmin 1TB -tlmax 512TB -tf 2 -te 1 -multithreaded
					RNG_test using PractRand version 0.95
					RNG = RNG_stdin64, seed = unknown
					test set = expanded, folding = extra

					rng=RNG_stdin64, seed=unknown
					length= 1 terabyte (2^40 bytes), time= 37829 seconds
					  no anomalies in 2460 test result(s)

					rng=RNG_stdin64, seed=unknown
					length= 2 terabytes (2^41 bytes), time= 83022 seconds
					  no anomalies in 2530 test result(s)
				*/

				if(algorithm_execute_count < 8)
					algorithm_execute_count = 8;

				result_type answer = 0;
				for (std::size_t round_counter = 0; round_counter < algorithm_execute_count; ++round_counter)
				{
					std::uint8_t bit = (state[0] ^ state[1]) & 0x01;

					answer <<= 1;
					answer |= bit;

					if((std::popcount(answer) & 0x01) != 0)
					{
						//Equivalent to function
						//GF256_Instance.addition_or_subtraction(reinterpret_cast<std::uint8_t*>(&answer)[index], FibonacciSequenceByteSpan);
						answer ^= FibonacciSequence;
					}
					else
					{
						auto multiplied_number_byte_span = memory_data_format_exchanger.Unpacker_8Byte(answer);

						for(std::uint8_t index = 0; index < sizeof(std::uint64_t); ++index)
							multiplied_number_byte_span[index] = GF256_Instance.multiplication(multiplied_number_byte_span[index], CircumferenceSequenceBytes[index]);

						//Equivalent to function
						//GF256_Instance.addition_or_subtraction(multiplied_number_byte_span, reinterpret_cast<std::uint8_t*>(answer)[index]);
						answer ^= memory_data_format_exchanger.Packer_8Byte(multiplied_number_byte_span);
					}

					if(algorithm_execute_count % 2 == 0)
					{
						auto& [value_0, value_1] = state;

						//可引起雪崩效应的二进制Mixed线性反馈移位寄存器处理
						//Binary Mixed linear feedback shift register processing that can cause avalanche effects
						//该函数被频繁调用时，非常消耗CPU的计算能力
						//When this function is called frequently, it consumes a lot of CPU computing power
						std::uint64_t&& random_number = static_cast<std::uint64_t>((answer >> static_cast<std::uint64_t>(53) ^ answer) ^ value_0);

						value_1 &= value_0;
						if(value_1 == 0)
							value_1 += value_0 * 2;

						answer ^= this->random_bits(value_1, random_number % 9ULL, static_cast<std::uint8_t>( (value_1 & 0x01) ^ bit ) );

						value_0 &= value_1;
						if(value_0 == 0)
							value_0 += value_1 * 2;
					}
					else
					{
						//应用所有状态的混合数据
						//Apply mixed data for all states

						state[0] ^= result_type{1} << (state[1] & Number2Power64Modulus);

						std::uint64_t a = state[0] & state[1];
						a ^= answer;

						std::uint64_t b = state[1] & answer;
						b ^= state[0];

						std::uint64_t c = answer & state[0];
						c ^= state[1];

						answer = ~((a | b) & c);

						state[1] ^= result_type{1} << (state[0] & Number2Power64Modulus);

						a = 0;
						b = 0;
						c = 0;
					}

					if((std::popcount(state[1]) & 0x01) == 0)
					{
						auto multiplied_number_byte_span = memory_data_format_exchanger.Unpacker_8Byte(state[1]);

						for(std::uint8_t index = 0; index < sizeof(std::uint64_t); ++index)
							multiplied_number_byte_span[index] = GF256_Instance.multiplication(multiplied_number_byte_span[index], GoldenRatioSequenceBytes[index]);

						//Equivalent to function
						//GF256_Instance.addition_or_subtraction(state[1], multiplied_number_byte_span);
						state[1] ^= memory_data_format_exchanger.Packer_8Byte(multiplied_number_byte_span);

						if(state[1] == 0)
						{
							//Equivalent to function
							//GF256_Instance.addition_or_subtraction(state[1], FibonacciSequenceByteSpan);
							state[1] ^= FibonacciSequence;
						}
					}
					else
					{
						//Equivalent to function
						//GF256_Instance.addition_or_subtraction(state[1], EulerNumberSequenceByteSpan);
						//GF256_Instance.addition_or_subtraction(state[1], reinterpret_cast<std::uint8_t*>(&answer)[index]);
						state[1] ^= EulerNumberSequence ^ answer;
					}
				}

				/*
					重要说明:
					这里的两个step常数17和42，可以互换位置；比特位左移（<<）和比特位右移（>>），也可以互换位置。
					注意，这个比特数互斥的或操作不能被删除，而且操作数必须是一个变量ANSWER！
					虽然两个step常数可以是 step ∈ [0 ，63]的任意数字，但是它们必须不相等而且需是1个奇数和1个偶数!

					Important Notes:
					The two step constants here, 17 and 42, can swap positions; bitwise left shifts (<<) and bitwise right shifts (>>), can also swap positions.
					Note that this bitwise exclusive-or operation cannot be removed, and the operand must be a variable ANSWER!
					Although the two step constants can be any number of step ∈ [0 , 63], they must be unequal and need to be 1 odd and 1 even!
				*/
				return answer ^ ( (answer >> 42) | (answer << 17) );
				
				//state[0] = std::rotl(state[0], 42) >> 1;
				//state[1] = std::rotr(state[1], 17) << 1;
				//answer ^= ( 0x01ULL << ( ( state[0] | state[1] ) & Number2Power64Modulus) );
				//return answer;

				#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2
				
				/*

				Method of random number quality test:
				https://www.pcg-random.org/posts/how-to-test-with-practrand.html
				
				Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS ~/PractRand/[MY-PRNG-TEST]
				# ./my-nlfsr_test-version3.exe | ./RNG_test.exe stdin64 -tlmin 1TB -tlmax 512TB -tf 2 -te 1 -multithreaded

				*/
				
				if(algorithm_execute_count < 8)
					algorithm_execute_count = 8;

				result_type answer = 0;
				std::uint8_t bit = 0;
				for (std::size_t round_counter = 0; round_counter < algorithm_execute_count; ++round_counter)
				{
					bit = (state[0] ^ state[1] ^ state[2] ^ state[3]) & 0x01;

					answer <<= 1;
					answer |= bit;

					if((std::popcount(answer) & 0x01) != 0)
					{
						//Equivalent to function
						//GF256_Instance.addition_or_subtraction(reinterpret_cast<std::uint8_t*>(&answer)[index], CircumferenceSequenceByteSpan);
						answer ^= CircumferenceSequence;
					}
					else
					{
						auto multiplied_number_byte_span = memory_data_format_exchanger.Unpacker_8Byte(answer);

						auto& SequenceBytes = (answer ^ state[1]) & 0x01 ? FibonacciSequenceBytes : GoldenRatioSequenceBytes;

						for(std::uint8_t index = 0; index < sizeof(std::uint64_t); ++index)
							multiplied_number_byte_span[index] = GF256_Instance.multiplication(multiplied_number_byte_span[index], SequenceBytes[index]);

						//Equivalent to function
						//GF256_Instance.addition_or_subtraction(multiplied_number_byte_span, FibonacciSequenceByteSpan);
						answer ^= memory_data_format_exchanger.Packer_8Byte(multiplied_number_byte_span);
					}

					if((std::popcount(state[2]) & 0x01) == 0)
					{
						auto multiplied_number_byte_span = memory_data_format_exchanger.Unpacker_8Byte(state[2]);

						auto& SequenceBytes = (answer ^ state[3]) & 0x01 ? EulerNumberSequenceBytes : CircumferenceSequenceBytes;

						for(std::uint8_t index = 0; index < sizeof(std::uint64_t); ++index)
							multiplied_number_byte_span[index] = GF256_Instance.multiplication(multiplied_number_byte_span[index], SequenceBytes[index]);

						//GF256 addition_or_subtraction
						state[2] ^= memory_data_format_exchanger.Packer_8Byte(multiplied_number_byte_span);

						if((state[2] & 0x01) == 0)
						{
							state[2] ^= FibonacciSequence;
						}
					}
					else
					{
						state[2] ^= GoldenRatioSequence ^ answer;

						if((state[2] & 0x01) != 0)
						{
							state[2] ^= CircumferenceSequence;
						}
					}

					if(round_counter % 2 == 0)
					{
						auto& [value_0, value_1, value_2, value_3] = state;
						
						//可引起雪崩效应的二进制哈希处理
						//Binary hash processing that can cause an avalanche effect
						//该函数被频繁调用时，非常消耗CPU的计算能力
						//When this function is called frequently, it consumes a lot of CPU computing power
						std::uint64_t&& random_number = static_cast<std::uint64_t>((answer >> static_cast<std::uint64_t>(17) ^ value_1) ^ value_2);
						
						value_0 &= value_3;
						if(value_0 == 0)
							value_0 += (value_2 * 2);

						answer ^= this->random_bits(value_0, random_number % 9ULL, static_cast<std::uint8_t>( (value_3 & 0x01) ^ bit ));

						value_3 &= value_0;
						if(value_3 == 0)
							value_3 -= value_1 * 2;

						//Deprecated code:
						//std::uint64_t&& random_number = static_cast<std::uint64_t>( ( answer >> 53 ^ state[1] ) ^ state[2] );
						//answer ^= this->random_bits( random_number & static_cast<std::uint64_t>(8 - 1), (state[2] & 0x01) ^ bit);
					}
					else
					{
						auto& [value_0, value_1, value_2, value_3] = state;

						//Bit Data Mixing Function
						//比特数据混合函数
						value_1 ^= std::rotr(answer ^ value_0, static_cast<result_type>(value_3 - value_2) & Number2Power64Modulus);
						value_2 ^= value_1 << (static_cast<result_type>(value_0 + value_3) & Number2Power64Modulus);
						value_3 ^= value_2 >> (static_cast<result_type>(value_1 + value_0) & Number2Power64Modulus);
						value_0 ^= std::rotl(answer ^ value_3, static_cast<result_type>(value_1 - value_2) & Number2Power64Modulus);

						//Pseudo-Hadamard Transform
						//伪哈达马德变换

						result_type value_a = (value_0 + value_1) == 0ULL ? bit : (value_0 + value_1);
						result_type value_b = (value_0 + value_1 * 2ULL) == 0ULL ? bit : (value_0 + value_1 * 2ULL);
						result_type value_c = (value_3 - value_2) == 0ULL ? bit : (value_3 - value_2);
						result_type value_d = (value_2 * 2ULL - value_3) == 0ULL ? bit : (value_2 * 2ULL - value_3);

						//Forward form
						value_0 ^= value_a;
						value_1 ^= value_b;

						//Backward form
						value_2 ^= value_c;
						value_3 ^= value_d;

						value_a = value_b = value_c = value_d = 0ULL;

						//应用所有状态的混合数据
						//Apply mixed data for all states
						answer ^= state[0] ^ state[1] ^ state[2] ^ state[3];
					}

					//对于内部状态的比特位集进行(左旋转和右旋转)1位
					//For the internal state the set of bits is performed (left rotation and right rotation) 1 bit
					//state[0] = ( state[0] << 1 ) | ( state[1] >> 63 );
					//state[1] = ( state[1] >> 1 ) | ( state[2] << 63 );
					//state[2] = ( state[2] << 1 ) | ( state[3] >> 63 );
					//state[3] = ( state[3] >> 1 ) | ( state[0] << 63 );

				}
				bit = 0ULL;

				/*
					重要说明:
					这里的两个step常数17和42，可以互换位置；比特位左移（<<）和比特位右移（>>），也可以互换位置。
					注意，这个比特数互斥的或操作不能被删除，而且操作数必须是一个变量ANSWER！
					虽然两个step常数可以是 step ∈ [0 ，63]的任意数字，但是它们必须不相等而且需是1个奇数和1个偶数!

					Important Notes:
					The two step constants here, 17 and 42, can swap positions; bitwise left shifts (<<) and bitwise right shifts (>>), can also swap positions.
					Note that this bitwise exclusive-or operation cannot be removed, and the operand must be a variable ANSWER!
					Although the two step constants can be any number of step ∈ [0 , 63], they must be unequal and need to be 1 odd and 1 even!
				*/

				return answer ^ ( (answer << 17) | (answer >> 42) );
				
				//state[0] = std::rotr(state[0], 17) << 42;
				//state[1] = std::rotl(state[1], 42) >> 17;
				//state[2] = std::rotr(state[2], 17) << 42;
				//state[3] = std::rotl(state[3], 42) >> 17;
				//result_type random_number = (state[1] & state[3]) ^ (state[0] | state[2]);
				//answer ^= ( 0x01ULL << (random_number & Number2Power64Modulus) );
				//return answer

				#endif
			}

			//产生不可预测的比特序列
			//Generate unpredictable bit sequences
			result_type unpredictable_bits(std::uint64_t base_number, std::size_t number_bits)
			{
				/*
				
					使用同一种数字种子，构造一个非线性反馈移位寄存器的对象，然后调用这个函数。
					根据基础数字(base_number)参数是否是奇数还是偶数，来决定即将生成的两种不同的比特序列的一种。
					
					Using the same numeric seed, construct an object of a nonlinear feedback shift register and call this function.
					Depending on whether the (base_number) argument is odd or even, it determines one of the two different bit sequences that will be generated.

					然而，有一种例外情况
					如果在(number_bit)参数大于等于64
					因为比特右移或者比特左移的次数大于了64，所以线性反馈移位寄存器(结果值 - answer)的特征被破坏了
					那么这个序列将会呈现一种就连线性反馈移位寄存器都不可知的混沌状态。
					尽管提供的所有参数和内部的状态是相同的，你也能还原出这些序列

					当序列处于混沌状态时，有可能处于线性和非线性状态之间，请自行记录所有提供的参数和数字种子。

					However, there is an exception to this rule
					If the (number_bit) parameter is greater than or equal to 64
					the linear feedback shift register (result value - answer) is broken because the number of bits shifted right or left is greater than 64
					Then the sequence will be chaotic in a way that even the linear feedback shift register is not known.
					Even though all the parameters provided and the internal state are the same, you can restore these sequences

					When the sequence is in a chaotic state, it may be in between linear and non-linear states, so please record all the provided parameters and numerical seeds yourself.
				*/

				result_type answer = base_number;
				result_type current_random_bit = 0U;

				std::array<std::uint8_t, 4> current_random_bits {0,0,0,0};

				for (std::size_t round_counter = 0; round_counter < number_bits; ++round_counter)
				{
					#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

					current_random_bit = state[1] & 0x01;
					//丢弃答案随机数的最高比特位，最低位由'0'补上
					//Discard the highest bit of the answer random number, the lowest bit is complemented by '0'
					answer <<= 1;
					//答案的随机数 BIT_OR 0ULL || 1ULL
					//The answer random number BIT_OR 0ULL || 1ULL
					answer |= current_random_bit;

					//计算二进制的伪随机比特序列
					//Compute pseudo-random bit sequences in binary
					//我这里把不同程度的线性反馈移位寄存器组合在一起
					//它们构成了一个非线性反馈移位寄存器，由这些状态混合然后生成的数字都是不能被预测的
					//I have combined different degrees of linear feedback shift registers here
					//They form a nonlinear feedback shift register, and the numbers generated by mixing these states are not predictable
					state[0] = this->random_bits(state[0], state[0] % 9ULL, current_random_bit);

					//只保留一个二进制的随机比特位
					//Only one binary random bit is retained
					current_random_bit = state[0] & 0x01;

					//根据当前状态(随机数种子或者随机数)，获取比特序列的最低比特位;
					//并且把那个比特位设置到下一个状态(随机数种子或者随机数)的最高比特位
					//Get the lowest bit of the bit sequence according to the current state (random number seed or random number);
					//and set that bit to the highest bit of the next state (random number seed or random number)
					
					state[1] >>= 1;
					state[1] |= (state[0] & 0x01ULL) << 63;
					
					state[0] >>= 1;
					state[0] |= current_random_bit << 63;

					#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

					current_random_bit = ((state[0] ^ state[1] ^ state[2] ^ state[3]) >> 63) & 0x01;
					
					//丢弃答案随机数的最高比特位，最低位由'0'补上
					//Discard the highest bit of the answer random number, the lowest bit is complemented by '0'
					answer <<= 1;
					
					//答案的随机数 BIT_OR 0ULL || 1ULL
					//The answer random number BIT_OR 0ULL || 1ULL
					answer ^= current_random_bit;
					
					//计算二进制的伪随机比特序列
					//Compute pseudo-random bit sequences in binary
					//我这里把不同程度的线性反馈移位寄存器组合在一起
					//它们构成了一个非线性反馈移位寄存器，由这些状态混合然后生成的数字都是不能被预测的
					//I have combined different degrees of linear feedback shift registers here
					//They form a nonlinear feedback shift register, and the numbers generated by mixing these states are not predictable
					state[0] = this->random_bits(state[0], (state[3] ^ state[2]) % 9ULL, current_random_bit);
					
					//只保留一个二进制的随机比特位
					//Only one binary random bit is retained
					current_random_bits[0] ^= state[0] & 0x01;
					
					state[1] = this->random_bits(state[1], (state[2] ^ state[1]) % 9ULL, current_random_bit);
					
					//只保留一个二进制的随机比特位
					//Only one binary random bit is retained
					current_random_bits[1] ^= state[1] & 0x01;
					
					state[2] = this->random_bits(state[2], (state[1] ^ state[0]) % 9ULL, current_random_bit);

					//只保留一个二进制的随机比特位
					//Only one binary random bit is retained
					current_random_bits[2] ^= state[2] & 0x01;
					
					state[3] = this->random_bits(state[3], (state[0] ^ state[3]) % 9ULL, current_random_bit);

					//只保留一个二进制的随机比特位
					//Only one binary random bit is retained
					current_random_bits[3] ^= state[3] & 0x01;
					
					current_random_bit = (current_random_bits[0] | current_random_bits[1])
						^ (current_random_bits[1] & current_random_bits[2])
						^ (current_random_bits[2] | current_random_bits[3])
						^ (current_random_bits[3] & current_random_bits[0]);

					//丢弃答案随机数的最高比特位，最低位由'0'补上
					//Discard the highest bit of the answer random number, the lowest bit is complemented by '0'
					answer <<= 1;
					
					answer |= current_random_bit;
					
					std::iter_swap(current_random_bits.begin() + (state[0] % current_random_bits.size()), current_random_bits.end() - 1);
					std::iter_swap(current_random_bits.begin() + (state[1] % current_random_bits.size()), current_random_bits.end() - 1);
					std::iter_swap(current_random_bits.begin() + (state[2] % current_random_bits.size()), current_random_bits.end() - 1);
					std::iter_swap(current_random_bits.begin() + (state[3] % current_random_bits.size()), current_random_bits.end() - 1);

					//根据当前状态(随机数种子或者随机数)，获取比特序列的最低比特位;
					//并且把那个比特位设置到下一个状态(随机数种子或者随机数)的最高比特位
					//Get the lowest bit of the bit sequence according to the current state (random number seed or random number);
					//and set that bit to the highest bit of the next state (random number seed or random number)
					
					state[1] >>= 1;
					state[1] |= (state[0] & 0x01ULL) << 63;
					
					state[2] >>= 1;
					state[2] |= (state[1] & 0x01ULL) << 63;
					
					state[3] >>= 1;
					state[3] |= (state[2] & 0x01ULL) << 63;
					
					state[0] >>= 1;
					state[0] |= (state[3] & 0x01ULL) << 63;
					
					/*
					current_random_bit = (state[0] ^ state[1] ^ state[2]) & 0x01;
					
					answer ^= current_random_bit;
					*/

					#endif
				}

				volatile void* CheckPointer = std::memset(current_random_bits.data(), 0, current_random_bits.size());
				CheckPointer = nullptr;

				return answer;
			}

			result_type operator() (void)
			{

				#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1
				
				//这里的参数影响随机数生成算法的时间复杂度
				//The parameters here affect the time complexity of the random number generate algorithm
				//Recommended number of executions(建议执行次数): algorithm_execute_count ∈ [8, 1024]
				//Example value is: 8,9,10,11,12,13,14,15,16 ...... 1024
				return this->generate_chaotic_number(8);

				#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

				//这里的参数影响随机数生成算法的时间复杂度
				//The parameters here affect the time complexity of the random number generate algorithm
				//Recommended number of executions(建议执行次数): algorithm_execute_count ∈ [8, 1024]
				//Example value is: 8,9,10,11,12,13,14,15,16 ...... 1024
				return this->generate_chaotic_number(8);

				#endif
			}

			static constexpr result_type min()  
			{ 
				return 0;
			}

			static constexpr result_type max()
			{
				return 0xFFFFFFFFFFFFFFFF;
			};

			void seed(result_type seed) 
			{ 
				*this = NonlinearFeedbackShiftRegister(seed);
			}

			void discard(std::size_t round_number)
			{
				if(round_number == 0)
					++round_number;

				#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1
				this->generate_chaotic_number(round_number * 4);

				#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2
				this->generate_chaotic_number(round_number * 2);

				#endif
			}

			#ifndef BOOST_RANDOM_NO_STREAM_OPERATORS

			/**  Writes a @c rand48 to a @c std::ostream. */
			template<class CharT, class Traits>
			friend std::basic_ostream<CharT, Traits>&
			operator<<(std::basic_ostream<CharT, Traits>& os, const NonlinearFeedbackShiftRegister& nlfsr)
			{ os << nlfsr.state[0]; os << ","; os << nlfsr.state[1]; return os; }

			/** Reads a @c rand48 from a @c std::istream. */
			template<class CharT, class Traits>
			friend std::basic_istream<CharT, Traits>&
			operator>>(std::basic_istream<CharT, Traits>& is, NonlinearFeedbackShiftRegister& nlfsr)
			{ char command; is >> nlfsr.state[0]; is >> command; is >> nlfsr.state[1]; return is; }

			#endif
			
			explicit NonlinearFeedbackShiftRegister(result_type seed)
			{
				if(seed == 0)
					++seed;

				#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1
				
				//Initial state
				state[0] = seed;
				state[1] = (seed * 2) + 1;

				//Update state
				for(std::size_t initial_round = 32; initial_round > 0; initial_round--)
				{
					//应用所有状态的混合数据
					//Apply mixed data for all states
				
					state[0] ^= result_type{1} << (state[1] & (std::numeric_limits<result_type>::digits - result_type{1}));

					std::uint64_t a = state[0] & state[1];
					a ^= seed;

					std::uint64_t b = this->random_bits(state[0], a % 9ULL, state[0] ^ state[1]) & state[1];
					b ^= state[0];

					std::uint64_t c = this->random_bits(state[1], (a ^ b) % 9ULL, (state[0] | state[1]) & 0x01) & state[0];
					c ^= state[1];

					seed = a ^ b ^ c;
				
					state[1] ^= result_type{1} << (seed & (std::numeric_limits<result_type>::digits - result_type{1}));

					a = 0;
					b = 0;
					c = 0;
				}

				#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

				//Initial state
				state[0] = seed;
				state[1] = (seed * 2) + 1;
				state[2] = (seed * 3) + 2;
				state[3] = (seed * 4) + 3;

				//Mix state (stage 1/2)
				state[0] += (state[1] ^ state[2]) ^ ~(state[3]);
				state[1] -= (state[2] & state[3]) | state[0];
				state[2] += (state[3] ^ state[0]) ^ ~(state[1]);
				state[3] -= (state[0] | state[1]) & state[2];

				//Mix state (stage 2/2)
				state[3] *= (seed << 48) & 0xffffffff;
				state[2] *= (seed << 32) & 0xffffffff;
				state[1] *= (seed << 16) & 0xffffffff;
				state[0] *= (seed) & 0xffffffff;

				//Update state
				for(std::size_t initial_round = 128; initial_round > 0; initial_round--)
				{
					state[2] ^= this->random_bits(state[0], static_cast<std::uint64_t>( ( state[0] >> 6 ^ state[1] ) ^ state[3] ^ seed ) % 9, state[1] & 0x01);
					state[3] ^= this->random_bits(state[1], static_cast<std::uint64_t>( ( state[1] << 57 ^ state[0] ) ^ state[2] ^ seed ) % 9, state[0] & 0x01);
					state[0] ^= this->random_bits(state[2], static_cast<std::uint64_t>( ( state[2] >> 24 ^ state[3] ) ^ state[1] ^ seed ) % 9, state[3] & 0x01);
					state[1] ^= this->random_bits(state[3], static_cast<std::uint64_t>( ( state[3] << 37 ^ state[2] ) ^ state[0] ^ seed ) % 9, state[2] & 0x01);

					//Current random bit
					std::uint64_t bit = (state[0] & 0x01) ^ (state[1] & 0x01) ^ (state[2] & 0x01) ^ (state[3] & 0x01);

					//Perform the nonlinear feedback function
					std::uint64_t temporary_state = (state[0] ^ state[1]) & state[2] | state[3];
					
					//Override seed number values
					seed = std::rotr(seed, 49) * std::rotl(state[0], 13);

					//Shift the values in the state array
					state[0] = state[1];
					state[1] = state[2];
					state[2] = state[3];
					state[3] = temporary_state;
					
					//In the (MSB/LSB) position, set a random bit
					seed |= (temporary_state & 0x01) ? (bit << 63) : bit & 0x01;
				}

				#endif
			}

			NonlinearFeedbackShiftRegister() : NonlinearFeedbackShiftRegister(1)
			{
				
			}

			NonlinearFeedbackShiftRegister(NonlinearFeedbackShiftRegister const &nlfsr)
			{
				#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

				state[0] = nlfsr.state[0];
				state[1] = nlfsr.state[1];

				#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

				state[0] = nlfsr.state[0];
				state[1] = nlfsr.state[1];
				state[2] = nlfsr.state[2];
				state[3] = nlfsr.state[3];

				#endif
			}

			NonlinearFeedbackShiftRegister(NonlinearFeedbackShiftRegister&& other_object)
				:
				state{other_object.state}
			{
				
			}

			NonlinearFeedbackShiftRegister& operator=(NonlinearFeedbackShiftRegister&& other_object)
			{
				//Do not move from ourselves or all hell will break loose
				//不要离开我们自己，否则大祸临头。
				if(this == &other_object)
					return *this;

				//Call our own destructor to clean up the class object before moving it
				//在移动类对象之前，调用我们自己的析构器来清理它
				std::destroy_at(this);

				//Moving class objects from calling our own copy constructor or move constructor
				//从调用我们自己的复制构造函数或移动构造函数来移动类对象
				std::construct_at(this, other_object);

				return *this;
			}

			~NonlinearFeedbackShiftRegister()
			{
				#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1
				
				state[0] = 0;
				state[1] = 0;

				#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

				state[0] = 0;
				state[1] = 0;
				state[2] = 0;
				state[3] = 0;

				#endif
			}
		};

		#undef SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION
	}
	
}