#include "XorConstantRotation.h"

namespace TwilightDreamOfMagical::CustomSecurity
{
	namespace CSPRNG
	{
		/*
		import math
		from mpmath import mp
		# Set the desired decimal precision
		mp.dps = 100
		# Define the mathematical constants
		e = mp.e
		pi = mp.pi
		phi = (1 + mp.sqrt(5)) / 2
		sqrt_2 = mp.sqrt(2)
		sqrt_3 = mp.sqrt(3)
		gamma = mp.mpf("0.5772156649") # Euler–Mascheroni constant
		delta = mp.mpf("4.6692016091") # Feigenbaum constant
		rho = mp.mpf("1.3247179572") # Plastic number
		def f(x):
			x = mp.mpf(x)
			term1 = (e ** x - mp.cos(pi * x))
			term2 = (phi * x ** 2 - phi * x - 1)
			term3 = (x * sqrt_2 - mp.floor(x * sqrt_2))
			term4 = (x * sqrt_3 - mp.floor(x * sqrt_3))
			term5 = mp.log(1 + x)
			term6 = (x * delta - mp.floor(x * delta))
			term7 = (x * rho - mp.floor(x * rho))
			return term1 * term2 * term3 * term4 * term5 * term6 * term7
		x = 1
		binary_string = ""
		for index in range(150):
		  # Calculate the result for a given input value
		  result = f(x)
		  print("Round: ", index)

		  # Print the decimal result
		  print("Decimal number:", result)

		  # Convert the fractional part to binary and print it
		  fractional_part = result - mp.floor(result)
		  binary_fractional_part = format(int(fractional_part * 2**128), 'b')  # Using 128 bits of precision for the binary representation
		  # print("Binary representation of fractional part:", binary_fractional_part)

		  # Convert the fractional part to hexadecimal and print it
		  hexadecimal_fractional_part = format(int(fractional_part * 2**128), 'x')
		  print("Hexadecimal representation of fractional part:", hexadecimal_fractional_part)

		  # Print the integer part
		  integer_part = int(result)
		  print("Integer part:", integer_part)
		  x += 1
		  binary_string += (binary_fractional_part)
		print("Binary String: ", binary_string)
		# Convert the binary string to an integer
		integer_value = int(binary_string, 2)
		# Convert the integer to a hexadecimal string
		hexadecimal_string = format(integer_value, 'x')
		print("Hexadecimal representation:", hexadecimal_string)
		*/
		constexpr std::array<std::uint64_t, 300> ROUND_CONSTANT
		{
			//Concatenation of Fibonacci numbers., π, φ, e
			0x01B70C8E97AD5F98ULL,0x243F6A8885A308D3ULL,0x9E3779B97F4A7C15ULL,0xB7E151628AED2A6AULL,

			//x ∈ [1, 138]
			//f(x) = (e^x - cos(πx)) * (φx^2 - φx - 1) * (2√x - floor(2√x)) * (3√x - floor(3√x)) * ln(1+x) * (xδ - floor(xδ)) * (xρ - floor(xρ))
			0x6a433d2ae48d4c90ULL,0x9e2b6e6880ad26daULL,0x5380e7890f281d86ULL,0x47ea9e01d8ef7c3cULL,
			0xb7cfc42c4640a591ULL,0x8ba869f86f575f77ULL,0x66ff83fd9954772cULL,0x0552755b7ef8c3f6ULL,
			0xe4931d40d079c5cbULL,0xd6065bf025a81d13ULL,0x586ceb7761d284afULL,0x5407a44155b8e341ULL,
			0x7810f48181dff9e2ULL,0x0f44524582d1d6cfULL,0x919ad67c2cd7118cULL,0x926d94a3923cb938ULL,
			0xc3f400bd67479e59ULL,0x83cb03ba7366b70eULL,0x629043e6e5712e5cULL,0x69589ff399736efbULL,
			0x834d96f80eea56d7ULL,0x02992cb1835476aaULL,0x78502c2a1b947013ULL,0xbca81dad05eac8c7ULL,
			0x43216fe770f57c2dULL,0x604a5ccfe888eef1ULL,0xfcf5bdd0ea8a112cULL,0xeb13dc4ba7327617ULL,
			0xf8587cc0dd587813ULL,0x092b98e058140b26ULL,0x1e044153ec902650ULL,0xd13ef3afb71efc3eULL,
			0x55af3f5bca28309eULL,0xcf478054be1173c8ULL,0x99bb2b591f35ac72ULL,0xd3f5e092a0c7c2bbULL,
			0xdc120bced1935766ULL,0xbb2525cf28193ea8ULL,0x6a06eb360550e537ULL,0x4501817d5023f9bbULL,
			0x6c9e6ef207e06420ULL,0xa12e023656301669ULL,0x2692fa5ed25b6a2bULL,0xeb48ef08fd6fbdb7ULL,
			0xfe8db57151c600fbULL,0x51197bfba60c36ffULL,0xe95328ef18701542ULL,0x0663e86118debfddULL,
			0xee0b0fcbaf12d0d0ULL,0xc92c72f7a14c35eaULL,0x21ca0bd30529c74cULL,0x70243d7854330319ULL,
			0x193b70b72995d737ULL,0xa936acbbbe88f426ULL,0x61da22530a461898ULL,0x49afa0f477bda24cULL,
			0x795bbbc0bf0cdc23ULL,0x3b5f4cf676e0fc41ULL,0xdeec67413dc24105ULL,0x1af46f766498679dULL,
			0xa9f37172c15f8e20ULL,0x292b237adf6467a9ULL,0x09538ddc3733c79eULL,0xde5c2f22b2c1aa42ULL,
			0x6204c7ebee5a90d8ULL,0x4359ac75de286849ULL,0x7e616650ab318ae8ULL,0xd7552e509ab0d5a6ULL,
			0xffaf2a408f8cfa95ULL,0x4289e66a0b74427eULL,0xc5e9869af1856c6dULL,0x336aa2e2b3dbfedaULL,
			0x9835ff10bf4b7e3cULL,0xc0c5d995789a9c04ULL,0x09dce0a22fccbe60ULL,0x7cc16b5458b38ec9ULL,
			0x880d6019ab1aa3faULL,0xb9ac43e6d90c89dcULL,0xe0c876bea28b38beULL,0xafca75b1c80bc8faULL,
			0xf4e5b08059acb0bdULL,0x643587ac551f3aa0ULL,0x83fa523817844ac9ULL,0x3e97eca86cc41268ULL,
			0xd53517b095a47a79ULL,0x418aaab53810d432ULL,0xde9ad8739ba769b7ULL,0x6f53b6fb08b9809cULL,
			0xe5d41d82eb6a0d63ULL,0x42137200d3b75b64ULL,0x9ee670cd25143c29ULL,0xdc2b3edf3617c034ULL,
			0xf5d6d70093472506ULL,0xeaca4e8f7eaa4b68ULL,0x0e7b78a6eca0e67eULL,0x67db9133f144d92dULL,
			0xa2f043bdf0bfc70dULL,0x679513157c68480eULL,0xc7359f77d43ecedbULL,0xa73610dd579db5e8ULL,
			0xd33f00a73c40b3f4ULL,0x1f6693cdc79f41cfULL,0x402aba3326ff09e4ULL,0xc2f06d96a33ed417ULL,
			0x16882cd0ac38796eULL,0xde2342960e538c6eULL,0xee16a05c0f946350ULL,0xb76895e14d9f81b0ULL,
			0x8d8e566bbc5b2b65ULL,0x1b1881ca8831ba3cULL,0x0fb99dab44900c06ULL,0x51701c39eabb7550ULL,
			0x98c5cadd4f0446cdULL,0x12cd6ac42824463fULL,0x815f799d0d2b6b8dULL,0xd34bed6a3284fb8fULL,
			0x1f4f71425e521345ULL,0x5ec3427cc37ef4b7ULL,0x41ca4c3fbb4ae014ULL,0x4d4a5a8399958a44ULL,
			0x6f21b526d0c7ee3cULL,0xe85d52cfba2818c0ULL,0x09d0b2cc4deccc35ULL,0x1b13c064ccec4d2eULL,
			0x92b538d3b747c6acULL,0x58719d59011b3faeULL,0xedde21671368f97eULL,0xfc4dbeff22c77aabULL,
			0x66997342600d0997ULL,0x6a173e62da2821d7ULL,0xe657b797f1f23506ULL,0x7052226e4dde4ce0ULL,
			0xcec9d219091d3713ULL,0x46b20fcd9abd9b13ULL,0x0a8bbb7b077261a8ULL,0x8cf03c3c366533dbULL,
			0x9d167cec4a7f4953ULL,0xed8bbf927c48dbf9ULL,0x21e8d4a1dd84e782ULL,0x4ac104ee6fa65e69ULL,
			0x5cb955963da25beeULL,0xa0f791f755ed9eadULL,0x1125fa77491b7c6aULL,0x3c0560dc8d08a6b6ULL,
			0x20cb39c7b8690d0cULL,0x29a3a26ccc8540deULL,0x3ba44a4cbb906982ULL,0xddf9454bc0acb110ULL,
			0xa989a47d915cc360ULL,0xb90af4a05b78e702ULL,0x7f20b78fb8d8eae8ULL,0xedb6cb8180b81603ULL,
			0xdfe86decf8f940b5ULL,0x4c6baf1de449fc4dULL,0x165f86d08961df51ULL,0x4c038e6a96040825ULL,
			0xf4f2cb95b6276944ULL,0xe7f98f0aae90ff54ULL,0xd90fc39cae09f82eULL,0x45ef9b03350e102cULL,
			0xba319140b8a35152ULL,0xa1c8bf3071254d17ULL,0x6d942b49712b2ff0ULL,0x687ab4e1a35f3a7fULL,
			0x8fa2a50edfdfce2dULL,0x1b123d5c5ba08e5bULL,0x287209f7e4ad4cd4ULL,0xaae61796f1414dd9ULL,
			0xabd88a4167ec1728ULL,0x584654213d59d9acULL,0x1010e8491f4e2d7dULL,0x01b6087b68d105e5ULL,
			0xd478306668f2aed3ULL,0x35b78cf5c30272dbULL,0x4e9b1bd35706711dULL,0xfbee714f84a270e5ULL,
			0x8855b3fe8d108055ULL,0x1829c0415ef92080ULL,0x2a6238b05b1e17f1ULL,0x270e32a624ce5105ULL,
			0x03a089b9cf427251ULL,0x468ff8821f5007cdULL,0xf3f13de46ea0de52ULL,0x2353e2eb32dd119cULL,
			0x5deef337d58f8050ULL,0x4627b46ab323ee76ULL,0x6bc50f6c85bf5ee4ULL,0x4e85d72c7ad96e41ULL,
			0xb3a3842fd79e9b66ULL,0xc1b355c2514cc12bULL,0x4d8d8e57e20a533fULL,0x9a230f94a80cc9ccULL,
			0x20287e80ba5f6a99ULL,0xbf798e5356d5544dULL,0xa4b98b8f7cf5d947ULL,0x5dfec4b0cf53d480ULL,
			0xaff6108433392823ULL,0xc77e7eafb9c35034ULL,0x627f1e008407d3a4ULL,0xd8187da069398c24ULL,
			0x5b82e2951399fb6bULL,0x8f4165a5b13ef5e5ULL,0xccc6836e6da90f20ULL,0x5bc18466d41ea4b4ULL,
			0xae57d5f0e7469301ULL,0x382ec77f6dda7973ULL,0x3334a04bfaf89130ULL,0x560ae692d459495dULL,
			0xad396981b2cc54c6ULL,0x721ee73a08477f9dULL,0xac3af4d5f2b948aeULL,0x8f027b0998907e6aULL,
			0xa2aa2576933135d2ULL,0xf977e97a32d0ff40ULL,0xc9ec4b2937331421ULL,0x0a60651dd255075eULL,
			0xbc57a87285ad8ce8ULL,0x05f745bb0f2f26c5ULL,0xdbcb6ea37829349eULL,0xac85ec736c6c05f0ULL,
			0xa0b8478607780956ULL,0xe1a6cfc18a52c5cfULL,0xfdc0c9870db192cbULL,0x6fef6fa94de1275fULL,
			0xe7095cf3a87858dfULL,0xa9382116dc12addfULL,0xfe43770e8ee1fdd0ULL,0x12b5911c68f5a4faULL,
			0xf674859107a9946eULL,0xbcbcec98535a2e90ULL,0x487bbba9ec45c860ULL,0xa6690ca5bfae55efULL,
			0x2e90b70e4a6edd45ULL,0xf75f315df85c92deULL,0x73c4b5d3f00c8ff6ULL,0x16e7c2df5e0cc2fdULL,
			0x4d3450b5d1238d73ULL,0x3be2360b8e8b5abfULL,0xaa9f15256af3545eULL,0x0b78b50380d558f5ULL,
			0x35b1cd715c1a79c2ULL,0xa5fd04e9b573386eULL,0xe8287684ad00498dULL,0x3af5a5175be12d85ULL,
			0x00bad43e22f3efd0ULL,0x2424d7c00ce3eea8ULL,0x43be6edf2c578cf0ULL,0x4640b84a827945fcULL,
			0x7e85782d5ed0fb6dULL,0xffde4449d800463dULL,0x5505de67825caf7cULL,0x958bad14a0d2bebdULL,
			0x19031376b81730d2ULL,0xffe7c1cfd5aaf333ULL,0x4a7cd21c4d61a00cULL,0xd955c74fee9622b4ULL,
			0xdb600428f8ec65bdULL,0x412e30c19e4e9b47ULL,0x1b39e37cd46c51fcULL,0x0b328354c1031b99ULL,
			0x71eb9da5c27e6be7ULL,0x56dd31a71467973dULL,0x9cefe510b69e8058ULL,0x516e50ccb614f4a3ULL,
			0x2feb109a1269f007ULL,0x5bed5039f264362cULL,0x5a35a81fc188b664ULL,0x86da46de6967b611ULL,
			0x21cbe3aa2bf1e587ULL,0x814748b95e35060dULL,0x4532a469e90aafc3ULL,0xe7cdfd61261c5f5fULL,
			0x5f9ed3b7b2f0e4c7ULL,0x8633484a1fe91578ULL,0x07982616ddb26917ULL,0x0a4a8fa267fd8e35ULL,
			0x0169aa3ddb17bbe0ULL,0x7ad23781004a8abbULL,0x8a99977154276184ULL,0xf5aa49eb805db993ULL,
			0xa91402c443f56747ULL,0x3a158fd200401788ULL,0x90d1286159a88e33ULL,0x225ba3c00271a613ULL,
			0xee87820cfe2bc5c1ULL,0xf9cdfc0003d47859ULL,0x58c3aeb0ed7bd81bULL,0x9dd2e17302417c1cULL,
			0x83236763812fd272ULL,0x66337800026dd3d8ULL,0x67926c64cdb2e951ULL,0x28cd00001a9deeb6ULL,
			0x7f5198092527e597ULL,0x87de18001de39c2aULL,0x2389f07669962eeeULL,0x4f2800002f2e26acULL,
		};

		void XorConstantRotation::StateInitialize()
		{
			counter = 0;

			if(state == 0)
				state = 1;

			uint64_t state_0 = state;
			uint64_t random = state;
			
			//Goldreich-Goldwasser-Micali Construct PRF’s <How to construct random functions>
			//https://www.wisdom.weizmann.ac.il/~oded/X/ggm.pdf 
			for(size_t round = 0; round < 4; round++)
			{
				uint64_t next_random = 0;
				for ( size_t bit_index = 0; bit_index < 64; bit_index++ )
				{
					//Iterative use of PRG to generate random values
					//迭代使用PRG生成随机值
					random = this->StateIteration(random);

					if(random & 1)
					{
						//If the generated random value is odd, set the current bit of the next random value to zero
						//如果生成的随机值是奇数,把下一次随机值当前比特设置为0
						//y=PRG[0](x)
						next_random |= 0;
						next_random <<= 1;
					}
					else
					{
						//Otherwise the random value generated is even, set the current bit of the next random value to 1
						//否则生成的随机值是偶数,把下一次随机值当前比特设置为1
						//y=PRG[1](x)
						next_random |= 1;
						next_random <<= 1;
					}
				}

				//Updates the next random value to the current random value.
				//把下一次的随机值更新为当前的随机值。
				random = next_random;
			}

			//Securely whitened uniformly randomized seeds.
			//安全白化的均匀随机种子。
			state ^= state_0 + random;
		}

		//Version select
		#if 0

		XorConstantRotation::result_type XorConstantRotation::StateIteration(std::size_t number_once)
		{
			y = (x ^ std::rotl(state, 32)) ^ std::rotl(state, 19);
			
			//使用 链式AR-Constant 模型 来密码分析？
			if(x == 0)
				x = ROUND_CONSTANT[number_once % ROUND_CONSTANT.size()];
			else
				x += std::rotl(x, 7) ^ ROUND_CONSTANT[number_once % ROUND_CONSTANT.size()] ^ number_once;
				
			// 使用 RX 模型 来密码分析？
			state = (x ^ y) + state;

			return y;
		}
		
		#else
		
		XorConstantRotation::result_type XorConstantRotation::StateIteration(std::size_t number_once)
		{
			//使用本次轮常量
			std::uint64_t RC0 = ROUND_CONSTANT[number_once % ROUND_CONSTANT.size()];
			std::uint64_t RC1 = ROUND_CONSTANT[(counter + number_once) % ROUND_CONSTANT.size()];
			std::uint64_t RC2 = ROUND_CONSTANT[state % ROUND_CONSTANT.size()];

			//使用 链式AR-Constant 模型 来密码分析？
			if(x == 0)
				x = RC0;
			else
			{
				/*
					扩散层：通过BitRotate和XOR操作实现各自状态之间的独立变换
					Diffusion layer: independent transformations between respective states via BitRotate and XOR operations
				*/

				// SM4-like algorithm Linear diffusion
				// r1,r2,r3,r4
				// 使用 RX 模型 来密码分析？
				y = y ^ std::rotl(x, 19) ^ std::rotl(x, 32);
				state = state ^ std::rotl(y, 32) ^ std::rotl(y, 47) ^ std::rotl(y, 63) ^ counter;
				x = x ^ std::rotl(state, 7) ^ std::rotl(state, 19) ^ RC0 ^ number_once;
			}

			/*
				混淆层：通过混合内部状态和非线性运算实现各自状态之间复杂关联变换
				Confusion layer: complex associative transformations between states by mixing internal states and nonlinear operations
			*/

			state += y ^ std::rotr(y, 1) ^ RC0; //use y
			x ^= state + std::rotr(state, 1) + RC1; //use state
			y += x ^ std::rotr(x, 1) ^ RC2; //use x

			counter++;

			return y;
		}
		
		#endif

	} // TwilightDreamOfMagical
} // CustomSecurity