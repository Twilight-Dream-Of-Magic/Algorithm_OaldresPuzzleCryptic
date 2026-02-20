#include "LittleOaldresPuzzle_Cryptic.h"

/*

Linear layer box attribute:

	find_linear_box.exe --bits 32 --efficient-implementation --quality-threshold-branch-number 12 --max-xor 6 --seed 4 --need-found-result 2 --no-progress
	M(rotl)_hex = 0xd05a0889  M(rotl)^{-1}_hex = 0x5fc08ef4
	M(rotr)_hex = 0x2220b417  M(rotr)^{-1}_hex = 0x5ee207f4
	minimum weight found (pair) = 12
	rotl: diff=12 lin=12 combined=12
	rotr: diff=12 lin=12 combined=12
	Operations(rotl): start_bit=0 steps=6
	v0 = (1 << 0)  [0x00000001]
	v1 = v0 ^ rotl(v0,2)  [0x00000005]
	v2 = v0 ^ rotl(v1,17)  [0x000a0001]
	v3 = v0 ^ rotl(v2,4)  [0x00a00011]
	v4 = v3 ^ rotl(v3,24)  [0x11a0a011]
	v5 = v2 ^ rotl(v4,7)  [0xd05a0889]
	Operations(rotr): start_bit=0 steps=6
	v0 = (1 << 0)  [0x00000001]
	v1 = v0 ^ rotr(v0,2)  [0x40000001]
	v2 = v0 ^ rotr(v1,17)  [0x0000a001]
	v3 = v0 ^ rotr(v2,4)  [0x10000a01]
	v4 = v3 ^ rotr(v3,24)  [0x100a0b11]
	v5 = v2 ^ rotr(v4,7)  [0x2220b417]

	M(rotl)_hex = 0x29082a87  M(rotl)^{-1}_hex = 0x7868ab73
	M(rotr)_hex = 0xc2a82129  M(rotr)^{-1}_hex = 0x9daa2c3d
	minimum weight found (pair) = 12
	rotl: diff=12 lin=12 combined=12
	rotr: diff=12 lin=12 combined=12
	Operations(rotl): start_bit=0 steps=6
	v0 = (1 << 0)  [0x00000001]
	v1 = v0 ^ rotl(v0,2)  [0x00000005]
	v2 = v1 ^ rotl(v0,24)  [0x01000005]
	v3 = v2 ^ rotl(v1,4)  [0x01000055]
	v4 = v2 ^ rotl(v3,27)  [0xa9080007]
	v5 = v4 ^ rotl(v3,7)  [0x29082a87]
	Operations(rotr): start_bit=0 steps=6
	v0 = (1 << 0)  [0x00000001]
	v1 = v0 ^ rotr(v0,2)  [0x40000001]
	v2 = v1 ^ rotr(v0,24)  [0x40000101]
	v3 = v2 ^ rotr(v1,4)  [0x54000101]
	v4 = v2 ^ rotr(v3,27)  [0xc000212b]
	v5 = v4 ^ rotr(v3,7)  [0xc2a82129]

	DONE.
	Tested candidates = 5736
	Accepted candidates (printed) = 2
	Accepted candidates (total)   = 2
	Elapsed seconds = 1.35393
	Random ISD iterations executed (Prange screen) = 8896
	Random ISD iterations executed (Quality gate)  = 32768
	Random ISD iterations executed (Final confirm) = 16384
	quality_threshold_branch_number(B) = 12
	Quality gate = ON  (quality_trials=4096 exhaustive_input_weight_max=2 full_unit_scan=yes)

	--- Best candidate (post-search confirmation) ---
	M(rotl)_hex = 0x29082a87  M(rotl)^{-1}_hex = 0x7868ab73
	M(rotr)_hex = 0xc2a82129  M(rotr)^{-1}_hex = 0x9daa2c3d
	minimum weight found = 12


	--- Search-phase upper bounds (before final confirmation) ---
	Best(rotl) differential branch upper bound = 12
	Best(rotl) linear branch upper bound       = 12
	Best(rotl) combined branch upper bound     = 12
	Best(rotr) differential branch upper bound = 12
	Best(rotr) linear branch upper bound       = 12
	Best(rotr) combined branch upper bound     = 12
	Best(pair) combined branch upper bound     = 12

	--- Post-search confirmed upper bounds ---
	Confirmed(rotl) differential upper bound   = 12
	Confirmed(rotl) linear upper bound         = 12
	Confirmed(rotl) combined upper bound       = 12
	Confirmed(rotr) differential upper bound   = 12
	Confirmed(rotr) linear upper bound         = 12
	Confirmed(rotr) combined upper bound       = 12
	Confirmed(pair) combined upper bound       = 12

	Threshold check (confirmed combined >= 12) = PASS

	Quality: ACCEPTED (safe to forward to heuristic decomposer)
	Next step: run linear_box_heuristic_decomposer --verify <hex> for strict validation (do this for BOTH matrices).

*/

namespace TwilightDreamOfMagical::CustomSecurity
{
	//SymmetricEncryptionDecryption
	namespace SED::StreamCipher
	{
		/*
			Implementation of Custom Data Encrypting Worker and Decrypting Worker
			自定义加密和解密数据工作器的实现

			OaldresPuzzle-Cryptic (Type 1)
			隐秘的奥尔德雷斯之谜 (类型 1)
		*/

		//NeoAlzette is like the Alzette ARX-box of Sparkle algorithms, but not, just similar in structure.
		//NeoAlzette就像 Sparkle 算法的 Alzette ARX-box，但又不是，只是结构相似而已。
		//https://eprint.iacr.org/2019/1378.pdf
		
		class NeoAlzetteSubstitutionBox
		{
		public:
			inline void forward( std::uint32_t& a, std::uint32_t& b ) const noexcept
			{
				using std::rotl;
				using std::rotr;
				const auto&	  RC = ROUND_CONSTANTS;
				std::uint32_t A = a, B = b;

				// ── Subround 0 : NL → Diffuse → CD  (CD ← B) / 第 0 子轮：非线性→扩散→注入（CD ← B）
				B += ( rotl( A, 31 ) ^ rotl( A, 17 ) ^ RC[ 0 ] );  // ★ 唯一一次 变量↔变量 模加（非线性） / only variable-variable modular add (nonlinear)
				A -= RC[ 1 ];									   // ★ 常量模减：断链 / constant modular subtraction to break the chain
				// Linear cross-branch diffusion (reversible) / 线性交叉扩散（可逆）
				A ^= rotl( B, CROSS_XOR_ROT_R0 );
				B ^= rotl( A, CROSS_XOR_ROT_R1 );
				// Simplified CD injection with quadratic term / 简化 CD 注入并加入布尔二次项
				{
					auto [ C0, D0 ] = cd_injection_from_B( B, ( RC[ 2 ] | RC[ 3 ] ), RC[ 3 ] );
					A ^= ( rotl( C0, 24 ) ^ rotl( D0, 16 ) ^ RC[ 4 ] );
				}

				// ── Subround 1 : NL → Diffuse → CD  (CD ← A) / 第 1 子轮：非线性→扩散→注入（CD ← A）
				A += ( rotl( B, 31 ) ^ rotl( B, 17 ) ^ RC[ 5 ] );  // ★ 唯一一次 变量↔变量 模加（非线性） / only variable-variable modular add (nonlinear)
				B -= RC[ 6 ];									   // ★ 常量模减：断链 / constant modular subtraction to break the chain
				// Linear cross-branch diffusion (reversible) / 线性交叉扩散（可逆）
				B ^= rotl( A, CROSS_XOR_ROT_R0 );
				A ^= rotl( B, CROSS_XOR_ROT_R1 );
				// Simplified CD injection with quadratic term / 简化 CD 注入并加入布尔二次项
				{
					auto [ C1, D1 ] = cd_injection_from_A( A, ( RC[ 7 ] & RC[ 8 ] ), RC[ 8 ] );
					B ^= ( rotl( C1, 24 ) ^ rotl( D1, 16 ) ^ RC[ 9 ] );
				}

				// Light whitening (reversible) / 轻度白化（可逆）
				A ^= RC[ 10 ];
				B ^= RC[ 11 ];
				a = A;
				b = B;
			}

			inline void backward( std::uint32_t& a, std::uint32_t& b ) const noexcept
			{
				using std::rotl;
				using std::rotr;
				const auto&	  RC = ROUND_CONSTANTS;
				std::uint32_t A = a, B = b;

				// Undo whitening / 撤白化
				B ^= RC[ 11 ];
				A ^= RC[ 10 ];

				// Undo Subround 1 (reverse order) / 撤第 1 子轮（逆序）
				{
					auto [ C1, D1 ] = cd_injection_from_A( A, ( RC[ 7 ] & RC[ 8 ] ), RC[ 8 ] );
					B ^= ( rotl( C1, 24 ) ^ rotl( D1, 16 ) ^ RC[ 9 ] );
				}  // Undo CD injection (XOR is involutive) / 撤 CD 注入（XOR 自反）
				A ^= rotl( B, CROSS_XOR_ROT_R1 );
				B ^= rotl( A, CROSS_XOR_ROT_R0 );
				B += RC[ 6 ];									   // Undo constant subtraction / 撤常量模减
				A -= ( rotl( B, 31 ) ^ rotl( B, 17 ) ^ RC[ 5 ] );  // Undo variable add / 撤变量↔变量 模加

				// Undo Subround 0 (reverse order) / 撤第 0 子轮（逆序）
				{
					auto [ C0, D0 ] = cd_injection_from_B( B, ( RC[ 2 ] | RC[ 3 ] ), RC[ 3 ] );
					A ^= ( rotl( C0, 24 ) ^ rotl( D0, 16 ) ^ RC[ 4 ] );
				}
				B ^= rotl( A, CROSS_XOR_ROT_R1 );
				A ^= rotl( B, CROSS_XOR_ROT_R0 );
				A += RC[ 1 ];
				B -= ( rotl( A, 31 ) ^ rotl( A, 17 ) ^ RC[ 0 ] );

				a = A;
				b = B;
			}


		private:
			/*
				Cross Injection: simplified structure with linear layers + small XOR/ROT mixing,
				while adding a quadratic Boolean term to retain nonlinearity.
				交叉注入：将结构简化为线性层 + 小型 XOR/ROT 混合，但加入布尔二次项以保留非线性。

				Reason: purely linear injection can allow low-weight linear/differential trails to bypass it;
				quadratic terms (NOT-AND / NOT-OR) break linear subspaces and improve diffusion.
				原因：纯线性注入可能让低权重线性/差分路径绕过；布尔二次项（非与/非或）可打破线性子空间并增强扩散。
			*/

			// Cross-branch XOR/ROT mixing constants / 分支交叉 XOR/ROT 常量
			static constexpr int CROSS_XOR_ROT_R0 = 23;
			static constexpr int CROSS_XOR_ROT_R1 = 16;
			static constexpr int CROSS_XOR_ROT_SUM = ( ( CROSS_XOR_ROT_R0 + CROSS_XOR_ROT_R1 ) & 31 );
			static_assert( ( CROSS_XOR_ROT_SUM & 1 ) == 1, "CROSS_XOR_ROT_R0 + CROSS_XOR_ROT_R1 must be odd (coprime with 32)." );

			// Dynamic diffusion masks (rotation XOR family) / 动态扩散掩码（旋转异或族）
			inline std::uint32_t generate_dynamic_diffusion_mask0( std::uint32_t x ) const noexcept
			{
				using std::rotl;
				std::uint32_t Y = 0;
				std::uint32_t v0 = X;

				std::uint32_t v1 = v0 ^ rotl(v0,2);
				std::uint32_t v2 = v0 ^ rotl(v1,17);
				std::uint32_t v3 = v0 ^ rotl(v2,4);
				std::uint32_t v4 = v3 ^ rotl(v3,24);
				Y = v2 ^ rotl(v4,7);
				return Y;
			}

			inline std::uint32_t generate_dynamic_diffusion_mask1( std::uint32_t x ) const noexcept
			{
				using std::rotr;
				std::uint32_t Y = 0;
				std::uint32_t v0 = X;

				std::uint32_t v1 = v0 ^ rotr(v0,2);
				std::uint32_t v2 = v0 ^ rotr(v1,17);
				std::uint32_t v3 = v0 ^ rotr(v2,4);
				std::uint32_t v4 = v3 ^ rotr(v3,24);
				Y = v2 ^ rotr(v4,7);
				return Y;
			}

			// —— CD(B)：依赖 B 与常量，简化结构并引入布尔二次项 / depends on B+constants, simplified with quadratic term
			inline std::pair<std::uint32_t, std::uint32_t> cd_injection_from_B( std::uint32_t B, std::uint32_t rc0, std::uint32_t rc1 ) const noexcept
			{
				using std::rotl;
				using std::rotr;
				const auto&	  RC = ROUND_CONSTANTS;
				const std::uint32_t mask0 = generate_dynamic_diffusion_mask0( B );
				// Quadratic Boolean term (NOT-AND) for nonlinearity / 布尔二次项（非与）增加非线性
				std::uint32_t s_box_in_B = ( B ^ RC[ 2 ] ) ^ ( ~( B & mask0 ) );

				std::uint32_t c = B;
				std::uint32_t d = mask0 ^ rc0;
				std::uint32_t t = c ^ d;
				c ^= d ^ s_box_in_B;
				d ^= rotr( t, 16 ) ^ rc1;
				return { c, d };
			}

			// —— CD(A)：依赖 A 与常量，简化结构并引入布尔二次项 / depends on A+constants, simplified with quadratic term
			inline std::pair<std::uint32_t, std::uint32_t> cd_injection_from_A( std::uint32_t A, std::uint32_t rc0, std::uint32_t rc1 ) const noexcept
			{
				using std::rotl;
				using std::rotr;
				const auto&	  RC = ROUND_CONSTANTS;
				const std::uint32_t mask1 = generate_dynamic_diffusion_mask1( A );
				// Quadratic Boolean term (NOT-OR) for nonlinearity / 布尔二次项（非或）增加非线性
				std::uint32_t s_box_in_A = ( A ^ RC[ 7 ] ) ^ ( ~( A | mask1 ) );

				std::uint32_t c = A;
				std::uint32_t d = mask1 ^ rc0;
				std::uint32_t t = c ^ d;
				c ^= d ^ s_box_in_A;
				d ^= rotl( t, 16 ) ^ rc1;
				return { c, d };
			}

			// ==== NeoAlzette ARX-box constants / NeoAlzette ARX-box 常量 ====
			static constexpr std::array<std::uint32_t, 16> ROUND_CONSTANTS
			{ 
				//1,2,3,5,8,13,21,34,55,89,144,233,377,610,987,1597,2584,4181 (Fibonacci numbers)
				//Concatenation of Fibonacci numbers : 123581321345589144233377610987159725844181
				//Hexadecimal : 16b2c40bc117176a0f9a2598a1563aca6d5
				0x16B2C40B, 0xC117176A, 0x0F9A2598, 0xA1563ACA,

				/*
						Mathematical Constants - Millions of Digits
						http://www.numberworld.org/constants.html
				*/

				//π Pi (3.243f6a8885a308d313198a2e0370734)
				0x243F6A88, 0x85A308D3, 0x13198102, 0xE0370734,
				//φ Golden ratio (1.9e3779b97f4a7c15f39cc0605cedc834)
				0x9E3779B9, 0x7F4A7C15, 0xF39CC060, 0x5CEDC834,
				//e Natural Constant (2.b7e151628aed2a6abf7158809cf4f3c7)
				0xB7E15162, 0x8AED2A6A, 0xBF715880, 0x9CF4F3C7
			};
		};
		
		// 生成所有轮次密钥状态的方法
		void LittleOaldresPuzzle_Cryptic::GenerateAndStoreKeyStates(const Key128 key_128bit, const std::uint64_t number_once)
		{
			// 注意：这里不构造任何 XorConstantRotation 实例，只使用成员 prng / prng_second
			for (std::size_t round = 0; round < rounds; ++round)
			{
				KeyState& key_state = KeyStates[round];

				const std::uint64_t round_u64 = static_cast<std::uint64_t>(round);
				const std::uint64_t input_left  = number_once ^ round_u64;
				const std::uint64_t input_right = (number_once ^ (round_u64 << 1)) ^ (round_u64 >> 1);

				// 两个成员实例各吐 128-bit：合计 4×64
				const auto out_left  = prng.GenerateSubKey128(input_left);
				const auto out_right = prng_second.GenerateSubKey128(input_right);

				const std::uint64_t a = out_left.a;
				const std::uint64_t b = out_left.b;
				const std::uint64_t c = out_right.a;
				const std::uint64_t d = out_right.b;

				// round 参与“位置”，不引入额外常量
				const int rot_r = static_cast<int>(round_u64 & 63ULL);

				// 生成 128-bit subkey（对应你 Key128 的 first/second）
				key_state.subkey.first  = key_128bit.first  ^ a ^ std::rotl(c, rot_r);
				key_state.subkey.second = key_128bit.second ^ b ^ std::rotl(d, (rot_r + 1) & 63);

				// choice：只要 2-bit
				key_state.choice_function = (a ^ b ^ c ^ d) & 3ULL;

				// rot amounts：从同一轮输出切片（6+6）
				const std::uint64_t rot_pool =
					(a ^ b) ^ (c ^ d) ^
					std::rotl(key_state.subkey.first, 1) ^
					std::rotl(key_state.subkey.second, 3);

				key_state.bit_rotation_amount_a = ( rot_pool        ) & 63ULL;  // bits 0..5
				key_state.bit_rotation_amount_b = ((rot_pool >> 6 ) ) & 63ULL;  // bits 6..11
			}
		}


		static inline uint64_t pack64( uint32_t hi, uint32_t lo )
		{
			return ( uint64_t( hi ) << 32 ) | uint64_t( lo );
		}

		static inline void unpack64( uint64_t v, uint32_t& hi, uint32_t& lo )
		{
			hi = uint32_t( v >> 32 );
			lo = uint32_t( v );
		}

		// Return 0xFFFFFFFFFFFFFFFF iff x == y, else 0x0. Constant-time, branchless.
		inline uint64_t ConstantTimeEqualMask( uint64_t x, uint64_t y )
		{
			uint64_t q = x ^ y;
			q |= ( uint64_t )0 - q;	 // q | (-q)
			q >>= 63;				 // 0 if equal, 1 otherwise
			return q - 1;			 // 0xFFFFFFFFFFFFFFFF if equal, 0x0 otherwise
		}

		//Mix Linear Transform Layer (Forward)
		inline void LittleOaldresPuzzle_Cryptic::MixLinearTransform_Forward
		(
			uint64_t& lane0, uint64_t& lane1, const KeyState& current_key_state
		)
		{
			/*
				switch ( current_key_state.choice_function & 3ULL )
				{
				case 0:
					lane0 ^= current_key_state.subkey.first;
					lane1 ^= current_key_state.subkey.second;
					break;
				case 1:
					lane0 = (~lane0) ^ current_key_state.subkey.first;
					lane1 = (~lane1) ^ current_key_state.subkey.second;
					break;
				case 2:
					lane0 = std::rotl( lane0, current_key_state.bit_rotation_amount_b );
					lane1 = std::rotl( lane1, current_key_state.bit_rotation_amount_b );
					break;
				case 3:
					lane0 = std::rotr( lane0, current_key_state.bit_rotation_amount_b );
					lane1 = std::rotr( lane1, current_key_state.bit_rotation_amount_b );
					break;
				}
			*/

			const uint64_t& choice_function = current_key_state.choice_function;
			const uint64_t& subkey_first = current_key_state.subkey.first;
			const uint64_t& subkey_second = current_key_state.subkey.second;

			const uint64_t lane0_case0 = (lane0) ^ subkey_first;
			const uint64_t lane1_case0 = (lane1) ^ subkey_second;

			const uint64_t lane0_case1 = (~lane0) ^ subkey_first;
			const uint64_t lane1_case1 = (~lane1) ^ subkey_second;

			const uint64_t lane0_case2 = std::rotl(lane0, current_key_state.bit_rotation_amount_b & 63ULL);
			const uint64_t lane1_case2 = std::rotl(lane1, current_key_state.bit_rotation_amount_b & 63ULL);

			const uint64_t lane0_case3 = std::rotr(lane0, current_key_state.bit_rotation_amount_b & 63ULL);
			const uint64_t lane1_case3 = std::rotr(lane1, current_key_state.bit_rotation_amount_b & 63ULL);

			const uint64_t m0 = ConstantTimeEqualMask(choice_function & 3ULL, 0ULL);
			const uint64_t m1 = ConstantTimeEqualMask(choice_function & 3ULL, 1ULL);
			const uint64_t m2 = ConstantTimeEqualMask(choice_function & 3ULL, 2ULL);
			const uint64_t m3 = ConstantTimeEqualMask(choice_function & 3ULL, 3ULL);

			lane0 = (lane0_case0 & m0) | (lane0_case1 & m1) | (lane0_case2 & m2) | (lane0_case3 & m3);
			lane1 = (lane1_case0 & m0) | (lane1_case1 & m1) | (lane1_case2 & m2) | (lane1_case3 & m3);
		}

		// Mix Linear Transform Layer (Backward)
		inline void LittleOaldresPuzzle_Cryptic::MixLinearTransform_Backward
		(
			uint64_t& lane0, uint64_t& lane1, const KeyState& current_key_state
		)
		{
			/*
				switch ( current_key_state.choice_function & 3ULL )
				{
				case 0:
					lane0 ^= current_key_state.subkey.first;
					lane1 ^= current_key_state.subkey.second;
					break;
				case 1:
					lane0 = (~lane0) ^ current_key_state.subkey.first;
					lane1 = (~lane1) ^ current_key_state.subkey.second;
					break;
				case 2:
					lane0 = std::rotr( lane0, current_key_state.bit_rotation_amount_b );
					lane1 = std::rotr( lane1, current_key_state.bit_rotation_amount_b );
					break;
				case 3:
					lane0 = std::rotl( lane0, current_key_state.bit_rotation_amount_b );
					lane1 = std::rotl( lane1, current_key_state.bit_rotation_amount_b );
					break;
				}
			*/

			const uint64_t& choice_function = current_key_state.choice_function;
			const uint64_t& subkey_first = current_key_state.subkey.first;
			const uint64_t& subkey_second = current_key_state.subkey.second;

			const uint64_t lane0_case0 = (lane0) ^ subkey_first;
			const uint64_t lane1_case0 = (lane1) ^ subkey_second;

			const uint64_t lane0_case1 = (~lane0) ^ subkey_first;
			const uint64_t lane1_case1 = (~lane1) ^ subkey_second;

			const uint64_t lane0_case2 = std::rotr(lane0, current_key_state.bit_rotation_amount_b & 63ULL);
			const uint64_t lane1_case2 = std::rotr(lane1, current_key_state.bit_rotation_amount_b & 63ULL);

			const uint64_t lane0_case3 = std::rotl(lane0, current_key_state.bit_rotation_amount_b & 63ULL);
			const uint64_t lane1_case3 = std::rotl(lane1, current_key_state.bit_rotation_amount_b & 63ULL);

			const uint64_t m0 = ConstantTimeEqualMask(choice_function & 3ULL, 0ULL);
			const uint64_t m1 = ConstantTimeEqualMask(choice_function & 3ULL, 1ULL);
			const uint64_t m2 = ConstantTimeEqualMask(choice_function & 3ULL, 2ULL);
			const uint64_t m3 = ConstantTimeEqualMask(choice_function & 3ULL, 3ULL);

			lane0 = (lane0_case0 & m0) | (lane0_case1 & m1) | (lane0_case2 & m2) | (lane0_case3 & m3);
			lane1 = (lane1_case0 & m0) | (lane1_case1 & m1) | (lane1_case2 & m2) | (lane1_case3 & m3);
		}

		Block128 LittleOaldresPuzzle_Cryptic::EncryptionCoreFunction( const Block128 data, const Key128 key, const std::uint64_t number_once )
		{
			// 生成并缓存密钥状态（保持实现不变）
			GenerateAndStoreKeyStates( key, number_once );

			NeoAlzetteSubstitutionBox SubstitutionBox;

			// 128-bit 状态按两条 64-bit 车道存放
			uint64_t lane0 = data.first;   // (w0 || w1)
			uint64_t lane1 = data.second;  // (w2 || w3)

			// 拆成 4×32（注意：hi 在前、lo 在后）
			uint32_t w0, w1, w2, w3;

			for ( size_t round = 0; round < rounds; ++round )
			{
				const KeyState& current_key_state = KeyStates[ round ];

				unpack64( lane0, w0, w1 );
				unpack64( lane1, w2, w3 );

				/*
					NeoAlzette ARX Layer (Forward)
					—— 采用“对角配对”：(w0,w2) 与 (w1,w3)，跨车道混合
				*/
				SubstitutionBox.forward( w0, w2 );
				SubstitutionBox.forward( w1, w3 );

				// 重新打包回两条 64-bit 车道
				lane0 = pack64( w0, w1 );
				lane1 = pack64( w2, w3 );

				/* Keyed Switching Layer - MixLinearTransform (Forward) */
				MixLinearTransform_Forward(lane0, lane1, current_key_state);

				/* Keyed Switching Layer - Random Bit Tweak (Nonlinear)(Forward) */
				lane0 ^= ( uint64_t( 1 ) << current_key_state.bit_rotation_amount_a );
				lane1 ^= ( uint64_t( 1 ) << ( 63 - current_key_state.bit_rotation_amount_a ) );

				// Add Round Key
				const uint64_t k0 = key.first;
				const uint64_t k1 = key.second;

				lane0 += ( k0 ^ current_key_state.subkey.first );
				lane0 = std::rotr( lane0 ^ k0, 16 );
				lane0 ^= std::rotl( k0 + current_key_state.subkey.first, 48 );

				lane1 += ( k1 ^ current_key_state.subkey.second );
				lane1 = std::rotr( lane1 ^ k1, 16 );
				lane1 ^= std::rotl( k1 + current_key_state.subkey.second, 48 );
			}

			return Block128 { lane0, lane1 };
		}

		Block128 LittleOaldresPuzzle_Cryptic::DecryptionCoreFunction( const Block128 data, const Key128 key, const std::uint64_t number_once )
		{
			// 生成并缓存密钥状态（保持实现不变）
			GenerateAndStoreKeyStates( key, number_once );

			NeoAlzetteSubstitutionBox SubstitutionBox;

			uint64_t lane0 = data.first;
			uint64_t lane1 = data.second;

			// NeoAlzette ARX Layer (Backward)
			uint32_t w0, w1, w2, w3;

			for ( size_t round = rounds; round > 0; --round )
			{
				const KeyState& current_key_state = KeyStates[ round - 1 ];

				// Subtract Round key
				const uint64_t k0 = key.first;
				const uint64_t k1 = key.second;

				lane1 ^= std::rotl( k1 + current_key_state.subkey.second, 48 );
				lane1 = std::rotl( lane1, 16 ) ^ k1;
				lane1 -= ( k1 ^ current_key_state.subkey.second );

				lane0 ^= std::rotl( k0 + current_key_state.subkey.first, 48 );
				lane0 = std::rotl( lane0, 16 ) ^ k0;
				lane0 -= ( k0 ^ current_key_state.subkey.first );

				/* Keyed Switching Layer^{-1} - Random Bit Tweak (Nonlinear)(Backward) */
				lane0 ^= ( uint64_t( 1 ) << current_key_state.bit_rotation_amount_a );
				lane1 ^= ( uint64_t( 1 ) << ( 63 - current_key_state.bit_rotation_amount_a ) );

				/* Keyed Switching Layer^{-1} - MixLinearTransform (Backward) */
				MixLinearTransform_Backward(lane0, lane1, current_key_state);

				unpack64( lane0, w0, w1 );
				unpack64( lane1, w2, w3 );

				SubstitutionBox.backward( w1, w3 );
				SubstitutionBox.backward( w0, w2 );

				lane0 = pack64( w0, w1 );
				lane1 = pack64( w2, w3 );
			}

			return Block128 { lane0, lane1 };
		}
	}  // TwilightDreamOfMagical
	
}