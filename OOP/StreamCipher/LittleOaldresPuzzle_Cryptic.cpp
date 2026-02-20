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
		
		/**
		 * NeoAlzette V6.5 Second Schedule - ARX-box / ARX S-box implementation
		 *
		 * This class is written in the older NeoAlzetteSubstitutionBox style:
		 * - forward/backward are instance methods;
		 * - the whole ARX-box is kept in one class body;
		 * - C++20 std::rotl/std::rotr and inline constexpr constants are used directly;
		 * - the V6.5 second schedule is preserved exactly from NeoAlzetteCore.
		 *
		 * Important design note:
		 * The first V6.5 schedule is intentionally abandoned here.  The second schedule
		 * moves the injection windows so the solver cannot cheaply kill the injection
		 * input branch around the nonlinear layer and reactivate it only after the
		 * injection layer has been bypassed.
		 */
		class NeoAlzetteSubstitutionBox
		{
		public:
			constexpr void forward( std::uint32_t& a, std::uint32_t& b ) const noexcept
			{
				const auto& RC = ROUND_CONSTANTS;

				std::uint32_t A = a;
				std::uint32_t B = b;

				std::uint32_t CD0{};
				std::uint32_t CD1{};
				std::uint32_t CD2{};
				std::uint32_t CD3{};

				// ========================================================================
				// Subround 0 : Constant subtract -> B-to-A injection -> ARX add -> bridge
				// 第 0 子轮：常量模减 -> B 到 A 的非线性注入 -> ARX 模加 -> 交叉桥接
				// ========================================================================

				// Step 0.1: fixed-public constant subtraction on B
				// 步骤 0.1：对 B 执行固定公开常量模减。
				//
				// This is hardcore.
				// Constant addition/subtraction inside an ARX-style trail is still costly to model precisely.
				// Existing differential treatments are possible, but practical low-complexity and broadly reusable
				// linear/correlation-oriented models are still awkward for this kind of construction.
				B -= RC[ 1 ];

				// Step 0.2: B-to-A nonlinear injection, before the first cross-branch bridge.
				// 步骤 0.2：B -> A 非线性注入，放在第一组交叉桥接之前。
				//
				// Scheduling point:
				// This is the V6.5 second schedule.  The injection consumes the already
				// constant-subtracted B state, and its C/D derivatives feed the following
				// modular addition.  This prevents the old zero-injection window where the
				// solver could keep the injection source inactive and reactivate it later.
				{
					const auto [ C0, D0 ] = cd_injection_from_B( B );

					CD0 = ( C0 << 2 ) ^ ( D0 >> 2 );
					CD1 = ( C0 >> 5 ) ^ ( D0 << 5 );

					A ^= std::rotl( B, 24 )
					  ^  std::rotl( C0, 16 )
					  ^  std::rotl( B, 8 );
				}

				// Step 0.3: CD-driven modular addition into A
				// 步骤 0.3：由注入层派生的 CD0/CD1 驱动 A 侧模加。
				A += ( std::rotl( CD0, 31 ) ^ std::rotl( CD1, 17 ) ^ RC[ 0 ] );

				// Step 0.4: cross-branch bridge, line 0
				// 步骤 0.4：交叉桥接第 0 行，把 A 的状态压回 B。
				B ^= std::rotl( A, CROSS_XOR_ROT_R0 ) ^ RC[ 4 ];

				// Step 0.5: cross-branch bridge, line 1
				// 步骤 0.5：交叉桥接第 1 行，使后续 A-to-B 注入消耗桥接后的 A。
				//
				// IMPORTANT:
				// This bridge must happen before the A-to-B nonlinear injection.
				A ^= std::rotl( B, CROSS_XOR_ROT_R1 );

				// ========================================================================
				// Subround 1 : Constant subtract -> A-to-B injection -> ARX add -> output bridge
				// 第 1 子轮：常量模减 -> A 到 B 的非线性注入 -> ARX 模加 -> 输出桥接
				// ========================================================================

				// Step 1.1: fixed-public constant subtraction on A
				// 步骤 1.1：对 A 执行固定公开常量模减。
				//
				// This is hardcore.
				// Constant addition/subtraction inside an ARX-style trail is still costly to model precisely.
				// Existing differential treatments are possible, but practical low-complexity and broadly reusable
				// linear/correlation-oriented models are still awkward for this kind of construction.
				A -= RC[ 6 ];

				// Step 1.2: A-to-B nonlinear injection
				// 步骤 1.2：A -> B 非线性注入。
				//
				// The A branch has already passed through both bridge lines, so the injector
				// no longer sees the same clean window that the abandoned first V6.5 schedule exposed.
				{
					const auto [ C1, D1 ] = cd_injection_from_A( A );

					CD2 = ( C1 >> 3 ) ^ ( D1 << 3 );
					CD3 = ( C1 << 1 ) ^ ( D1 >> 1 );

					B ^= std::rotr( A, 24 )
					  ^  std::rotr( D1, 16 )
					  ^  std::rotr( A, 8 );
				}

				// Step 1.3: CD-driven modular addition into B
				// 步骤 1.3：由注入层派生的 CD2/CD3 驱动 B 侧模加。
				B += ( CD2 ^ CD3 ^ RC[ 5 ] );

				// Step 1.4: final asymmetric XOR/ROT bridge
				// 步骤 1.4：最终非对称 XOR/ROT 桥接。
				A ^= std::rotl( B, 5 ) ^ RC[ 9 ];
				B ^= std::rotl( A, 25 );

				// Final light whitening (reversible)
				// 最终轻量白化（可逆）。
				A ^= RC[ 10 ];
				B ^= RC[ 11 ];

				a = A;
				b = B;
			}

			constexpr void backward( std::uint32_t& a, std::uint32_t& b ) const noexcept
			{
				const auto& RC = ROUND_CONSTANTS;

				std::uint32_t A = a;
				std::uint32_t B = b;

				// ========================================================================
				// Undo final whitening
				// 撤销最终轻量白化
				// ========================================================================
				B ^= RC[ 11 ];
				A ^= RC[ 10 ];

				// ========================================================================
				// Undo Subround 1
				// 撤销第 1 子轮
				// ========================================================================

				// Reverse Step 1.4.2: undo final B update
				// 逆步骤 1.4.2：撤销最终 B 侧桥接。
				B ^= std::rotl( A, 25 );

				// Reverse Step 1.4.1: undo final A update
				// 逆步骤 1.4.1：撤销最终 A 侧桥接。
				//
				// In forward direction this update used the post-addition B state,
				// so in backward direction it must be undone before recovering B.
				A ^= std::rotl( B, 5 ) ^ RC[ 9 ];

				// Reverse Step 1.3 + 1.2: undo B modular addition, then undo A-to-B injection.
				// 逆步骤 1.3 + 1.2：先撤销 B 侧模加，再撤销 A -> B 注入。
				{
					const auto [ C1, D1 ] = cd_injection_from_A( A );

					const std::uint32_t CD2 = ( C1 >> 3 ) ^ ( D1 << 3 );
					const std::uint32_t CD3 = ( C1 << 1 ) ^ ( D1 >> 1 );

					B -= ( CD2 ^ CD3 ^ RC[ 5 ] );

					B ^= std::rotr( A, 24 )
					  ^  std::rotr( D1, 16 )
					  ^  std::rotr( A, 8 );
				}

				// Reverse Step 1.1: undo fixed-public constant subtraction on A
				// 逆步骤 1.1：撤销 A 侧固定公开常量模减。
				//
				// This is hardcore.
				// Constant addition/subtraction inside an ARX-style trail is still costly to model precisely.
				// Existing differential treatments are possible, but practical low-complexity and broadly reusable
				// linear/correlation-oriented models are still awkward for this kind of construction.
				A += RC[ 6 ];

				// ========================================================================
				// Undo Subround 0
				// 撤销第 0 子轮
				// ========================================================================

				// Reverse Step 0.5: undo cross-branch bridge, line 1
				// 逆步骤 0.5：撤销交叉桥接第 1 行。
				A ^= std::rotl( B, CROSS_XOR_ROT_R1 );

				// Reverse Step 0.4: undo cross-branch bridge, line 0
				// 逆步骤 0.4：撤销交叉桥接第 0 行。
				//
				// This restores the B state consumed by the original B-to-A injection.
				B ^= std::rotl( A, CROSS_XOR_ROT_R0 ) ^ RC[ 4 ];

				// Reverse Step 0.3 + 0.2: undo A modular addition, then undo B-to-A injection.
				// 逆步骤 0.3 + 0.2：先撤销 A 侧模加，再撤销 B -> A 注入。
				{
					const auto [ C0, D0 ] = cd_injection_from_B( B );

					const std::uint32_t CD0 = ( C0 << 2 ) ^ ( D0 >> 2 );
					const std::uint32_t CD1 = ( C0 >> 5 ) ^ ( D0 << 5 );

					A -= ( std::rotl( CD0, 31 )
						^  std::rotl( CD1, 17 )
						^  RC[ 0 ] );

					A ^= std::rotl( B, 24 )
					  ^  std::rotl( C0, 16 )
					  ^  std::rotl( B, 8 );
				}

				// Reverse Step 0.1: undo fixed-public constant subtraction on B
				// 逆步骤 0.1：撤销 B 侧固定公开常量模减。
				//
				// This is hardcore.
				// Constant addition/subtraction inside an ARX-style trail is still costly to model precisely.
				// Existing differential treatments are possible, but practical low-complexity and broadly reusable
				// linear/correlation-oriented models are still awkward for this kind of construction.
				B += RC[ 1 ];

				a = A;
				b = B;
			}

		private:
			// ==== NeoAlzette ARX-box constants / NeoAlzette ARX-box 常量 ====
			static inline constexpr auto ROUND_CONSTANTS = std::to_array<std::uint32_t>
			({
				// 1,2,3,5,8,13,21,34,55,89,144,233,377,610,987,1597,2584,4181 (Fibonacci numbers)
				// Concatenation of Fibonacci numbers : 123581321345589144233377610987159725844181
				// Hexadecimal : 16b2c40bc117176a0f9a2598a1563aca6d5
				0x16B2C40B, 0xC117176A, 0x0F9A2598, 0xA1563ACA,

				/*
					Mathematical Constants - Millions of Digits
					http://www.numberworld.org/constants.html
				*/

				// π Pi (3.243f6a8885a308d313198a2e03707344)
				0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
				// φ Golden ratio (1.9e3779b97f4a7c15f39cc0605cedc834)
				0x9E3779B9, 0x7F4A7C15, 0xF39CC060, 0x5CEDC834,
				// e Natural Constant (2.b7e151628aed2a6abf7158809cf4f3c7)
				0xB7E15162, 0x8AED2A6A, 0xBF715880, 0x9CF4F3C7
			});

			// ========================================================================
			// NeoAlzette Cross-branch XOR/ROT bridge constants
			//
			// Ordered bridge assignment:
			//   R0 = 22, R1 = 13
			//
			// Structural rule:
			//   gcd(((R0 + R1) mod 32), 32) == 1
			//
			// Since 32 = 2^5, this is equivalent to requiring the bridge sum to be odd.
			// For the current pair:
			//   (22 + 13) mod 32 = 3, gcd(3, 32) = 1.
			//
			// Bottom line:
			// do not "clean up", "simplify", or "make symmetric" these constants unless
			// the full differential / linear / trace tooling is rerun and checked again.
			// ========================================================================
			static constexpr int CROSS_XOR_ROT_R0 = 22;
			static constexpr int CROSS_XOR_ROT_R1 = 13;
			static constexpr int CROSS_XOR_ROT_SUM = ( ( CROSS_XOR_ROT_R0 + CROSS_XOR_ROT_R1 ) & 31 );
			static_assert( ( CROSS_XOR_ROT_SUM & 1 ) == 1, "CROSS_XOR_ROT_R0 + CROSS_XOR_ROT_R1 must be odd (coprime with 32) to avoid large rotation fixed-point subspaces." );

			// ========================================================================
			// Dynamic diffusion masks (rotation XOR family)
			//
			// These are the V6.5 second-version linear diffusion layers carried over
			// from NeoAlzetteCore.  The selected pair was screened by the linear-box-search
			// tooling with confirmed differential/linear combined branch upper bound 12.
			// ========================================================================
			static constexpr std::uint32_t generate_dynamic_diffusion_mask0( std::uint32_t x ) noexcept
			{
				const std::uint32_t v0 = x;
				const std::uint32_t v1 = v0 ^ std::rotl( v0, 2 );
				const std::uint32_t v2 = v0 ^ std::rotl( v1, 17 );
				const std::uint32_t v3 = v0 ^ std::rotl( v2, 4 );
				const std::uint32_t v4 = v3 ^ std::rotl( v3, 24 );
				return v2 ^ std::rotl( v4, 7 );
			}

			static constexpr std::uint32_t generate_dynamic_diffusion_mask1( std::uint32_t x ) noexcept
			{
				const std::uint32_t v0 = x;
				const std::uint32_t v1 = v0 ^ std::rotr( v0, 2 );
				const std::uint32_t v2 = v0 ^ std::rotr( v1, 17 );
				const std::uint32_t v3 = v0 ^ std::rotr( v2, 4 );
				const std::uint32_t v4 = v3 ^ std::rotr( v3, 24 );
				return v2 ^ std::rotr( v4, 7 );
			}

			// ========================================================================
			// Precomputed constant views for the injection layer
			//
			// C++20 note:
			// These are real inline constexpr data members, not accessor functions.
			// For the two mask constants we use consteval lambdas, because class-scope
			// data-member initializers cannot call a static member function before the
			// class definition is complete.  The generated constants are still compile-time
			// values and do not introduce runtime storage or runtime initialization.
			// ========================================================================
			static inline constexpr std::uint32_t RC7_R24  = std::rotr( ROUND_CONSTANTS[ 7 ], 24 );
			static inline constexpr std::uint32_t RC8_R24  = std::rotr( ROUND_CONSTANTS[ 8 ], 24 );
			static inline constexpr std::uint32_t RC13_R24 = std::rotr( ROUND_CONSTANTS[ 13 ], 24 );
			static inline constexpr std::uint32_t RC2_L8   = std::rotl( ROUND_CONSTANTS[ 2 ], 8 );
			static inline constexpr std::uint32_t RC3_L8   = std::rotl( ROUND_CONSTANTS[ 3 ], 8 );
			static inline constexpr std::uint32_t RC12_L8  = std::rotl( ROUND_CONSTANTS[ 12 ], 8 );

			static inline constexpr std::uint32_t MASK0_RC7 = []() consteval
			{
				const std::uint32_t v0 = ROUND_CONSTANTS[ 7 ];
				const std::uint32_t v1 = v0 ^ std::rotl( v0, 2 );
				const std::uint32_t v2 = v0 ^ std::rotl( v1, 17 );
				const std::uint32_t v3 = v0 ^ std::rotl( v2, 4 );
				const std::uint32_t v4 = v3 ^ std::rotl( v3, 24 );
				return v2 ^ std::rotl( v4, 7 );
			}();

			static inline constexpr std::uint32_t MASK1_RC2 = []() consteval
			{
				const std::uint32_t v0 = ROUND_CONSTANTS[ 2 ];
				const std::uint32_t v1 = v0 ^ std::rotr( v0, 2 );
				const std::uint32_t v2 = v0 ^ std::rotr( v1, 17 );
				const std::uint32_t v3 = v0 ^ std::rotr( v2, 4 );
				const std::uint32_t v4 = v3 ^ std::rotr( v3, 24 );
				return v2 ^ std::rotr( v4, 7 );
			}();

			// ============================================================================
			// Cross-branch injection (value domain with constants)
			//
			// Design rationale:
			// - add a second nonlinearity source beyond the carry/borrow effects of the main ARX path;
			// - keep the injector lightweight;
			// - preserve reversibility at the round level via cross-branch XOR-style injection,
			//   so the local function itself does not need to be invertible.
			// ============================================================================

			// Feistel-like nonlinear branch injection: B -> A
			// Local nonlinear mixing function from B into A (PRF-like role, not a formal PRF claim)
			[[nodiscard]] static constexpr std::pair<std::uint32_t, std::uint32_t> cd_injection_from_B( std::uint32_t B ) noexcept
			{
				const std::uint32_t companion0 = std::rotr( B, 24 );

				const std::uint32_t mask = generate_dynamic_diffusion_mask0( B );
				const std::uint32_t companion_mask = std::rotr( mask, 24 ) ^ MASK0_RC7;
				const std::uint32_t mask_r1 = std::rotr( mask, 5 );

				const std::uint32_t x0 = companion0 ^ mask;
				const std::uint32_t x1 = B ^ mask;
				const std::uint32_t view = companion0 ^ companion_mask;
				const std::uint32_t bridge_state = std::rotr( B, 19 ) ^ ( B << 9 );

				const std::uint32_t q_state_na = RC7_R24 ^ ( ~( B & mask ) );
				const std::uint32_t q_comp_no  = companion0 ^ B ^ RC8_R24 ^ ( ~( companion0 | mask_r1 ) );
				const std::uint32_t q_bridge   = bridge_state ^ B ^ RC13_R24 ^ ( ~( bridge_state & companion_mask ) );
				const std::uint32_t q_shared   = q_state_na ^ q_comp_no;

				const std::uint32_t cross_q = ( B ^ mask_r1 ) & std::rotr( mask ^ companion_mask, 7 );
				const std::uint32_t anti_q  = ( ( x1 >> 3 ) ^ ( view >> 5 ) ^ mask_r1 ) & ( B ^ std::rotr( x0, 11 ) );

				const std::uint32_t c = q_shared ^ std::rotr( q_comp_no, 5 ) ^ std::rotr( q_comp_no, 11 ) ^ anti_q;
				const std::uint32_t d = q_shared ^ std::rotr( q_state_na, 5 ) ^ std::rotr( q_bridge, 13 ) ^ cross_q ^ anti_q;
				return { c, d };
			}

			// Feistel-like nonlinear branch injection: A -> B
			// Local nonlinear mixing function from A into B (PRF-like role, not a formal PRF claim)
			[[nodiscard]] static constexpr std::pair<std::uint32_t, std::uint32_t> cd_injection_from_A( std::uint32_t A ) noexcept
			{
				const std::uint32_t companion0 = std::rotl( A, 8 );

				const std::uint32_t mask = generate_dynamic_diffusion_mask1( A );
				const std::uint32_t companion_mask = std::rotl( mask, 8 ) ^ MASK1_RC2;
				const std::uint32_t mask_r1 = std::rotr( mask, 5 );

				const std::uint32_t x0 = companion0 ^ mask;
				const std::uint32_t x1 = A ^ mask;
				const std::uint32_t view = companion0 ^ companion_mask;
				const std::uint32_t bridge_state = std::rotl( A, 19 ) ^ ( A >> 9 );

				const std::uint32_t q_state_no = RC2_L8 ^ ( ~( A | mask ) );
				const std::uint32_t q_comp_na  = companion0 ^ A ^ RC3_L8 ^ ( ~( companion0 & mask_r1 ) );
				const std::uint32_t q_bridge   = bridge_state ^ A ^ RC12_L8 ^ ( ~( bridge_state | companion_mask ) );
				const std::uint32_t q_shared   = q_state_no ^ q_comp_na;

				const std::uint32_t cross_q = ( A ^ mask_r1 ) & std::rotl( mask ^ companion_mask, 13 );
				const std::uint32_t anti_q  = ( ( x1 << 3 ) ^ ( view << 5 ) ^ mask_r1 ) | ( A ^ std::rotl( x0, 11 ) );

				const std::uint32_t c = q_shared ^ std::rotl( q_comp_na, 5 ) ^ std::rotl( q_comp_na, 11 ) ^ anti_q;
				const std::uint32_t d = q_shared ^ std::rotl( q_state_no, 5 ) ^ std::rotl( q_bridge, 13 ) ^ cross_q ^ anti_q;
				return { c, d };
			}
		};
		
		// ---------------------------------------------------------------------
		// Generate and cache per-round key states
		// ---------------------------------------------------------------------
		// This function derives round-dependent key material from two persistent
		// XorConstantRotation member instances: `prng` and `prng_second`.
		//
		// Important usage semantics:
		// - No local XCR instances are created here.
		// - Both generators are stateful member objects and are consumed continuously
		//   across rounds inside this function.
		// - Therefore, round-to-round variation comes from BOTH:
		//      (1) the explicit per-round inputs derived from `number_once` and `round`,
		//      (2) the continuously evolving internal states of the two XCR instances.
		//
		// Current XCR API behavior matters here:
		// - `GenerateSubKey128(input)` mutates the XCR internal state, returns
		//   a 128-bit view {x ^ y, z ^ w}, and explicitly advances that XCR's
		//   public `counter`.
		// - So the main source of progression here is BOTH:
		//      (1) state evolution,
		//      (2) explicit counter stepping on every public call.
		//
		// Construction overview:
		// - Left generator input : input_left  = number_once ^ round
		// - Right generator input: input_right = (number_once ^ (round << 1)) ^ (round >> 1)
		// - Each generator emits 128 bits, producing four 64-bit words total: a,b,c,d.
		// - These words are folded into:
		//      * round subkey (first / second lane),
		//      * 2-bit choice_function,
		//      * two rotation amounts.
		//
		// No extra ad-hoc round constants are injected here;
		// round only affects position / routing.
		void LittleOaldresPuzzle_Cryptic::GenerateAndStoreKeyStates(const Key128 key_128bit, const std::uint64_t number_once)
		{
			// 注意：这里不构造任何 XorConstantRotation 实例，只使用成员 prng / prng_second
			for (std::uint64_t round = 0; round < rounds; ++round)
			{
				KeyState& key_state = KeyStates[round];

				const std::uint64_t input_left  = number_once ^ round;
				const std::uint64_t input_right = (number_once ^ (round << 1)) ^ (round >> 1);

				// 两个成员实例各吐 128-bit：合计 4×64
				const auto out_left  = prng.GenerateSubKey128(input_left);
				const auto out_right = prng_second.GenerateSubKey128(input_right);

				const std::uint64_t a = out_left.a;
				const std::uint64_t b = out_left.b;
				const std::uint64_t c = out_right.a;
				const std::uint64_t d = out_right.b;

				// ---------------------------------------------------------------------
				// ARX-shaped subkey folding
				//
				// IMPORTANT:
				// We intentionally use the form
				//   (key +/- xcr_word) ^ rotated_xcr_word
				// and NOT
				//   key +/- (xcr_word ^ rotated_xcr_word).
				//
				// Reason:
				// - The chosen form keeps the modular add/sub core isolated first,
				//   then applies a rotated-XOR outer perturbation.
				// - This preserves a cleaner modeling boundary for differential / linear /
				//   dependency-bit / state-machine style analysis.
				// - The rejected alternative would push the mixed XCR value directly into the
				//   carry/borrow chain, entangling XCR-side structure with the modular core
				//   and forcing a broader rework of the subkey model.
				//
				// In short:
				//   chosen   : ARX core first, XOR shell later
				//   rejected : XCR mixture first, carry entanglement later
				// ---------------------------------------------------------------------
				// round 参与“位置”，不引入额外常量
				// 生成 128-bit subkey（Key128 的 first/second）
				key_state.subkey.first  = (key_128bit.first  + a) ^ std::rotr(c, static_cast<int>(round & 63ULL));
				key_state.subkey.second = (key_128bit.second - b) ^ std::rotr(d, static_cast<int>((round + 1) & 63ULL));

				// choice：只要 2-bit
				key_state.choice_function = (a ^ b ^ c ^ d) & 3ULL;

				// rotation amounts：从同一轮输出切片（6+6）
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

				// Add Round Key
				lane0 ^= current_key_state.subkey.first;
				lane1 ^= current_key_state.subkey.second;

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

				// Subtract Round key
				lane0 ^= current_key_state.subkey.first;
				lane1 ^= current_key_state.subkey.second;
			}

			return Block128 { lane0, lane1 };
		}
	}  // TwilightDreamOfMagical
	
}