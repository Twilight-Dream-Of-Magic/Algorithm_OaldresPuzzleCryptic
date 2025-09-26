#include "LittleOaldresPuzzle_Cryptic.h"

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

		#if 0

		class NeoAlzetteSubstitutionBox
		{
		public:
			// 公开接口：就这两个
			inline void forward( std::uint32_t& a, std::uint32_t& b ) const noexcept
			{
				using std::rotl;
				using std::rotr;

				// 视作 64-bit，先做 16-bit 交错拼接
				std::uint32_t A1 = ( ( a & 0x0000FFFFu ) << 16 ) | ( ( b & 0xFFFF0000u ) >> 16 );
				std::uint32_t B1 = ( ( b & 0x0000FFFFu ) << 16 ) | ( ( a & 0xFFFF0000u ) >> 16 );

				/*
				
				Alzette 算法原来的思路
				先用旧值做一次 “模加法和模减法→产生非线性”
				再把这份已经非线性的值，经过旋转/XOR操作做一个迷你线性层，扩散到另一半的值
				最后再用常量对被改过的半边（已经非线性的值）做一次"键控扰动"
				
				*/
				
				// Post(A1, B1)
				A1 += (ROUND_CONSTANT[0] ^ rotr(B1, 17));
				B1 ^= ROUND_CONSTANT[1] ^ rotl(A1, 13);
				A1 ^= ROUND_CONSTANT[2] ^ rotr(B1, 31);
				B1 ^= ROUND_CONSTANT[3];

				// 线性层 L1/L2（可逆）
				std::uint32_t A2 = l1_forward( A1 );
				std::uint32_t B2 = l2_forward( B1 );

				// Post(A2, B2)
				B2 ^= ROUND_CONSTANT[4] - rotl(A2, 24);
				A2 ^= ROUND_CONSTANT[5] ^ rotr(B2, 16);
				B2 ^= ROUND_CONSTANT[6] ^ rotl(A2, 31);
				A2 ^= B2 ^ ROUND_CONSTANT[7];

				// 拆成 8 个字节：0..3 来自 a2，4..7 来自 b2
				std::uint8_t bytes[ 8 ] = {
					static_cast<std::uint8_t>( A2 & 0xFFu ), static_cast<std::uint8_t>( ( A2 >> 8 ) & 0xFFu ), static_cast<std::uint8_t>( ( A2 >> 16 ) & 0xFFu ), static_cast<std::uint8_t>( ( A2 >> 24 ) & 0xFFu ), 
					static_cast<std::uint8_t>( B2 & 0xFFu ), static_cast<std::uint8_t>( ( B2 >> 8 ) & 0xFFu ), static_cast<std::uint8_t>( ( B2 >> 16 ) & 0xFFu ), static_cast<std::uint8_t>( ( B2 >> 24 ) & 0xFFu ),
				};

				// 大替换S函数 = s2(s1(pair(byte,byte)))
				// === 小 s：S1 四对不相交 ===
				forward0_8bit( bytes[ 0 ], bytes[ 1 ], rc8( 8, 1 ) );
				forward1_8bit( bytes[ 2 ], bytes[ 3 ], rc8( 9, 2 ) );
				forward2_8bit( bytes[ 4 ], bytes[ 5 ], rc8( 10, 3 ) );
				forward3_8bit( bytes[ 6 ], bytes[ 7 ], rc8( 11, 4 ) );

				// === 小 s：S2 交叉四对（确保 0..7 全部“走一遍”）===
				forward4_8bit( bytes[ 0 ], bytes[ 2 ], rc8( 12, 5 ) );
				forward5_8bit( bytes[ 1 ], bytes[ 3 ], rc8( 13, 6 ) );
				forward6_8bit( bytes[ 4 ], bytes[ 6 ], rc8( 14, 7 ) );
				forward7_8bit( bytes[ 5 ], bytes[ 7 ], rc8( 15, 8 ) );

				// 重组：偶位 → a，奇位 → b
				a = ( std::uint32_t )bytes[ 0 ] | ( ( std::uint32_t )bytes[ 2 ] << 8 ) | ( ( std::uint32_t )bytes[ 4 ] << 16 ) | ( ( std::uint32_t )bytes[ 6 ] << 24 );

				b = ( std::uint32_t )bytes[ 1 ] | ( ( std::uint32_t )bytes[ 3 ] << 8 ) | ( ( std::uint32_t )bytes[ 5 ] << 16 ) | ( ( std::uint32_t )bytes[ 7 ] << 24 );
			}

			inline void backward( std::uint32_t& a, std::uint32_t& b ) const noexcept
			{
				using std::rotl;
				using std::rotr;

				// 把 a(偶位)、b(奇位)还原成 8 个字节
				std::uint8_t bytes[ 8 ] = {
					static_cast<std::uint8_t>( a & 0xFFu ),			   // 0
					static_cast<std::uint8_t>( b & 0xFFu ),			   // 1
					static_cast<std::uint8_t>( ( a >> 8 ) & 0xFFu ),   // 2
					static_cast<std::uint8_t>( ( b >> 8 ) & 0xFFu ),   // 3
					static_cast<std::uint8_t>( ( a >> 16 ) & 0xFFu ),  // 4
					static_cast<std::uint8_t>( ( b >> 16 ) & 0xFFu ),  // 5
					static_cast<std::uint8_t>( ( a >> 24 ) & 0xFFu ),  // 6
					static_cast<std::uint8_t>( ( b >> 24 ) & 0xFFu ),  // 7
				};

				// 大替换S^{-1}函数 = s1(s2(pair(byte,byte)))
				// === 先还原 S2（反序）===
				backward7_8bit( bytes[ 5 ], bytes[ 7 ], rc8( 15, 8 ) );
				backward6_8bit( bytes[ 4 ], bytes[ 6 ], rc8( 14, 7 ) );
				backward5_8bit( bytes[ 1 ], bytes[ 3 ], rc8( 13, 6 ) );
				backward4_8bit( bytes[ 0 ], bytes[ 2 ], rc8( 12, 5 ) );

				// === 再还原 S1（反序）===
				backward3_8bit( bytes[ 6 ], bytes[ 7 ], rc8( 11, 4 ) );
				backward2_8bit( bytes[ 4 ], bytes[ 5 ], rc8( 10, 3 ) );
				backward1_8bit( bytes[ 2 ], bytes[ 3 ], rc8( 9, 2 ) );
				backward0_8bit( bytes[ 0 ], bytes[ 1 ], rc8( 8, 1 ) );

				// 组回 A2/B2
				std::uint32_t A2 = ( std::uint32_t )bytes[ 0 ] | ( ( std::uint32_t )bytes[ 1 ] << 8 ) | ( ( std::uint32_t )bytes[ 2 ] << 16 ) | ( ( std::uint32_t )bytes[ 3 ] << 24 );
				std::uint32_t B2 = ( std::uint32_t )bytes[ 4 ] | ( ( std::uint32_t )bytes[ 5 ] << 8 ) | ( ( std::uint32_t )bytes[ 6 ] << 16 ) | ( ( std::uint32_t )bytes[ 7 ] << 24 );

				// Undo Post(A2, B2)
				A2 ^= (B2 ^ ROUND_CONSTANT[7]);
				B2 ^= (ROUND_CONSTANT[6] ^ rotl(A2, 31));
				A2 ^= (ROUND_CONSTANT[5] ^ rotr(B2, 16));
				B2 ^= (ROUND_CONSTANT[4] - rotl(A2, 24));

				// 线性层逆 A1/B1
				std::uint32_t A1 = l1_backward( A2 );
				std::uint32_t B1 = l2_backward( B2 );

				// Undo Post(A1, B1)
				B1 ^= ROUND_CONSTANT[3];
				A1 ^= (ROUND_CONSTANT[2] ^ rotr(B1, 31));
				B1 ^= (ROUND_CONSTANT[1] ^ rotl(A1, 13));
				A1 -= (ROUND_CONSTANT[0] ^ rotr(B1, 17));

				// 复原最初的 16-bit 交错
				std::uint32_t a_low16 = ( A1 >> 16 ) & 0x0000FFFFu;
				std::uint32_t a_high16 = ( B1 << 16 ) & 0xFFFF0000u;
				std::uint32_t b_low16 = ( B1 >> 16 ) & 0x0000FFFFu;
				std::uint32_t b_high16 = ( A1 << 16 ) & 0xFFFF0000u;
				a = a_high16 | a_low16;
				b = b_high16 | b_low16;
			}

		private:

			// ==== NeoAlzette ARX-box 常量 ====
			inline constexpr std::array<std::uint32_t, 16> ROUND_CONSTANT
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

			// 取 32-bit 常量的第 lane 个字节（lane=0..3）
			constexpr std::uint8_t rc8( std::size_t i, unsigned lane ) noexcept
			{
				return static_cast<std::uint8_t>( ( ROUND_CONSTANT[ i & 15 ] >> ( 8 * ( lane & 3 ) ) ) & 0xFFu );
			}

			// ==== 旋转 ====
			constexpr std::uint8_t rotl8( std::uint8_t x, unsigned r ) noexcept
			{
				r &= 7u;
				return ( x << r ) | ( x >> ( 8u - r ) );
			}
			constexpr std::uint8_t rotr8( std::uint8_t x, unsigned r ) noexcept
			{
				r &= 7u;
				return ( x >> r ) | ( x << ( 8u - r ) );
			}

			// ==== L1/L2 线性层（你给的集合）====
			constexpr std::uint32_t l1_forward( std::uint32_t in ) noexcept
			{
				using std::rotl;
				return in ^ rotl( in, 2 ) ^ rotl( in, 10 ) ^ rotl( in, 18 ) ^ rotl( in, 24 );
			}
			constexpr std::uint32_t l1_backward( std::uint32_t out ) noexcept
			{
				using std::rotr;
				return out ^ rotr( out, 2 ) ^ rotr( out, 8 ) ^ rotr( out, 10 ) ^ rotr( out, 14 ) 
					^ rotr( out, 16 ) ^ rotr( out, 18 ) ^ rotr( out, 20 ) ^ rotr( out, 24 ) 
					^ rotr( out, 28 ) ^ rotr( out, 30 );
			}
			constexpr std::uint32_t l2_forward( std::uint32_t in ) noexcept
			{
				using std::rotl;
				return in ^ rotl( in, 8 ) ^ rotl( in, 14 ) ^ rotl( in, 22 ) ^ rotl( in, 30 );
			}
			constexpr std::uint32_t l2_backward( std::uint32_t out ) noexcept
			{
				using std::rotr;
				return out ^ rotr( out, 2 ) ^ rotr( out, 4 ) ^ rotr( out, 8 ) ^ rotr( out, 12 ) 
					^ rotr( out, 14 ) ^ rotr( out, 16 ) ^ rotr( out, 18 ) ^ rotr( out, 22 ) 
					^ rotr( out, 24 ) ^ rotr( out, 30 );
			}

			// ==== 8-bit 模加/模减 ====
			inline uint8_t add8( uint8_t x, uint8_t y ) noexcept
			{
				return static_cast<uint8_t>( x + y );  // 环绕
			}
			inline uint8_t sub8( uint8_t x, uint8_t y ) noexcept
			{
				return static_cast<uint8_t>( x - y );  // 环绕
			}

			// === 无进位链的偶数型小 s：线性在前 → 2 次加（第 2 次只加常量）===
			inline void s_even_forward( uint8_t& a, uint8_t& b, uint8_t rc, unsigned r1, unsigned r2, unsigned r3 ) noexcept
			{
				// 线性扩散（不引入 carry）
				a ^= rotr8( b, r1 );
				b ^= rotl8( a, r1 );

				// 非线性：唯一一次 变量↔变量 的模加
				a = add8( a, rotl8( b, r3 ) );
				b ^= rotl8( a, r3 );
				a ^= rc;

				// —— 断模加链：加法只加常量 ——
				b = add8( b, rc );

				// 线性把两支重新搅在一起
				b ^= rotl8( a, r2 );
				a ^= rotl8( b, r2 );
			}

			inline void s_even_backward( uint8_t& a, uint8_t& b, uint8_t rc, unsigned r1, unsigned r2, unsigned r3 ) noexcept
			{
				a ^= rotl8( b, r2 );
				b ^= rotl8( a, r2 );
				b = sub8( b, rc );	// 撤常量加
				a ^= rc;
				b ^= rotl8( a, r3 );
				a = sub8( a, rotl8( b, r3 ) );	// 撤唯一一次变量↔变量加
				b ^= rotl8( a, r1 );
				a ^= rotr8( b, r1 );
			}

			// === 无进位链的偶数型小 s：线性在后 → 1 次加（第 2 次只加常量）===
			inline void s_odd_forward( uint8_t& a, uint8_t& b, uint8_t rc, unsigned r1, unsigned r2, unsigned r3 ) noexcept
			{
				// 混淆A
				a = add8( a, rotr8( b, r1 ) );
				// 强制扩散B
				b ^= rotl8( a, r2 );
				// 改变A以便再次强制扩散B
				a ^= rc;
				// 强制扩散B
				b ^= rotr8( a, r3 );
			}

			inline void s_odd_backward( uint8_t& a, uint8_t& b, uint8_t rc, unsigned r1, unsigned r2, unsigned r3 ) noexcept
			{
				b ^= rotr8( a, r3 );
				a ^= rc;
				b ^= rotl8( a, r2 );
				a = sub8( a, rotr8( b, r1 ) );
			}


			// ==== 八个具体小 s（给每个固定角度，覆盖 GCD(8,r1,r2,r3) = 1）====
			// 偶数型（线性在前 → 两次加；第 2 次加常量，断链）
			inline void forward0_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_even_forward( a, b, rc, 2, 3, 7 );
			}
			inline void backward0_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_even_backward( a, b, rc, 2, 3, 7 );
			}

			inline void forward2_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_even_forward( a, b, rc, 4, 1, 6 );
			}
			inline void backward2_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_even_backward( a, b, rc, 4, 1, 6 );
			}

			inline void forward4_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_even_forward( a, b, rc, 4, 5, 2 );
			}
			inline void backward4_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_even_backward( a, b, rc, 4, 5, 2 );
			}

			inline void forward6_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_even_forward( a, b, rc, 6, 7, 2 );
			}
			inline void backward6_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_even_backward( a, b, rc, 6, 7, 2 );
			}

			// 奇数型（线性在后 → 一次加，本身无链）
			inline void forward1_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_odd_forward( a, b, rc, 2, 5, 4 );
			}
			inline void backward1_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_odd_backward( a, b, rc, 2, 5, 4 );
			}

			inline void forward3_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_odd_forward( a, b, rc, 4, 3, 6 );
			}
			inline void backward3_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_odd_backward( a, b, rc, 4, 3, 6 );
			}

			inline void forward5_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_odd_forward( a, b, rc, 6, 5, 4 );
			}
			inline void backward5_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_odd_backward( a, b, rc, 6, 5, 4 );
			}

			inline void forward7_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_odd_forward( a, b, rc, 4, 1, 2 );
			}
			inline void backward7_8bit( uint8_t& a, uint8_t& b, uint8_t rc ) noexcept
			{
				s_odd_backward( a, b, rc, 4, 1, 2 );
			}
		};

		#else
		
		class NeoAlzetteSubstitutionBox
		{
		public:
			inline void forward( std::uint32_t& a, std::uint32_t& b ) const noexcept
			{
				using std::rotl;
				using std::rotr;
				const auto&	  RC = ROUND_CONSTANT;
				std::uint32_t A = a, B = b;

				// ── Subround 0 : NL → Diffuse → CD  (CD ← B)
				B += ( rotl( A, 31 ) ^ rotl( A, 17 ) ^ RC[ 0 ] );  // ★ 唯一一次 变量↔变量 模加（非线性）
				A -= RC[ 1 ];									   // ★ 常量模减：断链
				// 线性扩散：三角搅拌（可逆）
				A ^= rotl( B, 24 );
				B ^= rotl( A, 16 );
				// 分支线性层（可逆）
				A = l1_forward( A );
				B = l2_forward( B );
				// CD 注入（线性白化/扩散）
				{
					auto [ C0, D0 ] = cd_injection_from_B( B, RC[ 2 ], RC[ 3 ] );
					A ^= ( rotl( C0, 24 ) ^ rotl( D0, 16 ) ^ RC[ 4 ] );
				}

				// ── Subround 1 : NL → Diffuse → CD  (CD ← A)
				A += ( rotl( B, 31 ) ^ rotl( B, 17 ) ^ RC[ 5 ] );  // ★ 唯一一次 变量↔变量 模加（非线性）
				B -= RC[ 6 ];									   // ★ 常量模减：断链
				// 线性扩散：对称三角搅拌（可逆）
				B ^= rotl( A, 24 );
				A ^= rotl( B, 16 );
				// 分支线性层（可逆）
				B = l1_forward( B );
				A = l2_forward( A );
				// CD 注入（线性）
				{
					auto [ C1, D1 ] = cd_injection_from_A( A, RC[ 7 ], RC[ 8 ] );
					B ^= ( rotl( C1, 24 ) ^ rotl( D1, 16 ) ^ RC[ 9 ] );
				}

				// 轻度白化（可逆）
				A ^= RC[ 10 ];
				B ^= RC[ 11 ];
				a = A;
				b = B;
			}

			inline void backward( std::uint32_t& a, std::uint32_t& b ) const noexcept
			{
				using std::rotl;
				using std::rotr;
				const auto&	  RC = ROUND_CONSTANT;
				std::uint32_t A = a, B = b;

				// 撤白化
				B ^= RC[ 11 ];
				A ^= RC[ 10 ];

				// 撤 Subround 1 ：按逆序
				{
					auto [ C1, D1 ] = cd_injection_from_A( A, RC[ 7 ], RC[ 8 ] );
					B ^= ( rotl( C1, 24 ) ^ rotl( D1, 16 ) ^ RC[ 9 ] );
				}  // 撤 CD 注入（XOR 自反）
				B = l1_backward( B );
				A = l2_backward( A );
				A ^= rotl( B, 16 );
				B ^= rotl( A, 24 );
				B += RC[ 6 ];									   // 撤常量模减
				A -= ( rotl( B, 31 ) ^ rotl( B, 17 ) ^ RC[ 5 ] );  // 撤 变量↔变量 模加

				// 撤 Subround 0
				{
					auto [ C0, D0 ] = cd_injection_from_B( B, RC[ 2 ], RC[ 3 ] );
					A ^= ( rotl( C0, 24 ) ^ rotl( D0, 16 ) ^ RC[ 4 ] );
				}
				A = l1_backward( A );
				B = l2_backward( B );
				B ^= rotl( A, 16 );
				A ^= rotl( B, 24 );
				A += RC[ 1 ];
				B -= ( rotl( A, 31 ) ^ rotl( A, 17 ) ^ RC[ 0 ] );

				a = A;
				b = B;
			}


		private:
			/*
				交叉注入（Cross Injection）：这是设计的核心创新之一。它不是一个简单的线性函数，而是一个将输入分支（如B）通过两个不同的路径（使用不同的线性层和旋转）进行处理，产生两个中间值C0和D0，然后这两个中间值再经过一个小的ARX操作（相互混合）后，才用于更新另一个分支（如A）。
				
				这样做的好处是：将单个分支的信息复杂地分裂并重组，然后注入到另一个分支，使得两个分支之间的依赖关系更加复杂和不可逆。
				
				虽然交叉注入内部是线性操作，但由于它使用了多个不同的旋转常数和线性层，并且内部有交叉混合，使得它整体上是一个复杂的线性变换，但因为它是在两个分支之间传递信息，并且与非线性操作交替，所以有效地增强了算法的安全性。
			*/

			// —— CD(B)：只依赖 B 与常量；内部用强旋转量（16/17/24/31 家族）
			inline std::pair<std::uint32_t, std::uint32_t> cd_injection_from_B( std::uint32_t B, std::uint32_t rc0, std::uint32_t rc1 ) const noexcept
			{
				using std::rotl;
				using std::rotr;
				std::uint32_t c = l2_forward( B ^ rc0 );
				std::uint32_t d = l1_forward( rotr( B, 3 ) ^ rc1 );	 // r2=0 的用法见 Alzette
				// 交叉搅拌（XOR/ROT 可逆）
				std::uint32_t t = rotl( c ^ d, 31 );
				c ^= rotl( d, 17 );
				d ^= rotr( t, 16 );
				return { c, d };
			}

			// —— CD(A)：只依赖 A 与常量；同样用 31/17/24/16 家族
			inline std::pair<std::uint32_t, std::uint32_t> cd_injection_from_A( std::uint32_t A, std::uint32_t rc0, std::uint32_t rc1 ) const noexcept
			{
				using std::rotl;
				using std::rotr;
				std::uint32_t c = l1_forward( A ^ rc0 );
				std::uint32_t d = l2_forward( rotl( A, 24 ) ^ rc1 );
				std::uint32_t t = rotr( c ^ d, 31 );
				c ^= rotr( d, 17 );
				d ^= rotl( t, 16 );
				return { c, d };
			}

			// ==== 你给的 L1/L2 线性层 ====
			constexpr std::uint32_t l1_forward(std::uint32_t in) const noexcept {
				using std::rotl;
				return in ^ rotl(in, 2) ^ rotl(in, 10) ^ rotl(in, 18) ^ rotl(in, 24);
			}
			constexpr std::uint32_t l1_backward(std::uint32_t out) const noexcept {
				using std::rotr;
				return out ^ rotr(out, 2) ^ rotr(out, 8) ^ rotr(out, 10) ^ rotr(out, 14)
						   ^ rotr(out,16) ^ rotr(out,18) ^ rotr(out,20) ^ rotr(out,24)
						   ^ rotr(out,28) ^ rotr(out,30);
			}
			constexpr std::uint32_t l2_forward(std::uint32_t in) const noexcept {
				using std::rotl;
				return in ^ rotl(in, 8) ^ rotl(in, 14) ^ rotl(in, 22) ^ rotl(in, 30);
			}
			constexpr std::uint32_t l2_backward(std::uint32_t out) const noexcept {
				using std::rotr;
				return out ^ rotr(out, 2) ^ rotr(out, 4) ^ rotr(out, 8) ^ rotr(out, 12)
						   ^ rotr(out,14) ^ rotr(out,16) ^ rotr(out,18) ^ rotr(out,22)
						   ^ rotr(out,24) ^ rotr(out,30);
			}

			// ==== NeoAlzette ARX-box 常量 ====
			static constexpr std::array<std::uint32_t, 16> ROUND_CONSTANT
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

		#endif

		uint64_t ghash_multiply( uint64_t a, uint64_t b )
		{
			uint64_t	   product = 0;
			const uint64_t POLYNOMIAL = 0xE100000000000000;	 // This is x^64 + x^4 + x^3 + x + 1 in binary

			for ( int i = 0; i < 64; i++ )
			{
				if ( b & 1 )
				{
					product ^= a;
				}

				//boolean type
				uint64_t high_bit_set = a & 0x8000000000000000;

				a <<= 1;

				if ( high_bit_set )
				{
					a ^= POLYNOMIAL;
				}

				b >>= 1;
			}

			return product;
		}
		
		// 生成所有轮次密钥状态的方法
		void LittleOaldresPuzzle_Cryptic::GenerateAndStoreKeyStates( const Key128 key, const std::uint64_t number_once )
		{
			// Crypto Version Fold Multiply Generate Seed
			uint64_t a = ( key.first ^ key.second );
			uint64_t b = ~ghash_multiply( key.first, key.second );
			// Rationale for rot=1 and rot=13:
			// - rot1(b): 打断 a'⊕b' 的线性抵消恒等式（I⊕S），把乘法支路 b 的影响直接扩散到相邻位；
			// - rot13(a): 选用与 64 互素且与{8,16,24,31,17,…}等常见角度“错位”的中距奇数旋转，
			//             既避开与轮函数既有旋转的对齐/共振，又提供与 rot1 频段互补的扩散；
			//   两者叠加保证 a、b 两路都进 seed，且不存在简单线性组合把其中一路整体消掉。
			//   （说明：任意两个“奇数、互异、与现有角度不共振”的旋转也可行；1+13 是在扩散/代价/实现友好之间的折中。）
			uint64_t			seed = ( a ^ std::rotl( b, 1 ) ) ^ std::rotl( a, 13 );
			XorConstantRotation key_prng( seed );

			uint32_t round_constant_index = 0;
			for ( size_t round = 0; round < rounds; round++ )
			{
				KeyState& key_state = KeyStates[ round ];

				const uint64_t sk0 = key_prng( number_once );		// 密钥驱动（有状态→每轮不同）
				const uint64_t para = prng( number_once ^ round );	// 公开盐（含 round）

				// 两半子密钥：都含密钥信息
				key_state.subkey.first = key.first ^ sk0;
				key_state.subkey.second = key.second ^ para;

				// 由子密钥驱动选路（保留“PRG 输出的低 2 位”语义）
				key_state.choice_function = key_prng( key_state.subkey.first ^ ( key.first >> 1 ) ) & 0x3;

				// 旋转量由 subkey.second 与 choice 再驱动（保留链式依赖）
				const uint64_t bit_rotation = prng( key_state.subkey.second ^ key_state.choice_function );
				key_state.bit_rotation_amount_a = bit_rotation & 0x3F;			 // 0..63 (Selected bit 0~5)
				key_state.bit_rotation_amount_b = ( bit_rotation >> 6 ) & 0x3F;	 // 0..63 (Selected bit 6~11)

				//key_state.round_constant_index = ( round_constant_index >> 1 ) & 0x0F;
				round_constant_index += 2;
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

				/*  Keyed Switching Layer - Random Bit Tweak (Nonlinear)(Forward) */
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