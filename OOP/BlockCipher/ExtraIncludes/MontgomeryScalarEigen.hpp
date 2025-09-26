#pragma once
#include <cstdint>
#include <cstddef>
#include <limits>
#include <type_traits>
#include <cassert>

#if defined( _MSC_VER ) && !defined( __clang__ )
#include <intrin.h>	 // _umul128
#endif

#include <eigen/Eigen/Core>

namespace TwilightDreamOfMagical::PrimeField
{

	// —— 跨编译器 64x64->128 乘法小封装 ——
	static inline void MultiplyUnsignedWide( uint64_t left, uint64_t right, uint64_t& lower_product, uint64_t& upper_product ) noexcept
	{
#if defined( _MSC_VER ) && !defined( __clang__ )
		lower_product = _umul128( left, right, &upper_product );
#else
		unsigned __int128 full = ( unsigned __int128 )left * ( unsigned __int128 )right;  // GCC/Clang 扩展
		lower_product = ( uint64_t )full;
		upper_product = ( uint64_t )( full >> 64 );
#endif
	}

	// —— 蒙哥马利域上下文：模数、n'、R^2 等常量 ——
	// 约定：R = 2^64，n' = -n^{-1} (mod 2^64)
	struct MontgomeryPrimeFieldContext
	{
		uint64_t modulus = 0;			  // n：奇素数
		uint64_t montgomery_inverse = 0;  // n'：-n^{-1} mod 2^64
		uint64_t r2_mod = 0;			  // R^2 mod n

		static uint64_t ComputeMontgomeryInverse( uint64_t n )
		{
			// Newton 迭代，得到 n^{-1} mod 2^64，然后取相反数得到 n'
			uint64_t x = 1;
			for ( int i = 0; i < 6; ++i )
				x *= ( 2 - n * x );
			return ~x + 1;	// -x (mod 2^64)
		}

		static uint64_t ComputeR2( uint64_t n )
		{
			uint64_t acc = 1 % n;
			for (int i = 0; i < 128; ++i) {
				acc += acc;
				if (acc >= n)
					acc -= n;
			}
			return acc;
		}

		explicit MontgomeryPrimeFieldContext( uint64_t p ) : modulus( p ), montgomery_inverse( ComputeMontgomeryInverse( p ) ), r2_mod( ComputeR2( p ) ) {}

		// REDC：把 128-bit（hi:lo）按蒙哥马利规约映到 [0, n)
		inline uint64_t ReduceFrom128( uint64_t low, uint64_t high ) const noexcept
		{
			// u = (low * n') mod 2^64 —— 只取低 64 位即可
			uint64_t u_low, u_high;
			MultiplyUnsignedWide( low, montgomery_inverse, u_low, u_high );
			( void )u_high;

			// a = (low + u*modulus + high*2^64) >> 64 的高 64 位
			uint64_t m_low, m_high;
			MultiplyUnsignedWide( u_low, modulus, m_low, m_high );

			uint64_t sum_low = low + m_low;
			uint64_t carry_0 = ( sum_low < low ) ? 1 : 0;
			uint64_t sum_high = high + m_high + carry_0;

			// 条件减法到 [0, n)
			if ( sum_high >= modulus )
				sum_high -= modulus;
			return sum_high;
		}

		inline uint64_t ToMontgomery( uint64_t standard_value ) const noexcept
		{
			// xR = x * R^2 / R  =>  Reduce(x * R^2)
			uint64_t lo, hi;
			MultiplyUnsignedWide( standard_value % modulus, r2_mod, lo, hi );
			return ReduceFrom128( lo, hi );
		}

		inline uint64_t FromMontgomery( uint64_t mont_value ) const noexcept
		{
			// Reduce(xR)：把域内表示转回普通余数
			return ReduceFrom128( mont_value, 0 );
		}

		inline uint64_t AddResidues( uint64_t aR, uint64_t bR ) const noexcept
		{
			uint64_t c = aR + bR;
			// 处理 64 位回绕与条件减法
			if ( c < aR || c >= modulus )
				c -= modulus;
			return c;
		}

		inline uint64_t SubtractResidues( uint64_t aR, uint64_t bR ) const noexcept
		{
			return ( aR >= bR ) ? ( aR - bR ) : ( aR + modulus - bR );
		}

		inline uint64_t MultiplyResidues( uint64_t aR, uint64_t bR ) const noexcept
		{
			uint64_t lo, hi;
			MultiplyUnsignedWide( aR, bR, lo, hi );
			return ReduceFrom128( lo, hi );
		}
	};

	// —— 让算子能在 Eigen 里用到上下文：用 thread_local 作用域注入 ——
	// 用法：在一次 GEMV 前，构造一个临时的作用域对象把上下文“设为当前”；析构时自动恢复。
	struct MontgomeryComputationScope
	{
		static inline thread_local const MontgomeryPrimeFieldContext* active = nullptr;
		const MontgomeryPrimeFieldContext*							  previous = nullptr;

		explicit MontgomeryComputationScope( const MontgomeryPrimeFieldContext& ctx ) noexcept
		{
			previous = active;
			active = &ctx;
		}
		~MontgomeryComputationScope() noexcept
		{
			active = previous;
		}

		static const MontgomeryPrimeFieldContext& Context()
		{
			assert( active && "No active MontgomeryPrimeFieldContext. Create MontgomeryComputationScope on stack." );
			return *active;
		}
	};

	// —— 自定义标量：Montgomery64（内部存放“域内表示”的 64 位残数） ——
	struct Montgomery64
	{
		uint64_t residue = 0;  // 始终是域内表示（Montgomery 形式）

		// 构造 & 工具
		Montgomery64() = default;
		explicit Montgomery64( uint64_t montgomery_residue_value, bool already_montgomery ) 
			: residue( montgomery_residue_value )
		{
			( void )already_montgomery;	 // 只为可读的构造语义
		}

		Montgomery64(int x) noexcept
		  : Montgomery64( (x==0) ? uint64_t(0) : uint64_t(1), /*already_montgomery=*/ (x==0) )
		{
			assert(x==0 || x==1);
			if (x==1) 
			{
				// 把 1 转为域内表示
				const auto& C = TwilightDreamOfMagical::PrimeField::MontgomeryComputationScope::Context();
				residue = C.ToMontgomery(1);
			}
		}

		static Montgomery64 Zero()
		{
			return Montgomery64( 0, /*already_montgomery=*/true );
		}
		static Montgomery64 One()
		{
			const auto& C = MontgomeryComputationScope::Context();
			return Montgomery64( C.ToMontgomery( 1 ), /*already_montgomery=*/true );
		}

		static Montgomery64 FromStandard( uint64_t standard_value )
		{
			const auto& C = MontgomeryComputationScope::Context();
			return Montgomery64( C.ToMontgomery( standard_value % C.modulus ), /*already_montgomery=*/true );
		}
		uint64_t ToStandard() const
		{
			const auto& C = MontgomeryComputationScope::Context();
			return C.FromMontgomery( residue );
		}

		// —— 跟 int 的乘法桥（Eigen 某些路径会触发 scale * expr） ——
		// 仍然只接受 0/1（别让别的字面量污染域）
		friend inline Montgomery64 operator*(const Montgomery64& a, int b) noexcept {
			return (b==0) ? Montgomery64::Zero() : a;
		}
		friend inline Montgomery64 operator*(int a, const Montgomery64& b) noexcept {
			return (a==0) ? Montgomery64::Zero() : b;
		}

		// 算术运算（域内）
		friend inline Montgomery64 operator+( const Montgomery64& a, const Montgomery64& b )
		{
			const auto& C = MontgomeryComputationScope::Context();
			return Montgomery64( C.AddResidues( a.residue, b.residue ), /*already_montgomery=*/true );
		}
		friend inline Montgomery64 operator-( const Montgomery64& a, const Montgomery64& b )
		{
			const auto& C = MontgomeryComputationScope::Context();
			return Montgomery64( C.SubtractResidues( a.residue, b.residue ), /*already_montgomery=*/true );
		}
		friend inline Montgomery64 operator*( const Montgomery64& a, const Montgomery64& b )
		{
			const auto& C = MontgomeryComputationScope::Context();
			return Montgomery64( C.MultiplyResidues( a.residue, b.residue ), /*already_montgomery=*/true );
		}
		Montgomery64& operator+=( const Montgomery64& other )
		{
			*this = *this + other;
			return *this;
		}
		Montgomery64& operator-=( const Montgomery64& other )
		{
			*this = *this - other;
			return *this;
		}
		Montgomery64& operator*=( const Montgomery64& other )
		{
			*this = *this * other;
			return *this;
		}

		// 比较（仅用于断言/调试）
		friend inline bool operator==( const Montgomery64& a, const Montgomery64& b )
		{
			return a.residue == b.residue;
		}
		friend inline bool operator!=( const Montgomery64& a, const Montgomery64& b )
		{
			return !( a == b );
		}
	};

}  // namespace TwilightDreamOfMagical::PrimeField

// —— 告诉 Eigen：这个自定义标量能当 “数字” 用 ——
// 官方要求：实现常见运算符，并专门化 NumTraits。必要项够了，其他数学函数留给需要时再补。
// 参考：TopicCustomizing_CustomScalar / NumTraits 文档。
namespace Eigen
{
	template <>
	struct NumTraits<TwilightDreamOfMagical::PrimeField::Montgomery64> : NumTraits<uint64_t>
	{
		using Real = TwilightDreamOfMagical::PrimeField::Montgomery64;
		using NonInteger = TwilightDreamOfMagical::PrimeField::Montgomery64;
		using Nested = TwilightDreamOfMagical::PrimeField::Montgomery64;

		enum
		{
			IsComplex = 0,
			IsInteger = 1,
			IsSigned = 0,
			RequireInitialization = 1,
			ReadCost = 1,
			AddCost = 1,
			MulCost = 3
		};

		static inline Real epsilon()
		{
			return Real::Zero();
		}
		static inline Real dummy_precision()
		{
			return Real::Zero();
		}
		static inline Real highest()
		{
			return Real::One();
		}
		static inline Real lowest()
		{
			return Real::Zero();
		}
		static inline Real literal( int x )
		{
			return Real( x );
		}
	};
}  // namespace Eigen


namespace Eigen
{
	namespace internal
	{

		template <>
		struct scalar_product_traits<int, TwilightDreamOfMagical::PrimeField::Montgomery64>
		{
			using ReturnType = TwilightDreamOfMagical::PrimeField::Montgomery64;
		};

		template <>
		struct scalar_product_traits<TwilightDreamOfMagical::PrimeField::Montgomery64, int>
		{
			using ReturnType = TwilightDreamOfMagical::PrimeField::Montgomery64;
		};

	}  // namespace internal
}  // namespace Eigen
