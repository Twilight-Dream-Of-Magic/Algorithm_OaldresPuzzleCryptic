#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_SUPPORTBASEFUNCTIONS_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_SUPPORTBASEFUNCTIONS_HPP

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <ctime>

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <string_view>

#include <typeinfo>
#include <type_traits>

#include <algorithm>
#include <iomanip>
#include <utility>
#include <stdexcept>
#include <chrono>
#include <limits>
#include <bitset>
#include <random>
#include <codecvt>
#include <new>
#include <memory>
//#include <complex>

#if __cplusplus >= 201703L

#include <charconv>
#include <optional>
#include <filesystem>
#include <numeric>

#endif

#if __cplusplus >= 202002L

#include <bit>
#include <ranges>
#include <coroutine>
#include <source_location>
#include <numbers>
#include <concepts>
#include <span>

#endif

#include <iterator>
#include <array>
#include <vector>
#include <list>
#include <stack>
#include <queue>
#include <deque>
#include <set>
#include <unordered_set>
#include <map>
#include <unordered_map>

//Multi-Threading-Development-ISO-C++ Standard Library
#include <atomic>
#include <thread>
#include <mutex>
#include <future>
#include <functional>
#include <condition_variable>

#if __cplusplus >= 201703L

#include <shared_mutex>

#endif

#if defined(NULL)
#undef NULL

#if __cplusplus >= 201103L
#define NULL (nullptr)
#else
#define NULL 0
#endif

#endif

//Function to left rotate (number) by (count) bits
template <typename IntegerType>
requires std::is_integral_v<IntegerType>
inline IntegerType Binary_LeftRotateMove( IntegerType NumberValue, int RotationCount )
{
	constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;

	RotationCount = BitDigits & (BitDigits - 1) ? RotationCount % BitDigits : RotationCount & (BitDigits - 1);
	if(RotationCount == 0)
		return NumberValue;
	else if(static_cast<std::int64_t>(RotationCount) > 0)
		return (NumberValue << RotationCount) | NumberValue >> (BitDigits - RotationCount);
	else if(static_cast<std::int64_t>(RotationCount) < 0)
	{
		RotationCount = ~RotationCount + 1;
		return (NumberValue << RotationCount) | NumberValue >> (BitDigits - RotationCount);
	}

	return NumberValue;
}

//Function to right rotate (number) by (count) bits
template <typename IntegerType>
requires std::is_integral_v<IntegerType>
inline IntegerType Binary_RightRotateMove( IntegerType NumberValue, int RotationCount )
{
	constexpr auto BitDigits = std::numeric_limits<IntegerType>::digits;

	RotationCount = BitDigits & (BitDigits - 1) ? RotationCount % BitDigits : RotationCount & (BitDigits - 1);
	if(RotationCount == 0)
		return NumberValue;
	else if(static_cast<std::int64_t>(RotationCount) > 0)
		return (NumberValue >> RotationCount) | NumberValue << (BitDigits - RotationCount);
	else if(static_cast<std::int64_t>(RotationCount) < 0)
	{
		RotationCount = ~RotationCount + 1;
		return (NumberValue >> RotationCount) | NumberValue << (BitDigits - RotationCount);
	}

	return NumberValue;
}

namespace CommonToolkit
{
	// false value attached to a dependent name (for static_assert)
	template<auto>
	inline constexpr bool Dependent_Always_Failed = false;
	// true value attached to a dependent name (for static_assert)
	template<auto>
	inline constexpr bool Dependent_Always_Succeed = true;

	template<class T>
	struct dependent_always_true : std::true_type
	{
	};
	template<class T>
	struct dependent_always_false : std::false_type
	{
	};

#if __cplusplus >= 202002L
	template<std::integral Type ,std::size_t Size>
	constexpr std::array<Type, Size> make_array()
	{
		std::array<Type, Size> result;

		Type value = 0;
		for(std::size_t index = 0; index < Size; ++index)
		{
			result[index] = value;
			++value;
		}
		return result;
	}
#else
	namespace MakeArrayImplement
	{
		template<typename Type, std::size_t N, std::size_t... I>
		constexpr auto make_array(std::index_sequence<I...>)
		{
			return std::array<Type, N>{ {I...} };
		}

		template<typename Type, typename FunctionType, std::size_t... Is>
		requires std::invocable<FunctionType>
		constexpr auto generate_array(FunctionType& function, std::index_sequence<Is...>) -> std::array<Type, sizeof...(Is)>
		{
			return {{ function(std::integral_constant<std::size_t, Is>{})... }};
		}
	}

	namespace MakeVectorImplement
	{
		template <typename Type, Type... VALUES>
		constexpr std::vector<Type> make_vector()
		{
			return std::vector<Type> { VALUES... };
		}
	}

	template<typename Type, std::size_t N>
	constexpr auto make_array()
	{
		static_assert(N >= Type{}, "no negative sizes");
		return MakeArrayImplement::make_array<Type, N>(std::make_index_sequence<N>{});
	}

	template<typename Type, std::size_t N, typename FunctionType>
	requires std::invocable<FunctionType>
	constexpr auto generate_array(FunctionType function)
	{
		return MakeArrayImplement::generate_array<Type>(function, std::make_index_sequence<N>{});
	}

	template <typename Type, Type... VALUES>
	constexpr std::vector<Type> make_vector( std::integer_sequence<Type, VALUES...> )
	{
		return MakeVectorImplement::make_vector<Type, VALUES...>();
	}
#endif
}

static constexpr size_t CURRENT_SYSTEM_BITS = (std::numeric_limits<unsigned char>::digits * sizeof(void*));

#if __cplusplus >= 202002L

inline void my_cpp2020_assert(const bool JudgmentCondition, const char* ErrorMessage, std::source_location AssertExceptionDetailTrackingObject)
{
	if(!JudgmentCondition)
	{
		std::system("chcp 65001");

		std::cout << "The error message is(错误信息是):\n" << ErrorMessage << std::endl;
		std::cout << "Oh, crap, some of the code already doesn't match the conditions at runtime.(哦，糟糕，有些代码在运行时已经不匹配条件。)\n\n\n" << std::endl;
		std::cout << "Here is the trace before the assertion occurred(下面是发生断言之前的追踪信息):\n\n" << std::endl;
		std::cout << "The condition determines the code file that appears to be a mismatch(条件判断出现不匹配的代码文件):\n" << AssertExceptionDetailTrackingObject.file_name() << std::endl;
		std::cout << "Name of the function where this assertion is located(该断言所在的函数的名字):\n" << AssertExceptionDetailTrackingObject.function_name() << std::endl;
		std::cout << "Number of lines of code where the assertion is located(该断言所在的代码行数):\n" << AssertExceptionDetailTrackingObject.line() << std::endl;
		std::cout << "Number of columns of code where the assertion is located(该断言所在的代码列数):\n" << AssertExceptionDetailTrackingObject.column() << std::endl;

		// Print stack trace for C++23 and above
		#if __cplusplus >= 202300L
		std::cout << "Stack trace before assertion:\n";
		

		for (const auto& frame : std::stacktrace::current())
		{
			std::cout << frame << std::endl;
		}
		#endif

		throw std::runtime_error(ErrorMessage);
	}
	else
	{
		return;
	}
}

#endif


#define __STDC_WANT_LIB_EXT1__ 1

static inline void* (* const volatile memory_set_no_optimize_function_pointer)(void*, int, size_t) = memset;

struct MemorySetUitl
{
	/**
	 * @brief The function copies the value of @a value (converted to an unsigned char)
	 * into each of the first @a count characters of the object pointed to by @a dest.
	 * The purpose of this function is to make sensitive information stored in the object inaccessible.
	 * @param buffer_pointer to the object to fill
	 * @param value: character fill byte
	 * @param size: count number of bytes to fill
	 * @return a copy of dest
	 * @note C++ proposal: http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p1315r6.html
	 * @note The intention is that the memory store is always performed (i.e., never elided),
	 *		 regardless of optimizations. This is in contrast to calls to the memset function.
	 */
	inline volatile void* fill_memory_byte_no_optimize_implementation(volatile void* buffer_pointer, const int byte_value, size_t size)
	{
		if(buffer_pointer == nullptr)
			return nullptr;

#if __cplusplus >= 201103L && defined(__STDC_WANT_LIB_EXT1__) && __STDC_WANT_LIB_EXT1__ == 1 && defined(__STDC_LIB_EXT1__)
		memset_s(buffer_pointer, byte_value, 0, size);
#elif !defined(__STDC_WANT_LIB_EXT1__) && !defined(__STDC_LIB_EXT1__) && !defined(_WIN32)

		/*
			Pointer to memset is volatile so that compiler must de-reference the pointer and can't assume that it points to any function in particular (such as memset, which it then might further "optimize")
			指向memset的指针是不稳定的，因此编译器必须取消对该指针的引用，不能假定它指向任何特定的函数（例如memset，然后它可能进一步 "优化"）。

			New Reference code: https://github.com/peterlauro/memset_explicit/blob/main/include/cstring.h
			Old Reference code: https://github.com/openssl/openssl/blob/master/crypto/mem_clr.c
		*/
		volatile void* memory_set_volatile_pointer = std::memset(buffer_pointer, byte_value, size);

		// https://stackoverflow.com/questions/50428450/what-does-asm-volatile-pause-memory-do
		// https://preshing.com/20120625/memory-ordering-at-compile-time/
		// when -O2 or -O3 is on
		// the following line prevents the compiler to optimize away the call of memset
		// https://stackoverflow.com/questions/14449141/the-difference-between-asm-asm-volatile-and-clobbering-memory
		// compiler barrier:
		// - the linux inline assembler is not allowed to be used by the project coding rules
		// asm volatile ("" ::: "memory");
		// - the windows compiler intrinsic _ReadWriteBarrier is deprecated
		//	https://docs.microsoft.com/en-us/cpp/intrinsics/readwritebarrier?view=msvc-160
		//
		// the msvc /std:c++17 /Ot - without a compiler_barrier doesn't optimize away the call of memset
		// the linux g++ 9.3.0 -O2 - without a compiler_barrier the call of memset is optimized away
		//
		// std::atomic_thread_fence:
		// gcc 9.3.0 -std=c++17 -O2 generates mfence asm instruction; the call of memset is not optimized away
		// std::atomic_signal_fence:
		// gcc 9.3.0 -std=c++17 -O2 no mfence asm instruction is generated,
		// however the call of memset is not optimized away too

		#if __cplusplus >= 201402L

		std::atomic_signal_fence(std::memory_order_seq_cst);

		#endif

		return memory_set_volatile_pointer;

#elif __cplusplus >= 201103L

		if(byte_value > -1 && byte_value < 256)
		{
			static volatile unsigned char* volatile current_pointer = (volatile unsigned char *)buffer_pointer;
			do
			{
				memory_set_no_optimize_function_pointer((unsigned char *)current_pointer, byte_value, size);
			} while(*current_pointer != byte_value);

			return buffer_pointer;
		}
		else if(byte_value > -129 && byte_value < 128)
		{
			static volatile char* volatile current_pointer = (volatile char *)buffer_pointer;
			do
			{
				memory_set_no_optimize_function_pointer((char *)current_pointer, byte_value, size);
			} while(*current_pointer != byte_value);

			return buffer_pointer;
		}

		return nullptr;

#elif __cplusplus == 199711L

		if(size == 0)
		   return nullptr;
		static volatile char* volatile current_pointer = (volatile char*)buffer_pointer;


		if(byte_value > -1 && byte_value < 256)
		{
			static volatile unsigned char* volatile current_pointer = (volatile unsigned char*)buffer_pointer;
			while (size--)
			{
				if(*current_pointer != byte_value)
					*current_pointer ^= ( *current_pointer ^ byte_value );
			}

			return buffer_pointer;
		}
		else if(byte_value > -129 && byte_value < 128)
		{
			static volatile char* volatile current_pointer = (volatile char*)buffer_pointer;
			while (size--)
			{
				if(*current_pointer != byte_value)
					*current_pointer ^= ( *current_pointer ^ byte_value );
			}

			return buffer_pointer;
		}

		return nullptr;

#endif
	}

	inline volatile void fill_memory(volatile void* buffer_pointer, const int byte_value, size_t size)
	{
		volatile void* check_pointer = nullptr;
		check_pointer = this->fill_memory_byte_no_optimize_implementation(buffer_pointer, byte_value, size);

		if(check_pointer == nullptr)
		{
			throw std::runtime_error("Support-Library: Force Memory Fill Has Been \"Optimization\" !");
		}
	}
};

/**
 * @brief Copies the value of @a ch (converted to an unsigned char) into each byte of
 *		  the object pointed to by @a dest.
 *		  The purpose of this function is to make sensitive information stored
 *		  in the object inaccessible.
 * @param TriviallyCopyableType the type of object
 * @param that reference to the object to fill
 * @param value: character fill byte
 * @note C++ proposal: http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/p1315r6.html
 * @note The intention is that the memory store is always performed (i.e., never elided),
 *		 regardless of optimizations. This is in contrast to calls to the memset function.
 */
template<typename TriviallyCopyableType,
		std::enable_if_t<std::is_trivially_copyable_v<TriviallyCopyableType> && !std::is_pointer_v<TriviallyCopyableType>>* = nullptr>
void memory_set_explicit_call(TriviallyCopyableType& that_object, int value) noexcept
{
	MemorySetUitl MemorySetUitlObject;
	MemorySetUitlObject.fill_memory(std::addressof(that_object), value, sizeof(that_object));
}

// 开关：需要抽样自检就开；不想要就注释掉。
// #define TDOM_SECURE_WIPE_DIAGNOSTICS 1

// —— 写到 volatile 目标的输出迭代器（用来喂 std::fill_n） ——
struct VolatileByteOutputIterator
{
	using difference_type = std::ptrdiff_t;
	using value_type = void;
	using pointer = void;
	using reference = void;
	using iterator_category = std::output_iterator_tag;

	volatile unsigned char* current;

	struct AssignmentProxy
	{
		volatile unsigned char* target;
		AssignmentProxy&		operator=( unsigned char value ) noexcept
		{
			*target = value;  // 关键：volatile 写，属于“可观察副作用”
			return *this;
		}
	};

	explicit VolatileByteOutputIterator( volatile unsigned char* p ) noexcept : current( p ) {}

	AssignmentProxy operator*() const noexcept
	{
		return AssignmentProxy { current };
	}
	VolatileByteOutputIterator& operator++() noexcept
	{
		++current;
		return *this;
	}
	VolatileByteOutputIterator operator++( int ) noexcept
	{
		auto tmp = *this;
		++( *this );
		return tmp;
	}
};

// —— 安全擦除（不依赖 OS API），保持你原有模板签名和返回值语义 ——
template <int byte_value>
static inline volatile void* memory_set_no_optimize_function( void* buffer_pointer, std::size_t size ) noexcept
{
	// 空指针或空区间，直接按失败处理（与你之前一致）
	if ( buffer_pointer == nullptr || size == 0 )
		return nullptr;

	static_assert( byte_value >= -128 && byte_value <= 255, "Byte number is out of range!" );
	const unsigned char fill_byte = static_cast<unsigned char>( byte_value );

	// 目标指向 volatile 字节视图：写入成为“可观察副作用”，优化器不能删
	volatile unsigned char* volatile destination = static_cast<volatile unsigned char*>( buffer_pointer );

	// 用标准算法“优雅”地完成 volatile 写：没有手写 for，但本质是一串存储
	std::fill_n( VolatileByteOutputIterator { destination }, size, fill_byte );

	// 编译器栅栏：阻止重排把后续代码搬到擦除之前（可与 LTO 同用）
	std::atomic_signal_fence( std::memory_order_seq_cst );

#if defined( TDOM_SECURE_WIPE_DIAGNOSTICS )
	// —— 诊断模式：随机抽查最多 128 个位置（用 volatile 读确保真的从内存取）——
	std::size_t samples = ( size < 128 ) ? size : 128;

	// xorshift64* 轻量伪随机，seed 用地址与长度，避免引入库
	auto seed = ( static_cast<std::uint64_t>( reinterpret_cast<std::uintptr_t>( buffer_pointer ) ) ^ static_cast<std::uint64_t>( size ) ) | 1ull;
	auto next_rand = [ & ]() noexcept {
		seed ^= seed >> 12;
		seed ^= seed << 25;
		seed ^= seed >> 27;
		return seed * 0x2545F4914F6CDD1Dull;
	};

	for ( std::size_t k = 0; k < samples; ++k )
	{
		std::size_t idx = static_cast<std::size_t>( next_rand() % size );
		// 用 volatile 读，保证读本身是可观察的，从而不会被常量传播“脑补”
		if ( destination[ idx ] != fill_byte )
			return nullptr;	 // 发现不匹配，立刻报警
	}
#endif

	return buffer_pointer;
}

#if defined(__STDC_WANT_LIB_EXT1__)
#undef __STDC_WANT_LIB_EXT1__
#endif

namespace CommonToolkit::IntegerExchangeBytes
{
	#if !defined(BYTE_SWAP_FUNCTON) && __cplusplus >= 202002L
	#define BYTE_SWAP_FUNCTON
	#endif // !BYTE_SWAP_FUNCTON

	#if !defined(MEMORY_DATA_TYPE_PACKER_AND_UNPACKER) && __cplusplus >= 202002L
	#define MEMORY_DATA_TYPE_PACKER_AND_UNPACKER
	#endif // !MEMORY_DATA_TYPE_PACKER_AND_UNPACKER

	#if !defined(INTEGER_PACKCATION_OLD) && __cplusplus < 202002L
	#define INTEGER_PACKCATION_OLD
	#endif // !INTEGER_PACKCATION_OLD

	#if !defined(INTEGER_UNPACKCATION_OLD) && __cplusplus < 202002L
	#define INTEGER_UNPACKCATION_OLD
	#endif // !INTEGER_UNPACKCATION_OLD

	#if defined( BYTE_SWAP_FUNCTON )	

	/*
		Reference source code: https://gist.github.com/raidoz/4163b8ec6672aabb0656b96692af5e33
		cross-platform / cross-compiler standalone endianness conversion
	*/
	namespace ByteSwap
	{
		namespace Implementation
		{
			constexpr uint16_t Byteswap(uint16_t value) noexcept
			{
				return (value >> 8) | (value << 8);
			}

			constexpr uint32_t Byteswap(uint32_t value) noexcept
			{
				return ((value >> 24) & 0x000000FF) |
					((value >> 8)  & 0x0000FF00) |
					((value << 8)  & 0x00FF0000) |
					((value << 24) & 0xFF000000);
			}

			constexpr uint64_t Byteswap(uint64_t value) noexcept
			{
				return ((value >> 56) & 0x00000000000000FF) |
					((value >> 40) & 0x000000000000FF00) |
					((value >> 24) & 0x0000000000FF0000) |
					((value >> 8)  & 0x00000000FF000000) |
					((value << 8)  & 0x000000FF00000000) |
					((value << 24) & 0x0000FF0000000000) |
					((value << 40) & 0x00FF000000000000) |
					((value << 56) & 0xFF00000000000000);
			}

			static inline float Byteswap(float ByteValue) noexcept
			{
#ifdef __cplusplus
				static_assert(sizeof(float) == sizeof(uint32_t), "Unexpected float format");
				/* Problem: de-referencing float pointer as uint32_t breaks strict-aliasing rules for C++ and C, even if it normally works
				 *   uint32_t val = bswap32(*(reinterpret_cast<const uint32_t *>(&f)));
				 *   return *(reinterpret_cast<float *>(&val));
				 */
				// memcpy approach is guaranteed to work in C & C++ and fn calls should be optimized out:
				uint32_t asInt;
				std::memcpy(&asInt, reinterpret_cast<const void *>(&ByteValue), sizeof(uint32_t));
				asInt = Byteswap(asInt);
				std::memcpy(&ByteValue, reinterpret_cast<void *>(&asInt), sizeof(float));
				return ByteValue;
#else
				_Static_assert(sizeof(float) == sizeof(uint32_t), "Unexpected float format");
				// union approach is guaranteed to work in C99 and later (but not in C++, though in practice it normally will):
				union { uint32_t asInt; float asFloat; } conversion_union;
				conversion_union.asFloat = ByteValue;
				conversion_union.asInt = Byteswap(conversion_union.asInt);
				return conversion_union.asFloat;
#endif
			}

			static inline double Byteswap(double ByteValue) noexcept
			{
#ifdef __cplusplus
				static_assert(sizeof(double) == sizeof(uint64_t), "Unexpected double format");
				uint64_t asInt;
				std::memcpy(&asInt, reinterpret_cast<const void *>(&ByteValue), sizeof(uint64_t));
				asInt = Byteswap(asInt);
				std::memcpy(&ByteValue, reinterpret_cast<void *>(&asInt), sizeof(double));
				return ByteValue;
#else
				_Static_assert(sizeof(double) == sizeof(uint64_t), "Unexpected double format");
				union { uint64_t asInt; double asDouble; } conversion_union;
				conversion_union.asDouble = ByteValue;
				conversion_union.asInt = Byteswap(conversion_union.asInt);
				return conversion_union.asDouble;
#endif
			}
		}

		template <class Type> requires std::is_integral_v<Type>
		[[nodiscard]] constexpr Type byteswap(const Type ByteValue) noexcept
		{
			using ThisType = std::remove_cvref_t<Type>;

			if constexpr (sizeof(ThisType) == 1)
			{
				return ByteValue;
			}
			else if constexpr (sizeof(ThisType) == 2)
			{
				return static_cast<ThisType>(Implementation::Byteswap(static_cast<std::uint16_t>(ByteValue)));
			}
			else if constexpr (sizeof(ThisType) == 4)
			{
				return static_cast<Type>(Implementation::Byteswap(static_cast<std::uint32_t>(ByteValue)));
			}
			else if constexpr (sizeof(ThisType) == 8)
			{
				return static_cast<ThisType>(Implementation::Byteswap(static_cast<std::uint64_t>(ByteValue)));
			}
			else if constexpr (std::same_as<ThisType, float>)
			{
				return static_cast<Type>(Implementation::Byteswap(static_cast<float>(ByteValue)));
			}
			else if constexpr (std::same_as<ThisType, double>)
			{
				return static_cast<Type>(Implementation::Byteswap(static_cast<double>(ByteValue)));
			}
			else
			{
				static_assert(CommonToolkit::Dependent_Always_Failed<ThisType>, "Unexpected integer size");
			}
		}
	}

	#endif
	
	#if defined(MEMORY_DATA_TYPE_PACKER_AND_UNPACKER)

	class MemoryDataFormatExchange
	{

	private:
		std::array<std::uint8_t, 2> twobyte_array { 0, 0 };
		std::array<std::uint8_t, 4> fourbyte_array { 0, 0, 0, 0 };
		std::array<std::uint8_t, 8> eightbyte_array { 0, 0, 0, 0, 0, 0, 0, 0 };

	public:
		std::uint16_t Packer_2Byte(std::span<const std::uint8_t> bytes)
		{
			my_cpp2020_assert(bytes.size() == 2, "The required byte array size is 2", std::source_location::current());

			#if 0

			auto ValueA = bytes.operator[](0);
			auto ValueB = bytes.operator[](1);

			std::uint16_t integer = ValueA & 0xFF;
			integer |= ((static_cast<std::uint16_t>(ValueB) << 8) & 0xFF00);

			#else

			std::uint16_t integer = 0;
			std::memcpy(&integer, bytes.data(), bytes.size_bytes());

			#endif

			if constexpr(std::endian::native == std::endian::big)
			{
				#if __cpp_lib_byteswap

				integer = std::byteswap(integer);

				#else

				integer = ByteSwap::byteswap(integer);

				#endif
			}

			return integer;
		}

		std::span<std::uint8_t> Unpacker_2Byte(std::uint16_t integer)
		{
			if constexpr(std::endian::native == std::endian::big)
			{
				#if __cpp_lib_byteswap

				integer = std::byteswap(integer);

				#else

				integer = ByteSwap::byteswap(integer);

				#endif
			}

			#if 0

			twobyte_array.fill(0);
			std::span<std::uint8_t> bytes { twobyte_array };
			bytes.operator[](0) = (integer & 0x000000FF);
			bytes.operator[](1) = (integer & 0x0000FF00) >> 8;

			#else

			std::span<std::uint8_t> bytes { twobyte_array };
			std::memcpy(bytes.data(), &integer, bytes.size_bytes());

			#endif

			return bytes;
		}

		std::uint32_t Packer_4Byte(std::span<const std::uint8_t> bytes)
		{
			my_cpp2020_assert(bytes.size() == 4, "The required byte array size is 4", std::source_location::current());

			#if 0

			auto ValueA = bytes.operator[](0);
			auto ValueB = bytes.operator[](1);
			auto ValueC = bytes.operator[](2);
			auto ValueD = bytes.operator[](3);

			std::uint32_t integer = ValueA & 0xFF;
			integer |= ((static_cast<std::uint32_t>(ValueB) << 8) & 0xFF00);
			integer |= ((static_cast<std::uint32_t>(ValueC) << 16) & 0xFF0000);
			integer |= ((static_cast<std::uint32_t>(ValueD) << 24) & 0xFF000000);

			#else

			std::uint32_t integer = 0;
			std::memcpy(&integer, bytes.data(), bytes.size_bytes());

			#endif

			if constexpr(std::endian::native == std::endian::big)
			{
				#if __cpp_lib_byteswap

				integer = std::byteswap(integer);

				#else

				integer = ByteSwap::byteswap(integer);

				#endif
			}

			return integer;
		}

		std::span<std::uint8_t> Unpacker_4Byte(std::uint32_t integer)
		{
			if constexpr(std::endian::native == std::endian::big)
			{
				#if __cpp_lib_byteswap

				integer = std::byteswap(integer);

				#else

				integer = ByteSwap::byteswap(integer);

				#endif
			}

			#if 0

			fourbyte_array.fill(0);
			std::span<std::uint8_t> bytes { fourbyte_array };
			bytes.operator[](0) = (integer & 0x000000FF);
			bytes.operator[](1) = (integer & 0x0000FF00) >> 8;
			bytes.operator[](2) = (integer & 0x00FF0000) >> 16;
			bytes.operator[](3) = (integer & 0xFF000000) >> 24;

			#else

			std::span<std::uint8_t> bytes { fourbyte_array };
			std::memcpy(bytes.data(), &integer, bytes.size_bytes());

			#endif

			return bytes;
		}

		std::uint64_t Packer_8Byte(std::span<const std::uint8_t> bytes)
		{
			my_cpp2020_assert(bytes.size() == 8, "The required byte array size is 8", std::source_location::current());

			#if 0

			auto ValueA = bytes.operator[](0);
			auto ValueB = bytes.operator[](1);
			auto ValueC = bytes.operator[](2);
			auto ValueD = bytes.operator[](3);
			auto ValueE = bytes.operator[](4);
			auto ValueF = bytes.operator[](5);
			auto ValueG = bytes.operator[](6);
			auto ValueH = bytes.operator[](7);

			std::uint64_t integer = ValueA & 0xFF;
			integer |= ((static_cast<std::uint64_t>(ValueB) << 8) & 0xFF00);
			integer |= ((static_cast<std::uint64_t>(ValueC) << 16) & 0xFF0000);
			integer |= ((static_cast<std::uint64_t>(ValueD) << 24) & 0xFF000000);
			integer |= ((static_cast<std::uint64_t>(ValueE) << 32) & 0xFF00000000);
			integer |= ((static_cast<std::uint64_t>(ValueF) << 40) & 0xFF0000000000);
			integer |= ((static_cast<std::uint64_t>(ValueG) << 48) & 0xFF000000000000);
			integer |= ((static_cast<std::uint64_t>(ValueH) << 56) & 0xFF00000000000000);

			#else

			std::uint64_t integer = 0;
			std::memcpy(&integer, bytes.data(), bytes.size_bytes());

			#endif

			if constexpr(std::endian::native == std::endian::big)
			{
				#if __cpp_lib_byteswap

				integer = std::byteswap(integer);

				#else

				integer = ByteSwap::byteswap(integer);

				#endif
			}

			return integer;
		}

		std::span<std::uint8_t> Unpacker_8Byte(std::uint64_t integer)
		{
			if constexpr(std::endian::native == std::endian::big)
			{
				#if __cpp_lib_byteswap

				integer = std::byteswap(integer);

				#else

				integer = ByteSwap::byteswap(integer);

				#endif
			}

			#if 0

			eightbyte_array.fill(0);
			std::span<std::uint8_t> bytes { eightbyte_array };
			bytes.operator[](0) = (integer & 0x00000000000000FF);
			bytes.operator[](1) = (integer & 0x000000000000FF00) >> 8;
			bytes.operator[](2) = (integer & 0x0000000000FF0000) >> 16;
			bytes.operator[](3) = (integer & 0x00000000FF000000) >> 24;
			bytes.operator[](4) = (integer & 0x000000FF00000000) >> 32;
			bytes.operator[](5) = (integer & 0x0000FF0000000000) >> 40;
			bytes.operator[](6) = (integer & 0x00FF000000000000) >> 48;
			bytes.operator[](7) = (integer & 0xFF00000000000000) >> 56;

			#else

			std::span<std::uint8_t> bytes { eightbyte_array };
			std::memcpy(bytes.data(), &integer, bytes.size_bytes());

			#endif

			return bytes;
		}

		MemoryDataFormatExchange() = default;
		~MemoryDataFormatExchange() = default;

	};

	template<typename IntegerType, typename ByteType>
	concept BytesExchangeIntegersConecpt = std::is_integral_v<std::remove_cvref_t<IntegerType>> && std::is_same_v<std::remove_cvref_t<ByteType>, unsigned char> || std::is_same_v<std::remove_cvref_t<ByteType>, std::byte>;

	/*

		//Example Code:

		std::deque<unsigned char> Word;

		unsigned int InputWord = 0;
		unsigned int OutputWord = 0;
		std::vector<std::byte> bytes
		{
			static_cast<std::byte>(Word.operator[](0)),
			static_cast<std::byte>(Word.operator[](1)),
			static_cast<std::byte>(Word.operator[](2)),
			static_cast<std::byte>(Word.operator[](3))
		};

		std::span<std::byte> byteSpan{ bytes.begin(), bytes.end() };
		CommonToolkit::MessagePacking<unsigned int>(byteSpan, &InputWord);

		OutputWord = (InputWord << 8) | (InputWord >> 24);

		std::vector<unsigned int> words
		{
			OutputWord
		};
		std::span<unsigned int> wordSpan{ words };
		CommonToolkit::MessageUnpacking<unsigned int>(wordSpan, bytes.data());

		Word.operator[](0) = static_cast<unsigned char>(bytes.operator[](0));
		Word.operator[](1) = static_cast<unsigned char>(bytes.operator[](1));
		Word.operator[](2) = static_cast<unsigned char>(bytes.operator[](2));
		Word.operator[](3) = static_cast<unsigned char>(bytes.operator[](3));

		bytes.clear();
		words.clear();

	*/

	template<typename IntegerType, typename ByteType>
	requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
	void MessagePacking(const std::span<const ByteType>& input, IntegerType* output)
	{
		if constexpr((std::endian::native != std::endian::big) && (std::endian::native != std::endian::little))
		{
			throw std::invalid_argument("The byte order of your system's devices is unknown!");
		}
		
		if(input.size() % sizeof(IntegerType) != 0)
		{
			throw std::length_error("The size of the data must be aligned with the size of the type!");
		}

		if(output == nullptr)
		{
			throw std::logic_error("The target of the copied byte must not be a null pointer!");
		}

		constexpr bool whether_not_need_byteswap = (std::endian::native == std::endian::little);

		if constexpr (whether_not_need_byteswap)
		{
			std::memcpy(output, input.data(), input.size());
		}
		else
		{
			auto begin = input.data();
			auto end = input.data() + input.size();
			for (auto iterator = begin; iterator != end; iterator += sizeof(IntegerType))
			{
				IntegerType value;
				std::memcpy(&value, iterator, sizeof(IntegerType));

				#if __cpp_lib_byteswap

				*output++ = std::byteswap(value);

				#else

				*output++ = ByteSwap::byteswap(value);

				#endif
			}
		}
	}

	template<typename IntegerType, typename ByteType>
	requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
	std::vector<IntegerType> MessagePacking(const ByteType* input_pointer, std::size_t input_size)
	{
		if constexpr((std::endian::native != std::endian::big) && (std::endian::native != std::endian::little))
		{
			std::cout << "The byte order of your system's devices is unknown!" << std::endl;
			throw std::invalid_argument("");
		}

		if(input_pointer == nullptr)
			throw std::logic_error("The source of the copied byte must not be a null pointer!");

		if(input_size == 0)
			throw std::logic_error("The source size of the copied bytes cannot be 0!");
		else if (input_size % sizeof(IntegerType) != 0)
			throw std::length_error("The size of the data must be aligned with the size of the type!");
		else
		{
			std::vector<IntegerType> output_vector(input_size / sizeof(IntegerType), 0);

			std::memcpy(output_vector.data(), input_pointer, input_size);

			constexpr bool whether_need_byteswap = (std::endian::native == std::endian::big);

			if constexpr(whether_need_byteswap)
			{
				std::span<IntegerType> temporary_span { output_vector.data(), output_vector.size() };

				for(auto& temporary_value : temporary_span )
				{
					#if __cpp_lib_byteswap

					input_value = std::byteswap(value);

					#else

					temporary_value = ByteSwap::byteswap(temporary_value);

					#endif
				}
			}

			return output_vector;
		}
	}

	/*

		//Example Code:

		std::deque<unsigned char> Word;

		unsigned int InputWord = 0;
		unsigned int OutputWord = 0;
		std::vector<std::byte> bytes
		{
			static_cast<std::byte>(Word.operator[](0)),
			static_cast<std::byte>(Word.operator[](1)),
			static_cast<std::byte>(Word.operator[](2)),
			static_cast<std::byte>(Word.operator[](3))
		};

		std::span<std::byte> byteSpan{ bytes.begin(), bytes.end() };
		CommonToolkit::MessagePacking<unsigned int>(byteSpan, &InputWord);

		OutputWord = (InputWord << 8) | (InputWord >> 24);

		std::vector<unsigned int> words
		{
			OutputWord
		};
		std::span<unsigned int> wordSpan{ words };
		CommonToolkit::MessageUnpacking<unsigned int>(wordSpan, bytes.data());

		Word.operator[](0) = static_cast<unsigned char>(bytes.operator[](0));
		Word.operator[](1) = static_cast<unsigned char>(bytes.operator[](1));
		Word.operator[](2) = static_cast<unsigned char>(bytes.operator[](2));
		Word.operator[](3) = static_cast<unsigned char>(bytes.operator[](3));

		bytes.clear();
		words.clear();

	*/

	template<typename IntegerType, typename ByteType>
	requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
	void MessageUnpacking(const std::span<const IntegerType>& input, ByteType* output)
	{
		if constexpr((std::endian::native != std::endian::big) && (std::endian::native != std::endian::little))
		{
			std::cout << "The byte order of your system's devices is unknown!" << std::endl;
			throw std::invalid_argument("");
		}
		
		if(output == nullptr)
		{
			throw std::logic_error("The target of the copied byte must not be a null pointer!");
		}

		constexpr bool whether_not_need_byteswap = (std::endian::native == std::endian::little);

		if constexpr (whether_not_need_byteswap)
		{
			std::memcpy(output, input.data(), input.size() * sizeof(IntegerType));
		}
		else
		{
			// intentional copy
			for (IntegerType value : input)
			{
				#if __cpp_lib_byteswap

				value = std::byteswap(value);

				#else

				value = ByteSwap::byteswap(value);

				#endif

				std::memcpy(output, &value, sizeof(IntegerType));
				output += sizeof(IntegerType);
			}
		}
	}

	template<typename IntegerType, typename ByteType>
	requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
	std::vector<ByteType> MessageUnpacking(const IntegerType* input_pointer, std::size_t input_size)
	{
		if constexpr((std::endian::native != std::endian::big) && (std::endian::native != std::endian::little))
		{
			std::cout << "The byte order of your system's devices is unknown!" << std::endl;
			throw std::invalid_argument("");
		}

		if(input_pointer == nullptr)
			throw std::logic_error("The source of the copied byte must not be a null pointer!");

		if(input_size == 0)
			throw std::logic_error("The source size of the copied bytes cannot be 0!");
		else
		{
			std::vector<IntegerType> temporary_vector(input_pointer, input_pointer + input_size);

			constexpr bool whether_need_byteswap = (std::endian::native == std::endian::big);

			if constexpr(whether_need_byteswap)
			{
				std::span<IntegerType> temporary_span { temporary_vector.begin(), temporary_vector.end() };

				for(auto& temporary_value : temporary_span )
				{
					#if __cpp_lib_byteswap

					input_value = std::byteswap(value);

					#else

					temporary_value = ByteSwap::byteswap(temporary_value);

					#endif
				}

				std::vector<ByteType> output_vector(input_size * sizeof(IntegerType), 0);

				std::memcpy(output_vector.data(), temporary_vector.data(), output_vector.size());

				return output_vector;
			}
			else
			{
				std::vector<ByteType> output_vector(input_size * sizeof(IntegerType), 0);

				std::memcpy(output_vector.data(), input_pointer, output_vector.size());

				return output_vector;
			}
		}
	}

	template <typename ByteType, std::size_t Size>
	requires std::is_same_v<std::remove_cvref_t<ByteType>, unsigned char> || std::is_same_v<std::remove_cvref_t<ByteType>, std::byte>
	auto bytes_order_fixup(std::span<const ByteType> bytes)
	{
		auto buffer_bytes = std::array<ByteType, Size>{};
		if constexpr (std::endian::native == std::endian::little)
			std::copy(bytes.data(), bytes.data() + Size, buffer_bytes.data());
		else
			std::reverse_copy(bytes.data(), bytes.data() + Size, buffer_bytes.data());
		return buffer_bytes;
	}

	template <typename IntegerType, typename ByteType>
	requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
	auto value_to_bytes(const IntegerType& value)
	{
		auto bytes = std::array<ByteType, sizeof(IntegerType)>{};
		std::memcpy(bytes.data(), &value, sizeof(IntegerType));
		return bytes_order_fixup<ByteType, sizeof(IntegerType)>(bytes);
	}

	template <typename IntegerType, typename ByteType>
	requires BytesExchangeIntegersConecpt<IntegerType, ByteType>
	auto value_from_bytes(std::span<const ByteType> bytes)
	{
		my_cpp2020_assert(bytes.size() == sizeof(IntegerType), "", std::source_location::current());
		auto buffer_bytes = bytes_order_fixup<ByteType, sizeof(IntegerType)>(bytes);
		auto value = IntegerType{};
		std::memcpy(&value, buffer_bytes.data(), sizeof(IntegerType));
		return value;
	}

	#endif

	#if defined(BYTE_SWAP_FUNCTON)
	#undef BYTE_SWAP_FUNCTON
	#endif // !BYTE_SWAP_FUNCTON

	#if defined(MEMORY_DATA_TYPE_PACKER_AND_UNPACKER)
	#undef MEMORY_DATA_TYPE_PACKER_AND_UNPACKER
	#endif // !MEMORY_DATA_TYPE_PACKER_AND_UNPACKER

	#if defined(INTEGER_PACKCATION_OLD)
	#undef INTEGER_PACKCATION_OLD
	#endif // !INTEGER_PACKCATION_OLD

	#if defined(INTEGER_UNPACKCATION_OLD)
	#undef INTEGER_UNPACKCATION_OLD
	#endif // !INTEGER_UNPACKCATION_OLD
}

#endif //ALGORITHM_OALDRESPUZZLECRYPTIC_SUPPORTBASEFUNCTIONS_HPP