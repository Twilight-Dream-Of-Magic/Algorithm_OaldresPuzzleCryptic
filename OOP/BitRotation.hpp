#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_BITROTATION_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_BITROTATION_HPP

// Define a macro to check C++ version
#if __cplusplus >= 202002L
#define CPP20
#elif __cplusplus >= 201703L
#define CPP17
#elif __cplusplus >= 201402L
#define CPP14
#elif __cplusplus >= 201103L
#define CPP11
#else
#error A C++11 compiler is required!
#endif

#ifdef CPP20 // If C++20 is supported
#include <bit> // Use the <bit> header for bit manipulation
#else // If C++20 is not supported
#include <type_traits> // Use the <type_traits> header for type traits
#endif

#include <limits> // For CHAR_BIT

namespace TwilightDreamOfMagical::BaseOperation
{
	// Define a template function for left rotation
	template<typename T>
	T rotate_left(T x, unsigned int n)
	{
		static_assert(std::is_unsigned<T>::value, "T must be an unsigned type"); // Check if T is unsigned
#ifdef CPP20 // If C++20 is supported
		return std::rotl(x, n); // Use the std::rotl function for left rotation
#else // If C++20 is not supported
		return (x << n) | (x >> (std::numeric_limits<std::uint8_t>::digits * sizeof(x) - n)); // Use bit shift and OR operations for left rotation
#endif
	}

// Define a template function for right rotation
	template<typename T>
	T rotate_right(T x, unsigned int n)
	{
		static_assert(std::is_unsigned<T>::value, "T must be an unsigned type"); // Check if T is unsigned
#ifdef CPP20 // If C++20 is supported
		return std::rotr(x, n); // Use the std::rotr function for right rotation
#else // If C++20 is not supported
		return (x >> n) | (x << (std::numeric_limits<std::uint8_t>::digits * sizeof(x) - n)); // Use bit shift and OR operations for right rotation
#endif
	}
}

#if !defined(CPP20)

namespace std
{
	template<typename T>
	T rotl(T x, unsigned int n)
	{
		return TwilightDreamOfMagical::BaseOperation::rotate_left(x, n);
	}
	
	template<typename T>
	T rotr(T x, unsigned int n)
	{
		return TwilightDreamOfMagical::BaseOperation::rotate_right(x, n);
	}
}

#enif

#endif //ALGORITHM_OALDRESPUZZLECRYPTIC_BITROTATION_HPP

#if defined(CPP20)
#undef CPP20
#endif
#if defined(CPP17)
#undef CPP17
#endif
#if defined(CPP14)
#undef CPP14
#endif
#if defined(CPP11)
#undef CPP11
#endif

#endif