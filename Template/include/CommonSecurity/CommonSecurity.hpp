/*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * 本文件是 TDOM-EncryptOrDecryptFile-Reborn 的一部分。
 *
 * TDOM-EncryptOrDecryptFile-Reborn 是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是（按你的决定）任何以后版都可以。
 *
 * 发布 TDOM-EncryptOrDecryptFile-Reborn 是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的复本。如果没有，请看 <https://www.gnu.org/licenses/>。
 */
 
 /*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * This file is part of TDOM-EncryptOrDecryptFile-Reborn.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

//通用安全工具
//Common Security Tools
namespace CommonSecurity
{
	template<std::integral DataType>
	struct UniformRandomBitGenerator
	{
		using result_type = DataType;

		static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }
		static constexpr result_type min() { return std::numeric_limits<result_type>::min(); }
	};

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
			return (NumberValue << RotationCount) | (NumberValue >> BitDigits - RotationCount);
		else if(static_cast<std::int64_t>(RotationCount) < 0)
		{
			RotationCount = ~RotationCount + 1;
			return (NumberValue << RotationCount) | (NumberValue >> BitDigits - RotationCount);
		}
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
			return (NumberValue >> RotationCount) | (NumberValue << BitDigits - RotationCount);
		else if(static_cast<std::int64_t>(RotationCount) < 0)
		{
			RotationCount = ~RotationCount + 1;
			return (NumberValue >> RotationCount) | (NumberValue << BitDigits - RotationCount);
		}
	}

	template<typename ByteType>
	requires std::is_same_v<ByteType, std::uint8_t> || std::is_same_v<ByteType, std::byte>
	class GaloisFiniteField256
	{

	private:
		static constexpr std::array<unsigned char, 256> LogarithmicTable
		{
			0x00, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1a, 0xc6,
			0x03, 0xdf, 0x33, 0xee, 0x1b, 0x68, 0xc7, 0x4b,
			0x04, 0x64, 0xe0, 0x0e, 0x34, 0x8d, 0xef, 0x81,
			0x1c, 0xc1, 0x69, 0xf8, 0xc8, 0x08, 0x4c, 0x71,
			0x05, 0x8a, 0x65, 0x2f, 0xe1, 0x24, 0x0f, 0x21,
			0x35, 0x93, 0x8e, 0xda, 0xf0, 0x12, 0x82, 0x45,
			0x1d, 0xb5, 0xc2, 0x7d, 0x6a, 0x27, 0xf9, 0xb9,
			0xc9, 0x9a, 0x09, 0x78, 0x4d, 0xe4, 0x72, 0xa6,
			0x06, 0xbf, 0x8b, 0x62, 0x66, 0xdd, 0x30, 0xfd,
			0xe2, 0x98, 0x25, 0xb3, 0x10, 0x91, 0x22, 0x88,
			0x36, 0xd0, 0x94, 0xce, 0x8f, 0x96, 0xdb, 0xbd,
			0xf1, 0xd2, 0x13, 0x5c, 0x83, 0x38, 0x46, 0x40,
			0x1e, 0x42, 0xb6, 0xa3, 0xc3, 0x48, 0x7e, 0x6e,
			0x6b, 0x3a, 0x28, 0x54, 0xfa, 0x85, 0xba, 0x3d,
			0xca, 0x5e, 0x9b, 0x9f, 0x0a, 0x15, 0x79, 0x2b,
			0x4e, 0xd4, 0xe5, 0xac, 0x73, 0xf3, 0xa7, 0x57,
			0x07, 0x70, 0xc0, 0xf7, 0x8c, 0x80, 0x63, 0x0d,
			0x67, 0x4a, 0xde, 0xed, 0x31, 0xc5, 0xfe, 0x18,
			0xe3, 0xa5, 0x99, 0x77, 0x26, 0xb8, 0xb4, 0x7c,
			0x11, 0x44, 0x92, 0xd9, 0x23, 0x20, 0x89, 0x2e,
			0x37, 0x3f, 0xd1, 0x5b, 0x95, 0xbc, 0xcf, 0xcd,
			0x90, 0x87, 0x97, 0xb2, 0xdc, 0xfc, 0xbe, 0x61,
			0xf2, 0x56, 0xd3, 0xab, 0x14, 0x2a, 0x5d, 0x9e,
			0x84, 0x3c, 0x39, 0x53, 0x47, 0x6d, 0x41, 0xa2,
			0x1f, 0x2d, 0x43, 0xd8, 0xb7, 0x7b, 0xa4, 0x76,
			0xc4, 0x17, 0x49, 0xec, 0x7f, 0x0c, 0x6f, 0xf6,
			0x6c, 0xa1, 0x3b, 0x52, 0x29, 0x9d, 0x55, 0xaa,
			0xfb, 0x60, 0x86, 0xb1, 0xbb, 0xcc, 0x3e, 0x5a,
			0xcb, 0x59, 0x5f, 0xb0, 0x9c, 0xa9, 0xa0, 0x51,
			0x0b, 0xf5, 0x16, 0xeb, 0x7a, 0x75, 0x2c, 0xd7,
			0x4f, 0xae, 0xd5, 0xe9, 0xe6, 0xe7, 0xad, 0xe8,
			0x74, 0xd6, 0xf4, 0xea, 0xa8, 0x50, 0x58, 0xaf
		};

		static constexpr std::array<unsigned char, 256> ExponentialTable
		{
			0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
			0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26,
			0x4c, 0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9,
			0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0,
			0x9d, 0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35,
			0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23,
			0x46, 0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0,
			0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1,
			0x5f, 0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc,
			0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0,
			0xfd, 0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f,
			0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2,
			0xd9, 0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88,
			0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce,
			0x81, 0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93,
			0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc,
			0x85, 0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9,
			0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54,
			0xa8, 0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa,
			0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73,
			0xe6, 0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e,
			0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff,
			0xe3, 0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4,
			0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41,
			0x82, 0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e,
			0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6,
			0x51, 0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef,
			0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09,
			0x12, 0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5,
			0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16,
			0x2c, 0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83,
			0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e, 0x00
		};


		GaloisFiniteField256() = default;

	public:
		ByteType addition_or_subtraction(ByteType left, ByteType right)
		{
			return left ^ right;
		}

		ByteType multiplication(ByteType left, ByteType right)
		{
			if( left == static_cast<ByteType>(0x00) || right == static_cast<ByteType>(0x00) )
				return static_cast<ByteType>(0x00);
			
			auto integer_a = static_cast<std::uint32_t>(left);
			auto integer_b = static_cast<std::uint32_t>(right);

			integer_a = static_cast<std::uint32_t>( LogarithmicTable[integer_a] );
			integer_b = static_cast<std::uint32_t>( LogarithmicTable[integer_b] );

			auto value = (integer_a + integer_b) % 255;

			return static_cast<ByteType>( ExponentialTable[value] );
		}

		ByteType division(ByteType left, ByteType right)
		{
			if( left == static_cast<ByteType>(0x00) )
				return static_cast<ByteType>(0x00);

			if( right == static_cast<ByteType>(0x00) )
				my_cpp2020_assert( false, "GaloisFiniteField256: divide by zero", std::source_location::current() );
			
			auto integer_a = static_cast<std::uint32_t>(left);
			auto integer_b = static_cast<std::uint32_t>(right);

			integer_a = static_cast<std::uint32_t>( LogarithmicTable[integer_a] );
			integer_b = static_cast<std::uint32_t>( LogarithmicTable[integer_b] );

			auto value = static_cast<std::int32_t>(integer_a - integer_b) % 255;
			if(value < 0)
				value += 255;

			return static_cast<ByteType>( ExponentialTable[value] );
		}

		// Returns the value of the polynomial for the given index_value.
		static ByteType evaluation_polynomials(GaloisFiniteField256& this_instance, std::vector<ByteType> polynomials, ByteType index_value)
		{
			ByteType result { 0 };
			
			// special case the origin
			if(index_value == static_cast<ByteType>(0x00))
			{
				return polynomials[0];
			}
			
			// compute the polynomial value using Horner's method.
			for(std::int32_t index = polynomials.size() - 1; index >= 0; index--)
			{
				// do multiplication then addition
				result = this_instance.addition_or_subtraction( this_instance.multiplication(result, index_value), polynomials[index] );
			}

			return result;
		}

		// Using the computed Lagrangian function(0), N sample points are extracted and the interpolated values of the given byte_points are returned.
		static ByteType polynomial_interpolation(GaloisFiniteField256& this_instance, std::vector<std::vector<ByteType>> byte_points)
		{
			const ByteType input_value { 0 };
			ByteType output_value { 0 };

			for(std::size_t round = 0; round < byte_points.size(); round++)
			{
				const ByteType axis_x_from_a = byte_points[round][0];
				const ByteType axis_y_from_a = byte_points[round][1];
				
				ByteType lagrangian_basis_value { 1 };

				for(std::size_t round2 = 0; round2 < byte_points.size(); round2++)
				{
					const ByteType axis_x_from_b = byte_points[round2][0];

					if(round != round2)
					{
						// do subtraction then division
						auto that_number = this_instance.addition_or_subtraction(input_value, axis_x_from_b);
						auto denominator_of_that_number = this_instance.addition_or_subtraction(axis_x_from_a, axis_x_from_b);
						auto quotient = this_instance.division(that_number, denominator_of_that_number);

						// do multiplication
						lagrangian_basis_value = this_instance.multiplication(lagrangian_basis_value, quotient);
					}
				}

				// do multiplication then addition
				output_value = this_instance.addition_or_subtraction(output_value, this_instance.multiplication(lagrangian_basis_value, axis_y_from_a) );
			}

			return output_value;
		}

		static GaloisFiniteField256& get_instance()
		{
			static GaloisFiniteField256 instance = GaloisFiniteField256();
			return instance;
		}

		~GaloisFiniteField256() = default;
	};

	//随机数分布的功能库
	//Function library for random number distribution
	namespace RND
	{
		template <class _Elem, class _Traits>
		std::basic_ostream<_Elem, _Traits>&
		DataType_ValueWrite( std::basic_ostream<_Elem, _Traits>& Os, long double _DataValue_ )
		{
			constexpr long double _TwoPower31_ = 2147483648.0L;
			constexpr int _Nwords = 4;
			
			// write long double to stream
			int			_Ex;
			long double _Fraction_ = ::frexpl( _DataValue_, &_Ex );
			for ( int _Nw = 0; _Nw < _Nwords; ++_Nw )
			{  // break into 31-bit words
				_Fraction_ *= _TwoPower31_;
				long _Digits = static_cast<long>( _Fraction_ );
				_Fraction_ -= _Digits;
				Os << ' ' << _Digits;
			}
			Os << ' ' << _Ex;
			return Os;
		}

		template <class _Elem, class _Traits>
		std::basic_istream<_Elem, _Traits>&
		DataType_ValueRead( std::basic_istream<_Elem, _Traits>& Is, long double& _DataValue_ )
		{
			constexpr long double _TwoPower31_ = 2147483648.0L;
			constexpr int _Nwords = 4;
			
			// read long double from stream
			long double _Fraction_ = 0.0;
			long		_Digits_;
			for ( int _Nw = 0; _Nw < _Nwords; ++_Nw )
			{  // accumulate 31-bit words
				Is >> _Digits_;
				long double _TemporaryRealFloatingValue_ = _Digits_ / _TwoPower31_;
				for ( int Index = 0; Index < _Nw; ++Index )
				{
					_TemporaryRealFloatingValue_ /= _TwoPower31_;
				}

				_Fraction_ += _TemporaryRealFloatingValue_;
			}
			Is >> _Digits_;
			_DataValue_ = ::ldexpl( _Fraction_, _Digits_ );
			return Is;
		}

		template <class _Elem, class _Traits, class _DataType_>
		std::basic_istream<_Elem, _Traits>&
		DataType_ValueIn( std::basic_istream<_Elem, _Traits>& Is, _DataType_& _DataValue_ )
		{
			// read from stream
			long double _Value_;
			_DataType_	_Max = ( std::numeric_limits<_DataType_>::max )();
			DataType_ValueRead( Is, _Value_ );
			if ( ::fabsl( _Value_ ) <= _Max )
			{
				_DataValue_ = static_cast<_DataType_>( _Value_ );
			}
			else if ( _Value_ < 0 )
			{
				_DataValue_ = -_Max;
			}
			else
			{
				_DataValue_ = _Max;
			}

			return Is;
		}

		template <class _Elem, class _Traits, class _DataType_>
		std::basic_ostream<_Elem, _Traits>&
		DataType_ValueOut( std::basic_ostream<_Elem, _Traits>& Os, _DataType_ _DataValue_ )
		{
			// write to stream
			return DataType_ValueWrite( Os, _DataValue_ );
		}
		
		[[nodiscard]] constexpr int
		DoGenerateCanonicalIterations( const int Bits, const uint64_t RNG_NumberMin, const uint64_t RNG_NumberMax )
		{
			//For a URBG type `RNG_Type` with range == `(RNG_Type::max() - RNG_Type::min()) + 1`, returns the number of calls to generate at least Bits bits of entropy.
			//Specifically, max(1, ceil(_Bits / log2(range))).

			if ( Bits == 0 || ( RNG_NumberMax == std::numeric_limits<std::uint64_t>::max() && RNG_NumberMin == 0 ) )
			{
				return 1;
			}

			const auto RangeCount = ( RNG_NumberMax - RNG_NumberMin ) + 1;
			const auto Target = ~uint64_t { 0 } >> ( 64 - Bits );
			uint64_t   _Produce_ = 1;
			int		   _Ceil_ = 0;
			while ( _Produce_ <= Target )
			{
				++_Ceil_;
				if ( _Produce_ > std::numeric_limits<std::uint64_t>::max() / RangeCount )
				{
					break;
				}

				_Produce_ *= RangeCount;
			}

			return _Ceil_;
		}

		//从随机序列中建立一个浮点值
		//build a floating-point value from random sequence
		template <std::floating_point RealFloatingType, std::size_t Bits, class RNG_Type>
		[[nodiscard]] RealFloatingType
		GenerateCanonical( RNG_Type& RNG_Function )
		{
			constexpr auto Digits = static_cast<size_t>(std::numeric_limits<RealFloatingType>::digits );
			constexpr auto Minbits = static_cast<int>( Digits < Bits ? Digits : Bits );

			static_assert(0 <= Bits && Bits <= 64, "Number of invalid bits");

			constexpr auto RNG_NumberMin = static_cast<RealFloatingType>( ( RNG_Type::min )() );
			constexpr auto RNG_NumberMax = static_cast<RealFloatingType>( ( RNG_Type::max )() );
			constexpr auto RangeCount = ( RNG_NumberMax - RNG_NumberMin ) + RealFloatingType { 1.0 };

			constexpr int KTimes = DoGenerateCanonicalIterations( Minbits, ( RNG_Type::min )(), ( RNG_Type::max )() );

			RealFloatingType Answer { 0 };
			RealFloatingType Factor { 1 };

			for ( int Index = 0; Index < KTimes; ++Index )
			{
				// add in another set of bits
				Answer += ( static_cast<RealFloatingType>( RNG_Function() ) - RNG_NumberMin ) * Factor;
				Factor *= RangeCount;
			}

			return Answer / Factor;
		}

		template <class RNG_Type, class = void>
		struct HasStaticMinAndMax : std::false_type {};

		// This checks a requirement of N4901 [rand.req.urng] `concept uniform_random_bit_generator` but doesn't attempt
		// to implement the whole concept - we just need to distinguish Standard machinery from tr1 machinery.
		template <class RNG_Type>
		struct HasStaticMinAndMax<RNG_Type, std::void_t<decltype(std::bool_constant<(RNG_Type::min)() < (RNG_Type::max)()>::value)>> : std::true_type {};

		//从随机序列中建立一个浮点值
		// build a floating-point value from random sequence
		template <std::floating_point RealFloatingType, class RNG_Type>
		[[nodiscard]] RealFloatingType
		NRangeProbabilityEvaluation(RNG_Type& RNG_Function)
		{
			constexpr auto Digits  = static_cast<size_t>(std::numeric_limits<RealFloatingType>::digits);
			constexpr auto Bits    = ~size_t{0};
			constexpr auto Minbits = Digits < Bits ? Digits : Bits;

			if constexpr (HasStaticMinAndMax<RNG_Type>::value && Minbits <= 64)
			{
				return GenerateCanonical<RealFloatingType, Minbits>(RNG_Function);
			}
			else
			{
				// TRANSITION, for tr1 machinery only; Standard machinery can call generate_canonical directly
				constexpr auto RNG_NumberMin = static_cast<RealFloatingType>( ( RNG_Type::min )() );
				constexpr auto RNG_NumberMax = static_cast<RealFloatingType>( ( RNG_Type::max )() );
				constexpr auto RangeCount = ( RNG_NumberMax - RNG_NumberMin ) + RealFloatingType { 1.0 };

				const int _Ceil_ = static_cast<int>(::ceil(static_cast<RealFloatingType>(Minbits) / ::log2(RangeCount)));
				const int KTimes = _Ceil_ < 1 ? 1 : _Ceil_;

				RealFloatingType Answer { 0 };
				RealFloatingType Factor { 1 };

				for ( int Index = 0; Index < KTimes; ++Index )
				{
					// add in another set of bits
					Answer += ( static_cast<RealFloatingType>( RNG_Function() ) - RNG_NumberMin ) * Factor;
					Factor *= RangeCount;
				}

				return Answer / Factor;
			}
		}

		//将一个统一的随机数发生器包装成一个随机数发生器
		//Wrap a Uniform random number generator as an Random number generator
		template <class DifferenceType, class URNG_Type>
		requires std::uniform_random_bit_generator<std::remove_reference_t<URNG_Type>>
		class WARP_URNG_AS_AN_RNG
		{

		public:

			using Type0 = std::make_unsigned_t<DifferenceType>;
			using Type1 = typename URNG_Type::result_type;

			using UnsignedDifferenceType = std::conditional_t<sizeof( Type1 ) < sizeof( Type0 ), Type0, Type1>;

			explicit WARP_URNG_AS_AN_RNG( URNG_Type& RNG_Function )
				: URNG_TypeReference( RNG_Function ), RandomBits( CHAR_BIT * sizeof( UnsignedDifferenceType ) ), RandomBitMask( UnsignedDifferenceType( -1 ) )
			{
				for ( ; ( URNG_Type::max )() - ( URNG_Type::min )() < RandomBitMask; RandomBitMask >>= 1 )
				{
					--RandomBits;
				}
			}

			// adapt URNG_Type closed range to [0, DifferenceTypeIndex)
			DifferenceType operator()( DifferenceType DifferenceTypeIndex )
			{
				// try a sample random value
				for ( ;; )
				{
					UnsignedDifferenceType ResultObject = 0; // random bits
					UnsignedDifferenceType MaskInRange = 0; // 2^N - 1, ResultObject is within [0, MaskInRange]

					while ( MaskInRange < UnsignedDifferenceType( DifferenceTypeIndex - 1 ) )
					{
						// need more random bits
						ResultObject <<= RandomBits - 1;  // avoid full shift
						ResultObject <<= 1;
						ResultObject |= FindBits();
						MaskInRange <<= RandomBits - 1;	 // avoid full shift
						MaskInRange <<= 1;
						MaskInRange |= RandomBitMask;
					}

					// ResultObject is [0, MaskInRange], DifferenceTypeIndex - 1 <= MaskInRange, return if unbiased
					if ( ResultObject / DifferenceTypeIndex < MaskInRange / DifferenceTypeIndex || MaskInRange % DifferenceTypeIndex == UnsignedDifferenceType( DifferenceTypeIndex - 1 ) )
					{
						return static_cast<DifferenceType>( ResultObject % DifferenceTypeIndex );
					}
				}
			}

			UnsignedDifferenceType FindAllBits()
			{
				UnsignedDifferenceType ResultObject = 0;

				for ( size_t NumberIndex = 0; NumberIndex < CHAR_BIT * sizeof( UnsignedDifferenceType ); NumberIndex += RandomBits )
				{
					// don't mask away any bits
					ResultObject <<= RandomBits - 1; // avoid full shift
					ResultObject <<= 1;
					ResultObject |= FindBits();
				}

				return ResultObject;
			}

			WARP_URNG_AS_AN_RNG( const WARP_URNG_AS_AN_RNG& ) = delete;
			WARP_URNG_AS_AN_RNG& operator=( const WARP_URNG_AS_AN_RNG& ) = delete;

		private:

			// return a random value within [0, RandomBitMask]
			UnsignedDifferenceType FindBits()
			{
				for ( ;; )
				{
					// repeat until random value is in range
					UnsignedDifferenceType RandomValue = URNG_TypeReference() - ( URNG_Type::min )();

					if ( RandomValue <= RandomBitMask )
					{
						return RandomValue;
					}
				}
			}

			URNG_Type&			   URNG_TypeReference;	// reference to URNG
			size_t				   RandomBits;			// number of random bits generated by _Get_bits()
			UnsignedDifferenceType RandomBitMask;		// 2^RandomBits - 1
		};

		// uniform integer distribution base
		template <std::integral IntegerType>
		class UniformInteger
		{
		public:
			using result_type = IntegerType;

			// parameter package
			struct param_type
			{
				using distribution_type = UniformInteger;

				param_type()
				{
					InitialParamType( 0, 9 );
				}

				explicit param_type( result_type MinimumValue0, result_type MaximumValue0 = 9 )
				{
					InitialParamType( MinimumValue0, MaximumValue0 );
				}

				[[nodiscard]] friend bool operator==( const param_type& Left, const param_type& Right )
				{
					return Left.MinimumValue == Right.MinimumValue && Left.MaximumValue == Right.MaximumValue;
				}

			#if __cplusplus < 202002L
				[[nodiscard]] friend bool operator!=( const param_type& Left, const param_type& Right )
				{
					return !( Left == Right );
				}
			#endif

				[[nodiscard]] result_type a() const
				{
					return MinimumValue;
				}

				[[nodiscard]] result_type b() const
				{
					return MaximumValue;
				}

				void InitialParamType( IntegerType MinimumValue0, IntegerType MaximumValue0 )
				{
					// set internal state

					my_cpp2020_assert( MinimumValue0 <= MaximumValue0, "invalid min and max arguments for uniform_int", std::source_location::current() );

					MinimumValue = MinimumValue0;
					MaximumValue = MaximumValue0;
				}

				result_type MinimumValue;
				result_type MaximumValue;
			};

			UniformInteger() : ParamPackageObject( 0, 9 ) {}

			explicit UniformInteger( IntegerType MinimumValue0, IntegerType MaximumValue0 = 9 ) : ParamPackageObject( MinimumValue0, MaximumValue0 ) {}

			explicit UniformInteger( const param_type& ParamObject0 ) : ParamPackageObject( ParamObject0 ) {}

			[[nodiscard]] result_type a() const
			{
				return ParamPackageObject.a();
			}

			[[nodiscard]] result_type b() const
			{
				return ParamPackageObject.b();
			}

			[[nodiscard]] param_type param() const
			{
				return ParamPackageObject;
			}

			void param( const param_type& ParamObject0 )
			{
				// set parameter package
				ParamPackageObject = ParamObject0;
			}

			[[nodiscard]] result_type( min )() const
			{
				return ParamPackageObject.MinimumValue;
			}

			[[nodiscard]] result_type( max )() const
			{
				return ParamPackageObject.MaximumValue;
			}

			void reset() {}	 // clear internal state

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject ) const
			{
				return this->Evaluation( RNG_EngineObject, ParamPackageObject.MinimumValue, ParamPackageObject.MaximumValue );
			}

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject, const param_type& ParamObject0 ) const
			{
				return this->Evaluation( RNG_EngineObject, ParamObject0.MinimumValue, ParamObject0.MaximumValue );
			}

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject, result_type _Nx ) const
			{
				return this->Evaluation( RNG_EngineObject, 0, _Nx - 1 );
			}

			template <class _Elem, class _Traits>
			friend std::basic_istream<_Elem, _Traits>& operator>>( std::basic_istream<_Elem, _Traits>& Istr, UniformInteger& OperatedObject )
			{
				// read state from _Istr
				UniformInteger::result_type Min0;
				UniformInteger::result_type Max0;
				Istr >> Min0 >> Max0;
				OperatedObject.ParamPackageObject.InitialParamType( Min0, Max0 );
				return Istr;
			}

			template <class _Elem, class _Traits>
			friend std::basic_ostream<_Elem, _Traits>& operator<<( std::basic_ostream<_Elem, _Traits>& Ostr, const UniformInteger& OperatedObject )
			{
				// write state to _Ostr
				return Ostr << OperatedObject.ParamPackageObject.MinimumValue << ' ' << OperatedObject.ParamPackageObject.MaximumValue;
			}

		private:

			using UnsignedIntegerType = std::make_unsigned_t<IntegerType>;

			// compute next value in range [MinimumValue, MaximumValue]
			template <class RandomNumberGenerator_EngineType>
			result_type Evaluation( RandomNumberGenerator_EngineType& RNG_EngineObject, IntegerType MinimumValue, IntegerType MaximumValue ) const
			{
				WARP_URNG_AS_AN_RNG<UnsignedIntegerType, RandomNumberGenerator_EngineType> _Generator( RNG_EngineObject );

				const UnsignedIntegerType _UnsignedMinimunValue_ = AdjustNumber( static_cast<UnsignedIntegerType>( MinimumValue ) );
				const UnsignedIntegerType _UnsignedMaximunValue_ = AdjustNumber( static_cast<UnsignedIntegerType>( MaximumValue ) );

				UnsignedIntegerType UnsignedIntegerResult;

				if ( _UnsignedMaximunValue_ - _UnsignedMinimunValue_ == static_cast<UnsignedIntegerType>( -1 ) )
				{
					UnsignedIntegerResult = static_cast<UnsignedIntegerType>( _Generator.FindAllBits() );
				}
				else
				{
					UnsignedIntegerResult = static_cast<UnsignedIntegerType>( _Generator( static_cast<UnsignedIntegerType>( _UnsignedMaximunValue_ - _UnsignedMinimunValue_ + 1 ) ) );
				}

				return static_cast<IntegerType>( AdjustNumber( static_cast<UnsignedIntegerType>( UnsignedIntegerResult + _UnsignedMinimunValue_ ) ) );
			}

			// convert signed ranges to unsigned ranges and vice versa
			static UnsignedIntegerType AdjustNumber( UnsignedIntegerType UnsignedInegerValue )
			{
				if constexpr ( std::is_signed_v<IntegerType> )
				{
					const UnsignedIntegerType NumberAdjuster = ( static_cast<UnsignedIntegerType>( -1 ) >> 1 ) + 1;	 // 2^(N-1)

					if ( UnsignedInegerValue < NumberAdjuster )
					{
						return static_cast<UnsignedIntegerType>( UnsignedInegerValue + NumberAdjuster );
					}
					else
					{
						return static_cast<UnsignedIntegerType>( UnsignedInegerValue - NumberAdjuster );
					}
				}
				else
				{
					// IntegerType is already unsigned, do nothing
					return UnsignedInegerValue;
				}
			}

			param_type ParamPackageObject;
		};

		// uniform integer distribution
		template <class IntegerType>
		class UniformIntegerDistribution : public UniformInteger<IntegerType>
		{

		public:

			using _BaseType = UniformInteger<IntegerType>;
			using _ParamBaseType = typename _BaseType::param_type;
			using result_type = typename _BaseType::result_type;

			// parameter package
			struct param_type : _ParamBaseType
			{
				using distribution_type = UniformIntegerDistribution;

				param_type() : _ParamBaseType(0, (std::numeric_limits<IntegerType>::max)()) {}

				explicit param_type(result_type _Min0, result_type _Max0 = (std::numeric_limits<IntegerType>::max)()) : _ParamBaseType(_Min0, _Max0) {}

				param_type(const _ParamBaseType& OtherObject) : _ParamBaseType(OtherObject) {}
			};

			UniformIntegerDistribution() : _BaseType(0, (std::numeric_limits<IntegerType>::max)()) {}

			explicit UniformIntegerDistribution(IntegerType _Min0, IntegerType _Max0 = (std::numeric_limits<IntegerType>::max)()) : _BaseType(_Min0, _Max0) {}

			explicit UniformIntegerDistribution(const param_type& ParamObject) : _BaseType(ParamObject) {}

			[[nodiscard]] friend bool operator==(const UniformIntegerDistribution& Left, const UniformIntegerDistribution& Right)
			{
				return Left.param() == Right.param();
			}

		#if __cplusplus < 202002L
			[[nodiscard]] friend bool operator!=(const UniformIntegerDistribution& Left, const UniformIntegerDistribution& Right)
			{
				return !(Left == Right);
			}
		#endif

		};

		// uniform real number distribution base
		template <std::floating_point RealFloatingType>
		class UniformRealNumber
		{
		public:
			using result_type = RealFloatingType;

			// parameter package
			struct param_type
			{
				using distribution_type = UniformRealNumber;

				param_type()
				{
					InitialParamType( RealFloatingType{0.0}, RealFloatingType{1.0} );
				}

				explicit param_type( result_type MinimumValue0, result_type MaximumValue0 = 9 )
				{
					InitialParamType( MinimumValue0, MaximumValue0 );
				}

				[[nodiscard]] friend bool operator==( const param_type& Left, const param_type& Right )
				{
					return Left.MinimumValue == Right.MinimumValue && Left.MaximumValue == Right.MaximumValue;
				}

			#if __cplusplus < 202002L
				[[nodiscard]] friend bool operator!=( const param_type& Left, const param_type& Right )
				{
					return !( Left == Right );
				}
			#endif

				[[nodiscard]] result_type a() const
				{
					return MinimumValue;
				}

				[[nodiscard]] result_type b() const
				{
					return MaximumValue;
				}

				void InitialParamType( RealFloatingType MinimumValue0, RealFloatingType MaximumValue0 )
				{
					// set internal state

					my_cpp2020_assert
					( 
						MinimumValue0 <= MaximumValue0 && (0 <= MinimumValue0 || MaximumValue0 <= MinimumValue0 + (std::numeric_limits<RealFloatingType>::max)()),
						"invalid min and max arguments for uniform_real", 
						std::source_location::current() 
					);

					MinimumValue = MinimumValue0;
					MaximumValue = MaximumValue0;
				}

				result_type MinimumValue;
				result_type MaximumValue;
			};

			UniformRealNumber() : ParamPackageObject( RealFloatingType{0}, RealFloatingType{1} ) {}

			explicit UniformRealNumber( RealFloatingType MinimumValue0, RealFloatingType MaximumValue0 = 9 ) : ParamPackageObject( MinimumValue0, MaximumValue0 ) {}

			explicit UniformRealNumber( const param_type& ParamObject0 ) : ParamPackageObject( ParamObject0 ) {}

			[[nodiscard]] result_type a() const
			{
				return ParamPackageObject.a();
			}

			[[nodiscard]] result_type b() const
			{
				return ParamPackageObject.b();
			}

			[[nodiscard]] param_type param() const
			{
				return ParamPackageObject;
			}

			void param( const param_type& ParamObject0 )
			{
				// set parameter package
				ParamPackageObject = ParamObject0;
			}

			[[nodiscard]] result_type( min )() const
			{
				return ParamPackageObject.MinimumValue;
			}

			[[nodiscard]] result_type( max )() const
			{
				return ParamPackageObject.MaximumValue;
			}

			void reset() {}	 // clear internal state

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject ) const
			{
				return this->Evaluation( RNG_EngineObject, this->ParamPackageObject );
			}

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject, const param_type& ParamObject0 ) const
			{
				return this->Evaluation( RNG_EngineObject, ParamObject0 );
			}

			template <class _Elem, class _Traits>
			std::basic_istream<_Elem, _Traits>& Read( std::basic_istream<_Elem, _Traits>& Istr )
			{
				// read state from _Istr
				UniformRealNumber::result_type Min0;
				UniformRealNumber::result_type Max0;
				DataType_ValueIn( Istr, Min0 );
				DataType_ValueIn( Istr, Max0 );
				ParamPackageObject.InitialParamType( Min0, Max0 );
				return Istr;
			}

			template <class _Elem, class _Traits>
			std::basic_ostream<_Elem, _Traits>& Write( std::basic_ostream<_Elem, _Traits>& Ostr ) const
			{
				// write state to _Ostr
				DataType_ValueOut( Ostr, ParamPackageObject.MinimumValue );
				DataType_ValueOut( Ostr, ParamPackageObject.MaximumValue );
				return Ostr;
			}

			template <class _Elem, class _Traits>
			friend std::basic_istream<_Elem, _Traits>& operator>>( std::basic_istream<_Elem, _Traits>& Istr, UniformRealNumber& OperatedObject )
			{
				// read state from _Istr
				return OperatedObject.Read( Istr );
			}

			template <class _Elem, class _Traits>
			friend std::basic_ostream<_Elem, _Traits>& operator<<( std::basic_ostream<_Elem, _Traits>& Ostr, const UniformRealNumber& OperatedObject )
			{
				// write state to _Ostr
				return OperatedObject.Write( Ostr );
			}

		private:

			template <class RandomNumberGenerator_EngineType>
			result_type Evaluation( RandomNumberGenerator_EngineType& RNG_EngineObject, const param_type& ParamObject0 ) const
			{
				return NRangeProbabilityEvaluation<RealFloatingType>(RNG_EngineObject) * (ParamObject0.MaximumValue - ParamObject0.MinimumValue) + ParamObject0.MinimumValue;
			}

			param_type ParamPackageObject;
		};

		// uniform real number distribution
		template<std::floating_point RealFloatingType>
		class UniformRealNumberDistribution : public UniformRealNumber<RealFloatingType>
		{
		
		public:

			using _BaseType = UniformRealNumber<RealFloatingType>;
			using _ParamBaseType = typename _BaseType::param_type;
			using result_type = typename _BaseType::result_type;

			// parameter package
			struct param_type : _ParamBaseType
			{
				using distribution_type = UniformRealNumberDistribution;

				param_type() : _ParamBaseType(0, (std::numeric_limits<RealFloatingType>::max)()) {}

				explicit param_type(result_type _Min0, result_type _Max0 = (std::numeric_limits<RealFloatingType>::max)()) : _ParamBaseType(_Min0, _Max0) {}

				param_type(const _ParamBaseType& OtherObject) : _ParamBaseType(OtherObject) {}
			};

			UniformRealNumberDistribution() : _BaseType(RealFloatingType{0}, RealFloatingType{1}) {}

			explicit UniformRealNumberDistribution(RealFloatingType _Min0, RealFloatingType _Max0 = RealFloatingType{1}) : _BaseType(_Min0, _Max0) {}

			explicit UniformRealNumberDistribution(const param_type& ParamObject) : _BaseType(ParamObject) {}

			[[nodiscard]] friend bool operator==(const UniformRealNumberDistribution& Left, const UniformRealNumberDistribution& Right)
			{
				return Left.param() == Right.param();
			}

		#if __cplusplus < 202002L
			[[nodiscard]] friend bool operator!=(const UniformRealNumberDistribution& Left, const UniformRealNumberDistribution& Right)
			{
				return !(Left == Right);
			}
		#endif
		};

		class BernoulliDistribution
		{

		public:
			using result_type = bool;

			struct param_type
			{
				using distribution_type = BernoulliDistribution;

				param_type()
				{
					InitialParamType( 0.5 );
				}

				explicit param_type( double _Px0 )
				{
					InitialParamType( _Px0 );
				}

				[[nodiscard]] friend bool operator==( const param_type& Left, const param_type& Right )
				{
					return Left._RememberProbability_ == Right._RememberProbability_;
				}

			#if  __cplusplus < 202002L
				[[nodiscard]] friend bool operator!=( const param_type& Left, const param_type& Right )
				{
					return !( Left == Right );
				}
			#endif

				[[nodiscard]] double p() const
				{
					return _RememberProbability_;
				}

				void InitialParamType( double _Px0 )
				{
					// set internal state
					my_cpp2020_assert( 0.0 <= _Px0 && _Px0 <= 1.0, "invalid probability argument for bernoulli_distribution", std::source_location::current() );

					_RememberProbability_ = _Px0;
				}

				double _RememberProbability_;
			};

			BernoulliDistribution() : ParamPackageObject( 0.5 ) {}

			explicit BernoulliDistribution( double _Px0 ) : ParamPackageObject( _Px0 ) {}

			explicit BernoulliDistribution( const param_type& ParamObject0 ) : ParamPackageObject( ParamObject0 ) {}

			[[nodiscard]] double p() const
			{
				return ParamPackageObject.p();
			}

			[[nodiscard]] param_type param() const
			{
				return ParamPackageObject;
			}

			void param( const param_type& _Par0 )
			{
				// set parameter package
				ParamPackageObject = _Par0;
			}

			[[nodiscard]] result_type( min )() const
			{
				// get smallest possible result
				return false;
			}

			[[nodiscard]] result_type( max )() const
			{
				// get largest possible result
				return true;
			}

			void reset() {}	 // clear internal state

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject ) const
			{
				return this->Evaluation( RNG_EngineObject, ParamPackageObject );
			}

			template <class RandomNumberGenerator_EngineType>
			[[nodiscard]] result_type operator()( RandomNumberGenerator_EngineType& RNG_EngineObject, const param_type& ParamObject0 ) const
			{
				return this->Evaluation( RNG_EngineObject, ParamObject0 );
			}

			[[nodiscard]] friend bool operator==( const BernoulliDistribution& Left, const BernoulliDistribution& Right )
			{
				return Left.param() == Right.param();
			}

		#if  __cplusplus < 202002L 
			[[nodiscard]] friend bool operator!=( const BernoulliDistribution& Left, const BernoulliDistribution& Right )
			{
				return !( Left == Right );
			}
		#endif

			template <class _Elem, class _Traits>
			friend std::basic_istream<_Elem, _Traits>& operator>>( std::basic_istream<_Elem, _Traits>& Istr, BernoulliDistribution& OperatedObject )
			{
				// read state from Istr
				double RememberProbability0;
				DataType_ValueIn( Istr, RememberProbability0 );
				OperatedObject.ParamPackageObject.InitialParamType( RememberProbability0 );
				return Istr;
			}

			template <class _Elem, class _Traits>
			friend std::basic_ostream<_Elem, _Traits>& operator<<( std::basic_ostream<_Elem, _Traits>& Ostr, const BernoulliDistribution& OperatedObject )
			{
				// write state to Ostr
				DataType_ValueOut( Ostr, OperatedObject.ParamPackageObject._RememberProbability_ );
				return Ostr;
			}

		private:
			template <class RandomNumberGenerator_EngineType>
			result_type Evaluation( RandomNumberGenerator_EngineType& RNG_EngineObject, const param_type& ParamObject0 ) const
			{
				return NRangeProbabilityEvaluation<double>(RNG_EngineObject) < ParamObject0._RememberProbability_;
			}

			param_type ParamPackageObject;
		};
	}

	//针对容器内容进行洗牌
	//Shuffling against container content
	struct UniformShuffleRangeImplement
	{
		//RNG is random number generator
		template<std::random_access_iterator RandomAccessIteratorType, std::sentinel_for<RandomAccessIteratorType> SentinelIteratorType, typename RNG_Type>
		requires std::permutable<RandomAccessIteratorType> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		RandomAccessIteratorType operator()(RandomAccessIteratorType first, SentinelIteratorType last, RNG_Type&& functionRNG)
		{
			using iterator_difference_t = std::iter_difference_t<RandomAccessIteratorType>;
			using number_distribution_t = RND::UniformIntegerDistribution<iterator_difference_t>;
			using number_distribution_param_t = typename number_distribution_t::param_type;

			number_distribution_t number_distribution_object;
			const auto distance { last - first };

			for(iterator_difference_t index{1}; index < distance; ++index)
			{
				std::ranges::iter_swap(first + index, first + number_distribution_object(functionRNG, number_distribution_param_t(0, index)));
			}
			return std::ranges::next(first, last);
		}

		template <std::ranges::random_access_range RandomAccessRangeType, typename RNG_Type>
		requires std::permutable<std::ranges::iterator_t<RandomAccessRangeType>> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		std::ranges::borrowed_iterator_t<RandomAccessRangeType> operator()( RandomAccessRangeType&& range, RNG_Type&& functionRNG )
		{
			return this->operator()( std::ranges::begin( range ), std::ranges::end( range ), std::forward<RNG_Type>( functionRNG ) );
		}

		template<std::random_access_iterator RandomAccessIteratorType, typename RNG_Type>
		requires std::permutable<RandomAccessIteratorType> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		void KnuthShuffle(RandomAccessIteratorType begin, RandomAccessIteratorType end, RNG_Type&& functionRNG)
		{
			for ( std::iter_difference_t<RandomAccessIteratorType> difference_value = end - begin - 1; difference_value >= 1; --difference_value )
			{
				std::size_t iterator_offset = functionRNG() % ( difference_value + 1 );
				if ( iterator_offset != difference_value )
				{
					std::iter_swap( begin + iterator_offset, begin + difference_value );
				}
			}
		}

		template<std::ranges::random_access_range RandomAccessRangeType, typename RNG_Type>
		requires std::permutable<std::ranges::iterator_t<RandomAccessRangeType>> && std::uniform_random_bit_generator<std::remove_reference_t<RNG_Type>>
		void KnuthShuffle(RandomAccessRangeType&& range, RNG_Type&& functionRNG)
		{
			return (*this).KnuthShuffle(std::ranges::begin(range), std::ranges::end( range ), std::forward<RNG_Type>( functionRNG ));
		}
	};

	inline UniformShuffleRangeImplement ShuffleRangeData{};

}  // namespace CommonSecurity

namespace Cryptograph::CommonModule
{
	/**
	* MCA - Multiple Cryptography Algorithm
	*/

	/*
		//ENUM: Check Or Verify File Data IS Valid Or Invalid For Worker
		enum class CVFD_IsValidOrInvalid4Worker
		{
			MCA_CHECK_FILE_STRUCT,
			MCA_VERIFY_FILE_HASH
		};
	*/

	//ENUM: Cryption Mode To Multiple Cryptography Algorithm Core For File Data Worker
	enum class CryptionMode2MCAC4_FDW
	{
		MCA_ENCRYPTER,
		MCA_DECRYPTER,
		MCA_ENCODER,
		MCA_DECODER,
		MCA_PERMUTATION,
		MCA_PERMUTATION_REVERSE
	};

	namespace Adapters 
	{
		#if defined(__cpp_lib_byte) && !defined(__cpp_lib_span)

		inline void characterToByte(const std::vector<char>& input , std::vector<std::byte>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& characterData : input)
			{
				output.push_back( static_cast<std::byte>(static_cast<unsigned char>(characterData)) );
			}
		}

		inline void characterFromByte(const std::vector<std::byte>& input, std::vector<char>& output)
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& byteData : input)
			{
				output.push_back( static_cast<char>(static_cast<unsigned char>(byteData)) );
			}
		}

		inline void classicByteToByte(const std::vector<unsigned char>& input , std::vector<std::byte>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& characterData : input)
			{
				output.push_back( static_cast<std::byte>(characterData) );
			}
		}

		inline void classicByteFromByte(const std::vector<std::byte>& input, std::vector<unsigned char>& output)
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& byteData : input)
			{
				output.push_back( static_cast<unsigned char>(byteData) );
			}
		}

		#elif defined(__cpp_lib_byte) && defined(__cpp_lib_span)

		inline void characterToByte( std::span<const char> input , std::vector<std::byte>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& characterData : input)
			{
				output.push_back( static_cast<std::byte>(static_cast<unsigned char>(characterData)) );
			}
		}

		inline void characterFromByte( std::span<const std::byte> input, std::vector<char>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& byteData : input)
			{
				output.push_back( static_cast<char>(static_cast<unsigned char>(byteData)) );
			}
		}

		inline void classicByteToByte( std::span<const unsigned char> input , std::vector<std::byte>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& characterData : input)
			{
				output.push_back( static_cast<std::byte>(characterData) );
			}
		}

		inline void classicByteFromByte( std::span<const std::byte> input, std::vector<unsigned char>& output)
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& byteData : input)
			{
				output.push_back( static_cast<unsigned char>(byteData) );
			}
		}

		#endif

		#if !defined(__cpp_lib_span)

		inline void characterToClassicByte( const std::vector<char>& input , std::vector<unsigned char>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& characterData : input)
			{
				output.push_back( static_cast<unsigned char>(characterData) );
			}
		}

		inline void characterFromClassicByte( const std::vector<unsigned char>& input, std::vector<char>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& byteData : input)
			{
				output.push_back( static_cast<char>(byteData) );
			}
		}

		#else

		inline void characterToClassicByte( std::span<const char> input , std::vector<unsigned char>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& characterData : input)
			{
				output.push_back( static_cast<unsigned char>(characterData) );
			}
		}

		inline void characterFromClassicByte( std::span<const unsigned char> input, std::vector<char>& output )
		{
			output.clear();
			output.reserve(input.size());
			for (const auto& byteData : input)
			{
				output.push_back( static_cast<char>(byteData) );
			}
		}

		#endif
	}

}  // namespace Cryptograph::CommonModule