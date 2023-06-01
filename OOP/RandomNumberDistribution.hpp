#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_RANDOMNUMBERDISTRIBUTION_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_RANDOMNUMBERDISTRIBUTION_HPP

#include "SupportBaseFunctions.hpp"

namespace TwilightDreamOfMagical::CommonSecurity
{
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
}

#endif //ALGORITHM_OALDRESPUZZLECRYPTIC_RANDOMNUMBERDISTRIBUTION_HPP
