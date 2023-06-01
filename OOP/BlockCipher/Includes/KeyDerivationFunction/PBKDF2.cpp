#include "PBKDF2.hpp"
#include "../../DataFormating.hpp"

namespace TwilightDreamOfMagical::CommonSecurity
{
	namespace KeyDerivationFunction
	{
		std::vector<std::uint8_t> PBKDF2::WithSHA2_512( std::span<std::uint8_t> secret_passsword_or_key_byte, std::span<std::uint8_t> salt_data, const std::size_t round_count, std::uint64_t result_byte_size )
		{
			my_cpp2020_assert( result_byte_size > 0, "When using PBKDF2<PRF>, the byte size of the key that needs to be generated is not zero.", std::source_location::current() );

			using CommonToolkit::IntegerExchangeBytes::ByteSwap::byteswap;
			using UtilTools::DataFormating::ASCII_Hexadecmial::byteArray2HexadecimalString;
			using UtilTools::DataFormating::ASCII_Hexadecmial::hexadecimalString2ByteArray;

			my_cpp2020_assert( result_byte_size <= ( std::numeric_limits<std::uint64_t>::max() / ( 512 / sizeof( std::uint8_t ) ) ), "When using PBKDF2<PRF>, pseudo random function is HMAC-SHA2-512, the byte size of the key that needs to be generated is over the limit.", std::source_location::current() );

			const std::string secret_passsword_or_key_string = byteArray2HexadecimalString( secret_passsword_or_key_byte );
			const std::string salt_string_data = byteArray2HexadecimalString( salt_data );

			std::vector<std::uint8_t> result_byte;
			result_byte.reserve(result_byte_size);

			std::string U_Characters;
			std::string T_Characters;

			std::vector<std::uint8_t> _T_Array_;
			std::vector<std::uint8_t> _U_Array_;

			std::unique_ptr<SHA::SHA2_512> HashFunctionPointer = std::make_unique<SHA::SHA2_512>();
			DataHashingWrapper::HMAC_Worker HMAC_FunctionObject( *HashFunctionPointer );

			std::uint64_t Counter = 1;
			while ( result_byte_size > 0 )
			{
				std::string block_number_string;

				/*
				 The function F is the xor (^) of c iterations of chained PRFs.
				 The first iteration of PRF uses Password as the PRF key and Salt concatenated with encoded as a big-endian 32-bit integer as the input.
				 (Note that i is a 1-based index.)
				 Subsequent iterations of PRF use Password as the PRF key and the output of the previous PRF computation as the input: i
				 */
				if ( std::endian::native != std::endian::big )
					Counter = byteswap( Counter );

				block_number_string.push_back( static_cast<char>( ( Counter >> 56 ) & 0xff ) );
				block_number_string.push_back( static_cast<char>( ( Counter >> 48 ) & 0xff ) );
				block_number_string.push_back( static_cast<char>( ( Counter >> 40 ) & 0xff ) );
				block_number_string.push_back( static_cast<char>( ( Counter >> 32 ) & 0xff ) );
				block_number_string.push_back( static_cast<char>( ( Counter >> 24 ) & 0xff ) );
				block_number_string.push_back( static_cast<char>( ( Counter >> 16 ) & 0xff ) );
				block_number_string.push_back( static_cast<char>( ( Counter >> 8 ) & 0xff ) );
				block_number_string.push_back( static_cast<char>( ( Counter )&0xff ) );

				/* PRF is HMAC-SHA2-512 */
				/* Compute U[0] = PRF(Password, Salt || INTEGER(index)). */
				HMAC_FunctionObject.GivenKeyWith_SHA2_512( salt_string_data + block_number_string );
				HMAC_FunctionObject.With_SHA2_512( secret_passsword_or_key_string, U_Characters );

				/* T[index] = U[0] ... */
				T_Characters = U_Characters;

				for ( std::size_t round = 1; round < round_count; ++round )
				{
					/* Compute U[index] = PRF(Password, U[index - 1]) , index âˆˆ [1, round_count] */
					HMAC_FunctionObject.With_SHA2_512( secret_passsword_or_key_string, U_Characters );

					_T_Array_ = hexadecimalString2ByteArray( T_Characters );
					_U_Array_ = hexadecimalString2ByteArray( U_Characters );

					/* Exclusive-or operation U[index], U[index + 1] ... */
					std::ranges::transform( _T_Array_.begin(), _T_Array_.end(), _U_Array_.begin(), _U_Array_.end(), _T_Array_.begin(), []( std::uint8_t left, std::uint8_t right ) { return left ^ right; } );
				}

				if ( _T_Array_.empty() )
					_T_Array_ = hexadecimalString2ByteArray( T_Characters );

				/* Copy as many bytes as necessary into buffer. */
				std::copy( _T_Array_.begin(), _T_Array_.begin() + std::min( result_byte_size, _T_Array_.size() ), std::back_inserter(result_byte) );
				result_byte_size -= _T_Array_.size();

				block_number_string.clear();

				++Counter;
			}

			Counter = 0;

			std::ranges::fill( U_Characters.begin(), U_Characters.end(), '\x00' );
			std::ranges::fill( T_Characters.begin(), T_Characters.end(), '\x00' );

			U_Characters.clear();
			T_Characters.clear();

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>( _T_Array_.data(), _T_Array_.size() );
			CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>( _U_Array_.data(), _U_Array_.size() );
			CheckPointer = nullptr;

			return result_byte;
		}
	}  // namespace KeyDerivationFunction
}  // namespace TwilightDreamOfMagical::CommonSecurity
