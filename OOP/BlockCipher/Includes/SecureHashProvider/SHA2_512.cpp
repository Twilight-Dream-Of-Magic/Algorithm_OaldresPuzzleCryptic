#include "SHA2_512.hpp"

namespace TwilightDreamOfMagical::CommonSecurity
{
	namespace SHA
	{
		/*
			unpackInteger function unpacks an integer into a sequence of bytes with the least significant byte last.
			This is the "big-endian" byte order, also known as the "network byte order".
		*/
		template <typename IntegerType>
		requires std::is_integral_v<IntegerType>
		constexpr auto unpackInteger( IntegerType data )
		{
			constexpr auto	byteCount = std::numeric_limits<IntegerType>::digits / 8;
			std::array<std::uint8_t, byteCount> answer {};

			if constexpr(std::endian::native == std::endian::big)
			{
				::memcpy(&answer.data(), &data, sizeof(data));
				return answer;
			}

			for ( int index = byteCount - 1; index >= 0; --index )
			{
				answer[ index ] = static_cast<std::uint8_t>( data & 0xFF );
				data >>= 8;
			}

			return answer;
		}

		/*
			packInteger function is written to interpret the input bytes in big-endian order, with the most significant byte first.
		*/
		inline constexpr std::uint32_t packInteger( std::span<std::uint8_t, 4> data )
		{
			if constexpr(std::endian::native == std::endian::big)
			{
				std::uint32_t result = 0;
				::memcpy(&result, data.data(), data.size_bytes());
				return result;
			}

			return ( static_cast<std::uint32_t>( data[ 0 ] ) << 24 ) | ( static_cast<std::uint32_t>( data[ 1 ] ) << 16 ) | ( static_cast<std::uint32_t>( data[ 2 ] ) << 8 ) | ( static_cast<std::uint32_t>( data[ 3 ] ) );
		}

		inline constexpr std::uint64_t packInteger( std::span<std::uint8_t, 8> data )
		{
			if constexpr(std::endian::native == std::endian::big)
			{
				std::uint64_t result = 0;
				::memcpy(&result, data.data(), data.size_bytes());
				return result;
			}

			return ( static_cast<std::uint64_t>( packInteger( std::span<std::uint8_t, 4>{ data.begin(), 4u } ) ) << 32 ) | static_cast<std::uint64_t>( packInteger( std::span<std::uint8_t, 4>{ data.begin() + 4, 4u } ) );
		}

		//Function to find the choose of hash code (e, f, g)
		inline std::uint64_t ChooseHashCode( std::uint64_t e, std::uint64_t f, std::uint64_t g )
		{
			return ( e & f ) ^ ( ~e & g );
		}

		//Function to find the majority of hash code (a, b, c)
		inline std::uint64_t MajorityHashCode( std::uint64_t a, std::uint64_t b, std::uint64_t c )
		{
			return ( a & b ) ^ ( b & c ) ^ ( c & a );
		}

		//Function to find the Bitwise XOR with the right rotate over 14, 18, and 41 for (hash code e)
		inline std::uint64_t Sigma0( std::uint64_t e )
		{
			using TwilightDreamOfMagical::BaseOperation::rotate_left;
			using TwilightDreamOfMagical::BaseOperation::rotate_right;

			auto&& ea = rotate_right( e, 14ULL );
			auto&& eb = rotate_right( e, 18ULL );
			auto&& ec = rotate_right( e, 41ULL );
			return ea ^ eb ^ ec;
		}

		//Function to find the Bitwise XOR with the right rotate over 28, 34, and 39 for (hash code a)
		inline std::uint64_t Sigma1( std::uint64_t a )
		{
			using TwilightDreamOfMagical::BaseOperation::rotate_left;
			using TwilightDreamOfMagical::BaseOperation::rotate_right;

			auto&& aa = rotate_right( a, 28ULL );
			auto&& ab = rotate_right( a, 34ULL );
			auto&& ac = rotate_right( a, 39ULL );
			return aa ^ ab ^ ac;
		}

		//For hash word a
		inline std::uint64_t Gamma0( std::uint64_t hashWord )
		{
			using TwilightDreamOfMagical::BaseOperation::rotate_left;
			using TwilightDreamOfMagical::BaseOperation::rotate_right;

			auto&& a = rotate_right( hashWord, 19ULL );
			auto&& b = rotate_right( hashWord, 61ULL );
			auto&& c = hashWord >> 6ULL;
			return a ^ b ^ c;
		}

		//For hash word c
		inline std::uint64_t Gamma1( std::uint64_t hashWord )
		{
			using TwilightDreamOfMagical::BaseOperation::rotate_left;
			using TwilightDreamOfMagical::BaseOperation::rotate_right;

			auto&& a = rotate_right( hashWord, 1ULL );
			auto&& b = rotate_right( hashWord, 8ULL );
			auto&& c = hashWord >> 7ULL;
			return a ^ b ^ c;
		}

		void SHA2_512::HashUpdate( std::array< std::uint64_t, 8 >& data, const std::array< std::uint64_t, 80 >& keys)
		{
			auto HashingRound = [ & ]( std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t& d, std::uint64_t e, std::uint64_t f, std::uint64_t g, std::uint64_t& h, std::size_t count )
			{
				std::uint64_t hashcode = h + ChooseHashCode( e, f, g ) + Sigma0( e ) + keys[ count ] + round_constants[ count ];
				std::uint64_t hashcode2 = Sigma1( a ) + MajorityHashCode( a, b, c );
				d += hashcode;
				h = hashcode + hashcode2;
			};

			auto& [ a, b, c, d, e, f, g, h ] = data;

			// SHA-512 main loop
			// total 80 rounds of "HashingRound" called
			size_t count = 0;
			for ( size_t TotalRound = 0; TotalRound < 10; ++TotalRound )
			{
				HashingRound( a, b, c, d, e, f, g, h, count++ );
				HashingRound( h, a, b, c, d, e, f, g, count++ );
				HashingRound( g, h, a, b, c, d, e, f, count++ );
				HashingRound( f, g, h, a, b, c, d, e, count++ );
				HashingRound( e, f, g, h, a, b, c, d, count++ );
				HashingRound( d, e, f, g, h, a, b, c, count++ );
				HashingRound( c, d, e, f, g, h, a, b, count++ );
				HashingRound( b, c, d, e, f, g, h, a, count++ );
			}
		}

		void SHA2_512::PadMessage(std::vector<uint8_t>& message)
		{
			//This type of size must be (uint64_t)!
			std::uint64_t data_size = message.size();
			std::uint64_t modulue = data_size % Sha512BlockByteCount;

			auto FillZeroCount = FillByteCount - static_cast< std::int32_t >( modulue );
			if ( FillZeroCount <= 0 )
			{
				// at least 1 bit is added
				FillZeroCount += Sha512BlockByteCount;
			}

			// add 0b1000'0000...
			message.emplace_back( static_cast< std::uint64_t >( 0x80 ) );
			message.insert(  message.end(), static_cast< std::size_t >( FillZeroCount - 1 ), static_cast< std::uint8_t >( 0 ) );

			// add length inform
			// since sizeof(size_t) usually equals to 8
			// add 8 bytes of 0, then 8 bytes of length
			message.insert( message.end(), 8, static_cast< std::uint8_t >( 0 ) );
			auto data_size_bytes = unpackInteger< std::uint64_t >( data_size * 8 );
			message.insert( message.end(), data_size_bytes.begin(), data_size_bytes.end() );
		}

		void SHA2_512::Algorithm(std::span<std::uint8_t> PaddedMessage, std::array<std::uint64_t, 8>& HashValues)
		{
			// Initialize working variables to current hash value
			std::array<std::uint64_t, 8> hash_values(initial_hash_values);

			auto Byte128To16Worlds = [ this ]( std::span<std::uint8_t, Sha512BlockByteCount> ChunkSpan ) -> std::array<std::uint64_t, Sha512BlockByteCount / sizeof( std::uint64_t )>
			{
				std::array<std::uint64_t, Sha512BlockByteCount / sizeof( std::uint64_t )> answer {};
				auto span_begin = ChunkSpan.begin();
				for ( size_t index = 0; index < answer.size(); ++index )
				{
					answer[ index ] = packInteger( std::span<std::uint8_t, 8> { span_begin, sizeof( std::uint64_t ) } );
					span_begin += sizeof( std::uint64_t );
				}
				return answer;
			};

			// Process each block...
			// sha512 hash each 1024bits(128bytes)
			for ( std::size_t loop_count = 0; loop_count < PaddedMessage.size(); loop_count += 128 )
			{
				// Divide the block into 16 words
				// 1024 bits(128 bytes) as chunk
				std::span< std::uint8_t, Sha512BlockByteCount > ChunkSpan{ PaddedMessage.begin() + loop_count, Sha512BlockByteCount };
				auto MessageWords = Byte128To16Worlds( ChunkSpan );

				// 1st-fill in keys[80]
				// front 16 uint64 are from those 128bytes (16*8==128)
				// back 64 uint64 are calculated
				std::array<uint64_t, 80> KeyWords {};
				std::copy(MessageWords.begin(), MessageWords.end(), KeyWords.begin());
				for ( std::size_t block_index = 16; block_index < 80; ++block_index )
				{
					std::uint64_t wa = Gamma0( KeyWords[ block_index - 2 ] );
					std::uint64_t wb = KeyWords[ block_index - 7 ];
					std::uint64_t wc = Gamma1( KeyWords[ block_index - 15 ] );
					std::uint64_t wd = KeyWords[ block_index - 16 ];
					KeyWords[ block_index ]= wa + wb + wc + wd; // notice only unsigned overflow is legal
				}

				// 2nd calculate hash of chunk[loop_count]
				auto TranformedHash = hash_values;
				HashUpdate(TranformedHash, KeyWords);

				// 3rd add hash of chunk[loop_count] to global hashes
				for ( std::size_t index = 0; index < 8; ++index )
				{
					// Add this chunk's hash to result so far
					hash_values[ index ] += TranformedHash[ index ];
				}
			}

			HashValues = hash_values;
		}

		void SHA2_512::Hash( std::span<uint8_t> message, std::span<uint8_t> hashed_message )
		{
			// Error checking
			my_cpp2020_assert( !message.empty(), "Input invalid message size.", std::source_location::current() );
			my_cpp2020_assert( hashed_message.size() >= 64, "Output buffer too small.", std::source_location::current() );

			// Pad the message
			std::vector<uint8_t> PaddedMessage( message.begin(), message.end() );
			PadMessage( PaddedMessage );

			// Hash the message
			std::array<std::uint64_t, 8> hash_values {};
			Algorithm(PaddedMessage, hash_values);

			// Convert hash values to byte sequence for output
			for ( std::size_t i = 0; i < 8; ++i )
			{
				hashed_message[ i * 8 + 0 ] = ( hash_values[ i ] >> 56 ) & 0xFF;
				hashed_message[ i * 8 + 1 ] = ( hash_values[ i ] >> 48 ) & 0xFF;
				hashed_message[ i * 8 + 2 ] = ( hash_values[ i ] >> 40 ) & 0xFF;
				hashed_message[ i * 8 + 3 ] = ( hash_values[ i ] >> 32 ) & 0xFF;
				hashed_message[ i * 8 + 4 ] = ( hash_values[ i ] >> 24 ) & 0xFF;
				hashed_message[ i * 8 + 5 ] = ( hash_values[ i ] >> 16 ) & 0xFF;
				hashed_message[ i * 8 + 6 ] = ( hash_values[ i ] >> 8 ) & 0xFF;
				hashed_message[ i * 8 + 7 ] = ( hash_values[ i ] >> 0 ) & 0xFF;
			}
		}

		void SHA2_512::Hash( std::string message, std::string& hashed_message )
		{
			std::vector<uint8_t> message_bytes( message.begin(), message.end() );
			std::vector<uint8_t> hashed_message_bytes( 64 );
			Hash( std::span<uint8_t>( message_bytes ), std::span<uint8_t>( hashed_message_bytes ) );

			std::stringstream ss;
			ss << std::hex << std::setfill( '0' );
			for ( const auto& byte : hashed_message_bytes )
			{
				ss << std::setw( 2 ) << static_cast<int>( byte );
			}
			hashed_message = ss.str();
		}

		void SHA2_512::Hash( std::span<uint64_t> message, std::span<uint64_t> hashed_message )
		{
			// Convert input and output spans to byte-based spans.
			std::span<uint8_t> message_bytes( reinterpret_cast<uint8_t*>( message.data() ), message.size() * 8 );
			std::span<uint8_t> hashed_message_bytes( reinterpret_cast<uint8_t*>( hashed_message.data() ), hashed_message.size() * 8 );

			Hash( message_bytes, hashed_message_bytes );
		}
	}  // namespace SHA
}  // namespace TwilightDreamOfMagical::CommonSecurity