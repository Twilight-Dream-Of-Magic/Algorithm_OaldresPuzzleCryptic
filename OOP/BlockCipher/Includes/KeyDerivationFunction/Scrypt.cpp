#include "Scrypt.hpp"

namespace TwilightDreamOfMagical::CommonSecurity
{
	namespace KeyDerivationFunction
	{
		void Scrypt::Salsa20_WordSpecification( const std::array<std::uint32_t, 16>& in, std::array<std::uint32_t, 16>& out )
		{
			std::array<std::uint32_t, 16> words;

			// Words = Input
			std::ranges::copy( in.begin(), in.end(), words.begin() );

			// Words[index]..... = Words
			auto& [ word00, word01, word02, word03, word04, word05, word06, word07, word08, word09, word10, word11, word12, word13, word14, word15 ] = words;

			// While round = 8, rounds > 0, round = round - 2
			// Words[index] = Salsa20Round(Words[index]) ......
			std::int32_t round = 8;
			while ( round > 0 )
			{
				//Odd round
				word04 ^= std::rotl( word00 + word12, 7 );
				word08 ^= std::rotl( word04 + word00, 9 );
				word12 ^= std::rotl( word08 + word04, 13 );
				word00 ^= std::rotl( word12 + word08, 18 );
				word09 ^= std::rotl( word05 + word01, 7 );
				word13 ^= std::rotl( word09 + word05, 9 );
				word01 ^= std::rotl( word13 + word09, 13 );
				word05 ^= std::rotl( word01 + word13, 18 );
				word14 ^= std::rotl( word10 + word06, 7 );
				word02 ^= std::rotl( word14 + word10, 9 );
				word06 ^= std::rotl( word02 + word14, 13 );
				word10 ^= std::rotl( word06 + word02, 18 );
				word03 ^= std::rotl( word15 + word11, 7 );
				word07 ^= std::rotl( word03 + word15, 9 );
				word11 ^= std::rotl( word07 + word03, 13 );
				word15 ^= std::rotl( word11 + word07, 18 );

				//Even round
				word01 ^= std::rotl( word00 + word03, 7 );
				word02 ^= std::rotl( word01 + word00, 9 );
				word03 ^= std::rotl( word02 + word01, 13 );
				word00 ^= std::rotl( word03 + word02, 18 );
				word06 ^= std::rotl( word05 + word04, 7 );
				word07 ^= std::rotl( word06 + word05, 9 );
				word04 ^= std::rotl( word07 + word06, 13 );
				word05 ^= std::rotl( word04 + word07, 18 );
				word11 ^= std::rotl( word10 + word09, 7 );
				word08 ^= std::rotl( word11 + word10, 9 );
				word09 ^= std::rotl( word08 + word11, 13 );
				word10 ^= std::rotl( word09 + word08, 18 );
				word12 ^= std::rotl( word15 + word14, 7 );
				word13 ^= std::rotl( word12 + word15, 9 );
				word14 ^= std::rotl( word13 + word12, 13 );
				word15 ^= std::rotl( word14 + word13, 18 );

				round -= 2;
			}

			round = 0;

			// Output[index] = Input[index] + Words[index] ......
			std::ranges::transform( in.begin(), in.end(), words.begin(), words.end(), out.begin(), []( const std::uint32_t a, const std::uint32_t b ) { return a + b; } );

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>( words.data(), words.size() * sizeof( std::uint32_t ) );
			CheckPointer = nullptr;
		}

		std::array<std::uint32_t, 16> Scrypt::ExclusiveOrBlock( std::span<const std::uint32_t> left, std::span<const std::uint32_t> right )
		{
			std::array<std::uint32_t, 16> exclusive_or_word_result;

			std::ranges::transform( left.begin(), left.end(), right.begin(), right.end(), exclusive_or_word_result.begin(), []( const std::uint32_t a, const std::uint32_t b ) { return a ^ b; } );

			return exclusive_or_word_result;
		}

		void Scrypt::MixBlock( std::array<std::uint32_t, 16>& word32_buffer, std::span<const std::uint32_t> in, std::span<std::uint32_t> out, const std::uint64_t block_size )
		{
			std::array<std::uint32_t, 16> word32_buffer_t {};

			/* 1: X = Block[2 * block_size - 1] */
			std::memcpy( word32_buffer.data(), &in[ ( 2 * block_size - 1 ) * 16 ], 16 * sizeof( std::uint32_t ) );

			/* 2: for index = 0 to 2 * block_size - 1 do */
			for ( std::size_t index = 0; index < 2 * block_size; index += 2 )
			{
				/* 3: T = X xor Block[index] */
				word32_buffer_t = this->ExclusiveOrBlock( word32_buffer, { in.begin() + ( index * 16 ), in.end() } );

				/* 4: X = Salsa20(T) */
				//Exclusive-or And Salsa20
				this->Salsa20_WordSpecification( word32_buffer_t, word32_buffer );

				/* 5: Y[index] = X */
				/* 6: Block' = (Y[0], Y[2], ..., Y[2 * block_size - 2], Y[1], Y[3], ..., Y[2 * block_size - 1]) */
				std::memcpy( &out[ index * 8 ], word32_buffer.data(), word32_buffer.size() * sizeof( std::uint32_t ) );

				word32_buffer_t = this->ExclusiveOrBlock( word32_buffer, { in.begin() + ( index * 16 + 16 ), in.end() } );

				this->Salsa20_WordSpecification( word32_buffer_t, word32_buffer );

				std::memcpy( &out[ index * 8 + block_size * 16 ], word32_buffer.data(), word32_buffer.size() * sizeof( std::uint32_t ) );
			}

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>( word32_buffer_t.data(), word32_buffer_t.size() * sizeof( std::uint32_t ) );
			CheckPointer = nullptr;
		}

		std::uint64_t Scrypt::Integerify( std::span<std::uint32_t> block, const std::uint64_t block_size )
		{
			const std::uint64_t index = ( 2 * block_size - 1 ) * 16;
			return static_cast<std::uint64_t>( block[ index ] ) | static_cast<std::uint64_t>( block[ index + 1 ] ) << 32;
		}

		void Scrypt::ScryptMixFuncton( std::span<std::uint8_t> block, const std::uint64_t& block_size, const std::uint64_t resource_cost, std::span<std::uint32_t> block_v, std::span<std::uint32_t> block_xy )
		{
			using CommonToolkit::IntegerExchangeBytes::MessagePacking;
			using CommonToolkit::IntegerExchangeBytes::MessageUnpacking;

			std::array<std::uint32_t, 16> word32_buffer {};
			const std::size_t			  word32_block_size = 32 * block_size;
			std::span<std::uint32_t>	  block_x { block_xy.begin(), block_xy.end() };
			std::span<std::uint32_t>	  block_y { block_xy.begin() + word32_block_size, block_xy.end() };

			std::uint64_t offset_index = 0;

			/* 1: X = Block */
			MessagePacking<std::uint32_t, std::uint8_t>( { block.begin(), block.begin() + word32_block_size * sizeof( std::uint32_t ) }, block_x.data() );

			/* 2: for index = 0 to resource_cost - 1 do */
			for ( std::size_t index = 0; index < resource_cost; index += 2 )
			{
				/* 3: V[index] = X */
				std::memcpy( &block_v[ index * word32_block_size ], block_x.data(), word32_block_size * sizeof( std::uint32_t ) );

				/* 4: Y = MixSalsa20(X) */
				this->MixBlock( word32_buffer, block_x, block_y, block_size );

				/* 5: V[index] = Y */
				std::memcpy( &block_v[ ( index + 1 ) * word32_block_size ], block_y.data(), word32_block_size * sizeof( std::uint32_t ) );

				/* 4: X = MixSalsa20(Y) */
				this->MixBlock( word32_buffer, block_y, block_x, block_size );
			}

			/* 5: for index = 0 to resource_cost - 1 do */
			for ( std::size_t index = 0; index < resource_cost; index += 2 )
			{
				/* 6: offset_index = Integerify(X) mod resource_cost */
				offset_index = static_cast<int>( this->Integerify( block_x, block_size ) & ( resource_cost - 1 ) );

				/* 7: X = X ExclusiveOr V[offset_index] */
				std::span<std::uint32_t> _block_v_ { block_v.begin() + offset_index * word32_block_size, block_v.end() };
				std::ranges::transform( _block_v_.begin(), _block_v_.begin() + word32_block_size, block_x.begin(), block_x.begin() + word32_block_size, block_x.begin(), []( const std::uint32_t a, const std::uint32_t b ) { return a ^ b; } );

				/* 8: Y = MixSalsa20(X) */
				this->MixBlock( word32_buffer, block_x, block_y, block_size );

				/* 9: offset_index = Integerify(Y) mod resource_cost */
				offset_index = static_cast<int>( this->Integerify( block_y, block_size ) & ( resource_cost - 1 ) );

				/* 10: Y = Y ExclusiveOr V[offset_index] */
				_block_v_ = { block_v.begin() + offset_index * word32_block_size, block_v.end() };
				std::ranges::transform( _block_v_.begin(), _block_v_.begin() + word32_block_size, block_y.begin(), block_y.begin() + word32_block_size, block_y.begin(), []( const std::uint32_t a, const std::uint32_t b ) { return a ^ b; } );

				/* 11: X = MixSalsa20(Y) */
				this->MixBlock( word32_buffer, block_y, block_x, block_size );
			}

			offset_index = 0;

			/* 12: Block = X */
			MessageUnpacking<std::uint32_t, std::uint8_t>( { block_x.begin(), block_x.begin() + word32_block_size }, block.data() + offset_index );

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>( word32_buffer.data(), word32_buffer.size() * sizeof( std::uint32_t ) );
			CheckPointer = nullptr;
		}

		std::vector<std::uint8_t> Scrypt::DoGenerateKeys( std::span<std::uint8_t> secret_passsword_or_key_byte, std::span<std::uint8_t> salt_data, std::uint64_t& result_byte_size, std::uint64_t& resource_cost, std::uint64_t& block_size, std::uint64_t& parallelization_count )
		{

			PBKDF2 pbkdf2;

			// 1: (Block[0] ... Block{ParallelizationCount-1}) = PBKDF2(Password, Salt, 1, ParallelizationCount * MixFunctionLength)
			std::vector<std::uint8_t> block = pbkdf2.WithSHA2_512( secret_passsword_or_key_byte, salt_data, 1, parallelization_count * 128 * block_size );

			std::vector<std::uint32_t> block_xy( 64 * block_size, 0 );
			std::vector<std::uint32_t> block_v( 32 * resource_cost * block_size, 0 );

			// 2: for index = 0 to ParallelizationCount - 1 do
			for ( std::size_t index = 0; index < parallelization_count; index++ )
			{
				// 3: Block[index] = MixFunction(Block[index], N)
				std::span<std::uint8_t> slice_block { block.begin() + index * 128 * block_size, block.end() };
				this->ScryptMixFuncton( slice_block, block_size, resource_cost, block_v, block_xy );
			}

			// 4: DeriveKey = PBKDF2(Password, Block, 1, DeriveKeyLength)
			std::vector<std::uint8_t> generated_secure_keys = pbkdf2.WithSHA2_512( secret_passsword_or_key_byte, block, 1, result_byte_size );

			volatile void* CheckPointer = memory_set_no_optimize_function<0x00>( block.data(), block.size() );
			CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>( block_xy.data(), block_xy.size() * sizeof( std::uint32_t ) );
			CheckPointer = nullptr;
			CheckPointer = memory_set_no_optimize_function<0x00>( block_v.data(), block_v.size() * sizeof( std::uint32_t ) );
			CheckPointer = nullptr;

			return generated_secure_keys;
		}
	}  // namespace KeyDerivationFunction
}  // namespace TwilightDreamOfMagical::CommonSecurity
