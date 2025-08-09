#include "Wrapper_LittleOaldresPuzzle_Cryptic.h"
#include "LittleOaldresPuzzle_Cryptic.h"

#include <vector>
#include <algorithm>

using TwilightDreamOfMagical::CustomSecurity::SED::StreamCipher::LittleOaldresPuzzle_Cryptic;
using Block128 = TwilightDreamOfMagical::CustomSecurity::SED::StreamCipher::Block128;
using Key128 = TwilightDreamOfMagical::CustomSecurity::SED::StreamCipher::Key128;

static inline Block128 to_cpp_block( const LittleOPC_Block128& b )
{
	return Block128 { b.first, b.second };
}
static inline LittleOPC_Block128 from_cpp_block( const Block128& b )
{
	return LittleOPC_Block128 { b.first, b.second };
}
static inline Key128 to_cpp_key( const LittleOPC_Key128& k )
{
	return Key128 { k.first, k.second };
}

extern "C"
{

	LittleOPC_Instance LittleOPC_New( uint64_t seed )
	{
		return new LittleOaldresPuzzle_Cryptic( seed );
	}

	void LittleOPC_Delete( LittleOPC_Instance cryptic )
	{
		delete static_cast<LittleOaldresPuzzle_Cryptic*>( cryptic );
	}

	void LittleOPC_ResetPRNG( LittleOPC_Instance cryptic )
	{
		static_cast<LittleOaldresPuzzle_Cryptic*>( cryptic )->ResetPRNG();
	}

	LittleOPC_Block128 LittleOPC_SingleRoundEncryption( LittleOPC_Instance cryptic, LittleOPC_Block128 data, LittleOPC_Key128 key, uint64_t number_once )
	{
		Block128 C = static_cast<LittleOaldresPuzzle_Cryptic*>( cryptic )->SingleRoundEncryption( to_cpp_block( data ), to_cpp_key( key ), number_once );
		return from_cpp_block( C );
	}

	LittleOPC_Block128 LittleOPC_SingleRoundDecryption( LittleOPC_Instance cryptic, LittleOPC_Block128 data, LittleOPC_Key128 key, uint64_t number_once )
	{
		Block128 P = static_cast<LittleOaldresPuzzle_Cryptic*>( cryptic )->SingleRoundDecryption( to_cpp_block( data ), to_cpp_key( key ), number_once );
		return from_cpp_block( P );
	}

	void LittleOPC_MultipleRoundsEncryption( LittleOPC_Instance cryptic, const LittleOPC_Block128* data_array, size_t data_count, const LittleOPC_Key128* keys_array, size_t keys_count, LittleOPC_Block128* result_data_array )
	{
		std::vector<Block128> data( data_count );
		for ( size_t i = 0; i < data_count; ++i )
			data[ i ] = to_cpp_block( data_array[ i ] );

		std::vector<Key128> keys( keys_count );
		for ( size_t i = 0; i < keys_count; ++i )
			keys[ i ] = to_cpp_key( keys_array[ i ] );

		std::vector<Block128> enc( data_count );

		static_cast<LittleOaldresPuzzle_Cryptic*>( cryptic )->MultipleRoundsEncryption( data, keys, enc );

		for ( size_t i = 0; i < data_count; ++i )
			result_data_array[ i ] = from_cpp_block( enc[ i ] );
	}

	void LittleOPC_MultipleRoundsDecryption( LittleOPC_Instance cryptic, const LittleOPC_Block128* data_array, size_t data_count, const LittleOPC_Key128* keys_array, size_t keys_count, LittleOPC_Block128* result_data_array )
	{
		std::vector<Block128> data( data_count );
		for ( size_t i = 0; i < data_count; ++i )
			data[ i ] = to_cpp_block( data_array[ i ] );

		std::vector<Key128> keys( keys_count );
		for ( size_t i = 0; i < keys_count; ++i )
			keys[ i ] = to_cpp_key( keys_array[ i ] );

		std::vector<Block128> dec( data_count );

		static_cast<LittleOaldresPuzzle_Cryptic*>( cryptic )->MultipleRoundsDecryption( data, keys, dec );

		for ( size_t i = 0; i < data_count; ++i )
			result_data_array[ i ] = from_cpp_block( dec[ i ] );
	}

	LittleOPC_Block128* LittleOPC_GenerateSubkeyWithEncryption( LittleOPC_Instance cryptic, LittleOPC_Key128 key, uint64_t loop_count )
	{
		std::vector<Block128> subs = static_cast<LittleOaldresPuzzle_Cryptic*>( cryptic )->GenerateSubkey_WithUseEncryption( to_cpp_key( key ), loop_count );
		LittleOPC_Block128*	  out = new LittleOPC_Block128[ subs.size() ];
		for ( size_t i = 0; i < subs.size(); ++i )
			out[ i ] = from_cpp_block( subs[ i ] );
		return out;
	}

	LittleOPC_Block128* LittleOPC_GenerateSubkeyWithDecryption( LittleOPC_Instance cryptic, LittleOPC_Key128 key, uint64_t loop_count )
	{
		std::vector<Block128> subs = static_cast<LittleOaldresPuzzle_Cryptic*>( cryptic )->GenerateSubkey_WithUseDecryption( to_cpp_key( key ), loop_count );
		LittleOPC_Block128*	  out = new LittleOPC_Block128[ subs.size() ];
		for ( size_t i = 0; i < subs.size(); ++i )
			out[ i ] = from_cpp_block( subs[ i ] );
		return out;
	}

	void LittleOPC_FreeBlocks( LittleOPC_Block128* ptr )
	{
		delete[] ptr;
	}

}  // extern "C"