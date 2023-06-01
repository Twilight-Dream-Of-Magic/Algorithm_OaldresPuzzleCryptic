#include "Wrapper_OaldresPuzzle_Cryptic.h"
#include "../BlockCipher/OPC_MainAlgorithm_Worker.hpp"

using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::OaldresPuzzle_Cryptic;
using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::OPC_MainAlgorithm_Worker;
using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::ImplementationDetails::CommonStateData;

struct OaldresPuzzle_CrypticContext
{
	uint64_t								  data_block_size = 16;
	uint64_t								  key_block_size = 32;
	std::unique_ptr<CommonStateData>		  CommonStateDataPointer = nullptr;
	std::unique_ptr<OaldresPuzzle_Cryptic>	  AlgorithmCorePointer = nullptr;
	std::unique_ptr<OPC_MainAlgorithm_Worker> AlgorithmWorkerPointer = nullptr;
	std::vector<std::uint8_t>				  InitialVector;
	uint64_t								  LFSR_Seed;
	uint64_t								  NLFSR_Seed;
	uint64_t								  SDP_Seed;
};

OaldresPuzzle_CrypticContext* New_OPC( uint64_t data_block_size, uint64_t key_block_size, const uint8_t* initial_vector, uint64_t initial_vector_size, uint64_t LFSR_Seed, uint64_t NLFSR_Seed, uint64_t SDP_Seed )
{
	if ( ( ( data_block_size % 2 ) != 0 ) || data_block_size < 2 )
	{
		std::cerr << "My C API Error: data_block_size must be a multiple of 2 quad-words and must not be less than 2 quad-words (128Bit)!" << std::endl;
		return nullptr;
	}

	if ( ( ( key_block_size % 4 ) != 0 ) || key_block_size < 4 )
	{
		std::cerr << "My C API Error: key_block_size must be a multiple of 4 quad-words and must not be less than 4 quad-words (256Bit), otherwise it does not meet the post-quantum standard of data security!" << std::endl;
		return nullptr;
	}

	if ( key_block_size <= data_block_size || ( ( key_block_size % data_block_size ) != 0 ) )
	{
		std::cerr << "My C API Error: key_block_size must be any multiple of data_block_size !" << std::endl;
		return nullptr;
	}

	if ( LFSR_Seed == 0 || NLFSR_Seed == 0 )
	{
		std::cerr << "My C API Error: Invalid custom random number generator for (LFSR or NLFSR) number seeding!" << std::endl;
		return nullptr;
	}

	if ( ( initial_vector_size % ( data_block_size * sizeof( uint64_t ) ) ) != 0 )
	{
		std::cerr << "My C API Error: The initial_vector size of the referenced data is not a multiple of (data_block_size * sizeof(uint64_t)) byte!" << std::endl;
		return nullptr;
	}

	if ( SDP_Seed < 0x2540BE400 )
	{
		std::cerr << "My C API Error: The numbers that are too small represent bit sequence seeds that will not allow chaotic systems that simulate the physical phenomena of a two-segment pendulum to work properly!" << std::endl;
		return nullptr;
	}

	OaldresPuzzle_CrypticContext* context = new OaldresPuzzle_CrypticContext;
	context->data_block_size = data_block_size;
	context->key_block_size = key_block_size;

	context->InitialVector.resize( initial_vector_size, 0 );
	::memcpy( context->InitialVector.data(), initial_vector, initial_vector_size );

	context->LFSR_Seed = LFSR_Seed;
	context->NLFSR_Seed = NLFSR_Seed;
	context->SDP_Seed = SDP_Seed;

	context->CommonStateDataPointer = std::make_unique<CommonStateData>( data_block_size, key_block_size, context->InitialVector, LFSR_Seed, NLFSR_Seed, SDP_Seed );
	context->AlgorithmCorePointer = std::make_unique<OaldresPuzzle_Cryptic>( *context->CommonStateDataPointer );
	context->AlgorithmWorkerPointer = std::make_unique<OPC_MainAlgorithm_Worker>( *context->AlgorithmCorePointer );

	return context;
}

void Reset_OPC( OaldresPuzzle_CrypticContext* context )
{
	context->CommonStateDataPointer.reset();
	context->AlgorithmCorePointer.reset();
	context->AlgorithmWorkerPointer.reset();

	context->CommonStateDataPointer = std::make_unique<CommonStateData>( context->data_block_size, context->key_block_size, context->InitialVector, context->LFSR_Seed, context->NLFSR_Seed, context->SDP_Seed );
	context->AlgorithmCorePointer = std::make_unique<OaldresPuzzle_Cryptic>( *context->CommonStateDataPointer );
	context->AlgorithmWorkerPointer = std::make_unique<OPC_MainAlgorithm_Worker>( *context->AlgorithmCorePointer );
}

void OPC_Encryption( OaldresPuzzle_CrypticContext* context, const uint8_t* keys, uint64_t keys_size, const uint8_t* input, size_t input_size, uint8_t* output )
{
	std::vector<std::uint8_t> MasterKeys( keys_size, 0 );
	::memcpy( MasterKeys.data(), keys, keys_size );
	std::vector<std::uint8_t> PlainTexts( input_size, 0 );
	::memcpy( PlainTexts.data(), input, input_size );
	std::vector<std::uint8_t> CipherTexts;

	if ( PlainTexts.size() % context->data_block_size != 0 )
		CipherTexts = context->AlgorithmWorkerPointer->EncrypterMain( PlainTexts, MasterKeys );
	else
		CipherTexts = context->AlgorithmWorkerPointer->EncrypterMainWithoutPadding( PlainTexts, MasterKeys );

	::memcpy( output, CipherTexts.data(), CipherTexts.size() );

	Reset_OPC( context );
}

void OPC_Decryption( OaldresPuzzle_CrypticContext* context, const uint8_t* keys, uint64_t keys_size, const uint8_t* input, size_t input_size, uint8_t* output )
{
	std::vector<std::uint8_t> MasterKeys( keys_size, 0 );
	::memcpy( MasterKeys.data(), keys, keys_size );
	std::vector<std::uint8_t> CipherTexts( input_size, 0 );
	::memcpy( CipherTexts.data(), input, input_size );
	std::vector<std::uint8_t> PlainTexts;

	if ( CipherTexts.size() % context->data_block_size != 0 )
		PlainTexts = context->AlgorithmWorkerPointer->DecrypterMain( CipherTexts, MasterKeys );
	else
		PlainTexts = context->AlgorithmWorkerPointer->DecrypterMainWithoutUnpadding( CipherTexts, MasterKeys );

	::memcpy( output, PlainTexts.data(), PlainTexts.size() );

	Reset_OPC( context );
}

void Delete_OPC( OaldresPuzzle_CrypticContext* context )
{
	delete context;
}
