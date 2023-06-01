#include "Wrapper_LittleOaldresPuzzle_Cryptic.h"
#include "../StreamCipher/LittleOaldresPuzzle_Cryptic.h"

using TwilightDreamOfMagical::CustomSecurity::SED::StreamCipher::LittleOaldresPuzzle_Cryptic;

extern "C"
{
	LittleOPC_Instance New_LittleOPC(uint64_t seed = 1)
	{
		return new LittleOaldresPuzzle_Cryptic(seed);
	}

	void Delete_LittleOPC(LittleOPC_Instance cryptic)
	{
		delete static_cast<LittleOaldresPuzzle_Cryptic*>(cryptic);
	}

	uint64_t LittleOPC_SingleRoundEncryption(LittleOPC_Instance cryptic, uint64_t data, uint64_t key, uint64_t round)
	{
		return static_cast<LittleOaldresPuzzle_Cryptic*>(cryptic)->SingleRoundEncryption(data, key, round);
	}

	uint64_t LittleOPC_SingleRoundDecryption(LittleOPC_Instance cryptic, uint64_t data, uint64_t key, uint64_t round)
	{
		return static_cast<LittleOaldresPuzzle_Cryptic*>(cryptic)->SingleRoundDecryption(data, key, round);
	}

	void LittleOPC_MultipleRoundsEncryption(LittleOPC_Instance cryptic, uint64_t* data_array, size_t size, uint64_t* keys, uint64_t* result_data_array)
	{
		std::vector<uint64_t> data(data_array, data_array + size);
		std::vector<uint64_t> result_data(size);
		std::vector<uint64_t> _keys(keys, keys + size);
		static_cast<LittleOaldresPuzzle_Cryptic*>(cryptic)->MultipleRoundsEncryption(data, _keys, result_data);
		std::copy(result_data.begin(), result_data.end(), result_data_array);
	}

	void LittleOPC_MultipleRoundsDecryption(LittleOPC_Instance cryptic, uint64_t* data_array, size_t size, uint64_t* keys, uint64_t* result_data_array)
	{
		std::vector<uint64_t> data(data_array, data_array + size);
		std::vector<uint64_t> result_data(size);
		std::vector<uint64_t> _keys(keys, keys + size);
		static_cast<LittleOaldresPuzzle_Cryptic*>(cryptic)->MultipleRoundsDecryption(data, _keys, result_data);
		std::copy(result_data.begin(), result_data.end(), result_data_array);
	}

	uint64_t* LittleOPC_GenerateSubkeyWithEncryption(LittleOPC_Instance cryptic, uint64_t key, uint64_t loop_count)
	{
		std::vector<uint64_t> subkeys = static_cast<LittleOaldresPuzzle_Cryptic*>(cryptic)->GenerateSubkey_WithUseEncryption(key, loop_count);
		uint64_t* array = new uint64_t[loop_count];
		std::copy(subkeys.begin(), subkeys.end(), array);
		return array;
	}

	uint64_t* LittleOPC_GenerateSubkeyWithDecryption(LittleOPC_Instance cryptic, uint64_t key, uint64_t loop_count)
	{
		std::vector<uint64_t> subkeys = static_cast<LittleOaldresPuzzle_Cryptic*>(cryptic)->GenerateSubkey_WithUseDecryption(key, loop_count);
		uint64_t* array = new uint64_t[loop_count];
		std::copy(subkeys.begin(), subkeys.end(), array);
		return array;
	}

	void LittleOPC_ResetPRNG(LittleOPC_Instance cryptic)
	{
		static_cast<LittleOaldresPuzzle_Cryptic*>(cryptic)->ResetPRNG();
	}
}