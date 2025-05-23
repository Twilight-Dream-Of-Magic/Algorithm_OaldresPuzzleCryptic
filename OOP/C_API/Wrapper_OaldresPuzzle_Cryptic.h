/*
 * Copyright (C) 2023-2050 Twilight-Dream
 *
 * 本文件是 Algorithm_OaldresPuzzleCryptic 的一部分。
 *
 * Algorithm_OaldresPuzzleCryptic 是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是（按你的决定）任何以后版都可以。
 *
 * 发布 Algorithm_OaldresPuzzleCryptic 是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的复本。如果没有，请看 <https://www.gnu.org/licenses/>。
 */
 
 /*
 * Copyright (C) 2023-2050 Twilight-Dream
 *
 * This file is part of Algorithm_OaldresPuzzleCryptic.
 *
 * Algorithm_OaldresPuzzleCryptic is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_WRAPPER_OALDRESPUZZLE_CRYPTIC_H
#define ALGORITHM_OALDRESPUZZLECRYPTIC_WRAPPER_OALDRESPUZZLE_CRYPTIC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct OaldresPuzzle_CrypticContext OaldresPuzzle_CrypticContext;

	OaldresPuzzle_CrypticContext* New_OPC( uint64_t data_block_size, uint64_t key_block_size, const uint8_t* initial_vector, uint64_t initial_vector_size, uint64_t LFSR_Seed, uint64_t NLFSR_Seed, uint64_t SDP_Seed );

	void OPC_Encryption( OaldresPuzzle_CrypticContext* context, const uint8_t* keys, uint64_t keys_size, const uint8_t* input, size_t input_size, uint8_t* output );

	void OPC_Decryption( OaldresPuzzle_CrypticContext* context, const uint8_t* keys, uint64_t keys_size, const uint8_t* input, size_t input_size, uint8_t* output );

	void Delete_OPC( OaldresPuzzle_CrypticContext* context );

#ifdef __cplusplus
}
#endif

#endif	//ALGORITHM_OALDRESPUZZLECRYPTIC_WRAPPER_OALDRESPUZZLE_CRYPTIC_H
