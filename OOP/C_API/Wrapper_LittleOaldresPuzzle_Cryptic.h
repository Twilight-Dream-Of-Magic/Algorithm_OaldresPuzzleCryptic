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

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_WRAPPER_LITTLEOALDRESPUZZLE_CRYPTIC_H
#define ALGORITHM_OALDRESPUZZLECRYPTIC_WRAPPER_LITTLEOALDRESPUZZLE_CRYPTIC_H

/*
 * C API v2 for LittleOaldresPuzzle_Cryptic
 * - Switched to 128-bit block/key (two uint64_t fields).
 * - Exposes single-round and multi-round operations.
 * - Subkey generators return heap arrays; free with LittleOPC_FreeBlocks.
 */

#include <stddef.h>   // size_t
#include <stdint.h>   // uint64_t

#ifdef __cplusplus
extern "C" {
#endif

// Opaque instance handle
typedef void* LittleOPC_Instance;

// 128-bit block and key (two 64-bit lanes)
typedef struct {
    uint64_t first;
    uint64_t second;
} LittleOPC_Block128;

typedef struct {
    uint64_t first;
    uint64_t second;
} LittleOPC_Key128;

// Lifecycle
LittleOPC_Instance LittleOPC_New(uint64_t seed);
void LittleOPC_Delete(LittleOPC_Instance cryptic);
void LittleOPC_ResetPRNG(LittleOPC_Instance cryptic);

// Single-round ("number_once" plays role similar to a nonce/counter for that round)
LittleOPC_Block128 LittleOPC_SingleRoundEncryption(
    LittleOPC_Instance cryptic,
    LittleOPC_Block128 data,
    LittleOPC_Key128 key,
    uint64_t number_once);

LittleOPC_Block128 LittleOPC_SingleRoundDecryption(
    LittleOPC_Instance cryptic,
    LittleOPC_Block128 data,
    LittleOPC_Key128 key,
    uint64_t number_once);

// Multi-round over arrays of blocks/keys
// keys_count may be 1 (single key) or more; implementation will use all provided keys.
void LittleOPC_MultipleRoundsEncryption(
    LittleOPC_Instance cryptic,
    const LittleOPC_Block128* data_array,
    size_t data_count,
    const LittleOPC_Key128* keys_array,
    size_t keys_count,
    LittleOPC_Block128* result_data_array);

void LittleOPC_MultipleRoundsDecryption(
    LittleOPC_Instance cryptic,
    const LittleOPC_Block128* data_array,
    size_t data_count,
    const LittleOPC_Key128* keys_array,
    size_t keys_count,
    LittleOPC_Block128* result_data_array);

// Subkey generation (returns heap array of length loop_count). Free with LittleOPC_FreeBlocks.
LittleOPC_Block128* LittleOPC_GenerateSubkeyWithEncryption(
    LittleOPC_Instance cryptic,
    LittleOPC_Key128 key,
    uint64_t loop_count);

LittleOPC_Block128* LittleOPC_GenerateSubkeyWithDecryption(
    LittleOPC_Instance cryptic,
    LittleOPC_Key128 key,
    uint64_t loop_count);

// Deallocate arrays returned by the subkey generators
void LittleOPC_FreeBlocks(LittleOPC_Block128* ptr);

// ---- Backward-compat convenience (macro aliases) ----
// Keep old constructor/destructor names mapping to v2 naming.
#define New_LittleOPC(seed)            LittleOPC_New((seed))
#define Delete_LittleOPC(inst)         LittleOPC_Delete((inst))
#define LittleOPC_ResetPRNG_v1(inst)   LittleOPC_ResetPRNG((inst))

#ifdef __cplusplus
}
#endif

#endif // ALGORITHM_OALDRESPUZZLECRYPTIC_WRAPPER_LITTLEOALDRESPUZZLE_CRYPTIC_H
