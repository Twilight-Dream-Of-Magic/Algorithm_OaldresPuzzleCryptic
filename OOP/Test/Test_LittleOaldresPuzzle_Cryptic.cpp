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

#include "LittleOaldresPuzzle_Cryptic.h"
#include <iostream>
#include <vector>
#include <random>
#include <chrono>

namespace TwilightDreamOfMagical
{
	namespace Test_LittleOaldresPuzzle_Cryptic
	{
		using LittleOaldresPuzzle_Cryptic = CustomSecurity::SED::StreamCipher::LittleOaldresPuzzle_Cryptic;
		using Block128 = CustomSecurity::SED::StreamCipher::Block128;
		using Key128 = CustomSecurity::SED::StreamCipher::Key128;

		static inline void PrintBlock(const char* name, const Block128& b)
		{
			std::cout << name << " = (" << b.first << ", " << b.second << ")\n";
		}

		static inline void PrintKey(const char* name, const Key128& k)
		{
			std::cout << name << " = (" << k.first << ", " << k.second << ")\n";
		}

		// helper: XOR two 128-bit blocks in-place
		static inline void XorBlock(Block128& dst, const Block128& ks)
		{
			dst.first  ^= ks.first;
			dst.second ^= ks.second;
		}

		void SingleRoundTest()
		{
			// pack original A/B into one 128-bit block; key is 128-bit too
			Block128 P{1475ULL, 3695ULL};
			Key128  K{7532ULL, 9512ULL};

			std::uint64_t seed = 1;
			LittleOaldresPuzzle_Cryptic opc(seed);

			std::cout << "--------------------------------------------------\n";
			PrintBlock("P", P);
			PrintKey("K", K);

			Block128 C = opc.SingleRoundEncryption(P, K, /*number_once*/ 1);
			PrintBlock("C", C);

			opc.ResetPRNG();
			Block128 D = opc.SingleRoundDecryption(C, K, /*number_once*/ 1);
			PrintBlock("D", D);

			if (P == D) std::cout << "The decryption was successful.\n";
			else        std::cout << "The decryption failed.\n";
			std::cout << "--------------------------------------------------\n";
		}

		void MultipleRoundsTest()
		{
			std::vector<Block128> data{{1475ULL,3695ULL},{1258ULL,7593ULL},{777ULL,888ULL},{0ULL,1ULL}};
			std::vector<Key128>   keys{{7532ULL,9512ULL},{6108ULL,8729ULL}};

			std::vector<Block128> enc(data.size());
			std::vector<Block128> dec(data.size());

			std::uint64_t seed = 1;
			LittleOaldresPuzzle_Cryptic opc(seed);

			opc.MultipleRoundsEncryption(data, keys, enc);
			opc.MultipleRoundsDecryption(enc,  keys, dec);

			std::cout << "--------------------------------------------------\n";
			for (size_t i = 0; i < data.size(); ++i)
			{
				PrintBlock("P", data[i]);
				PrintBlock("C", enc[i]);
				PrintBlock("D", dec[i]);
				std::cout << (data[i] == dec[i] ? "Decryption was successful for block " : "Decryption failed for block ")
						  << i << ".\n----\n";
			}
			std::cout << "--------------------------------------------------\n";
		}

		void MultipleRoundsWithMoreDataTest()
		{
			// 10 MB of 128-bit blocks
			std::size_t n = (10 * 1024 * 1024) / sizeof(Block128);
			std::vector<Block128> data(n);

			std::random_device rd;
			std::mt19937_64 gen(rd());
			for (size_t i = 0; i < n; ++i) data[i] = {gen(), gen()};

			// 5120-byte key list
			std::size_t kcnt = 5120 / sizeof(Key128);
			std::vector<Key128> keys(kcnt, {0,0});
			if (!keys.empty()) keys[0] = {1,0};

			std::vector<Block128> enc(n), dec(n);

			std::uint64_t seed = 1;
			LittleOaldresPuzzle_Cryptic opc(seed);

			auto t0 = std::chrono::high_resolution_clock::now();
			opc.MultipleRoundsEncryption(data, keys, enc);
			auto t1 = std::chrono::high_resolution_clock::now();
			auto enc_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

			opc.ResetPRNG();

			t0 = std::chrono::high_resolution_clock::now();
			opc.MultipleRoundsDecryption(enc, keys, dec);
			t1 = std::chrono::high_resolution_clock::now();
			auto dec_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

			std::cout << "--------------------------------------------------\n";
			std::cout << "Encryption time: " << enc_ms << " ms\n";
			std::cout << "Decryption time: " << dec_ms << " ms\n";

			size_t ok = 0; for (size_t i = 0; i < n; ++i) if (data[i] == dec[i]) ++ok;
			std::cout << "Number of successful decrypts: " << ok << " out of " << n << "\n";
			std::cout << "--------------------------------------------------\n";
		}

		void NumberOnce_CounterMode_Test()
		{
			// CTR-like keystream accumulation on 128-bit lanes
			Block128 A{1475ULL, 3695ULL};
			Block128 B{   0ULL,    1ULL};
			Block128 C{   0ULL,    0ULL};
			Block128 D{   0ULL,    0ULL};

			Key128 KeyA{7532ULL, 0ULL};
			Key128 KeyB{9512ULL, 0ULL};
			std::uint64_t Rounds = 32;

			std::uint64_t seed = 1;
			LittleOaldresPuzzle_Cryptic lopc(seed);

			std::cout << "--------------------------------------------------\n";
			PrintBlock("A", A); PrintBlock("B", B); PrintBlock("C", C); PrintBlock("D", D);

			lopc.ResetPRNG();
			std::vector<Block128> SubKeysA = lopc.GenerateSubkey_WithUseEncryption(KeyA, Rounds);
			lopc.ResetPRNG();
			std::vector<Block128> SubKeysB = lopc.GenerateSubkey_WithUseEncryption(KeyB, Rounds);

			for (std::uint64_t r = 0; r < Rounds; ++r)
			{
				XorBlock(A, SubKeysA[r]);
				XorBlock(B, SubKeysB[r]);
				XorBlock(C, SubKeysA[r]);
				XorBlock(D, SubKeysB[r]);
			}

			PrintBlock("A'", A); PrintBlock("B'", B); PrintBlock("C'", C); PrintBlock("D'", D);

			for (std::uint64_t r = 0; r < Rounds; ++r)
			{
				XorBlock(A, SubKeysA[r]);
				XorBlock(B, SubKeysB[r]);
				XorBlock(C, SubKeysA[r]);
				XorBlock(D, SubKeysB[r]);
			}

			PrintBlock("A", A); PrintBlock("B", B); PrintBlock("C", C); PrintBlock("D", D);
			std::cout << "--------------------------------------------------\n";
		}
	} // namespace Test_LittleOaldresPuzzle_Cryptic
} // namespace TwilightDreamOfMagical
