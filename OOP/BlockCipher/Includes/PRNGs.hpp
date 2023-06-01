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

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_PRNGS_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_PRNGS_HPP

#include "../../CommonSecurity.hpp"
#include "../../DataFormating.hpp"

namespace TwilightDreamOfMagical::CustomSecurity
{
	//PseudoRandomNumberGenerator
	namespace PRNG
	{
		/*
			Reference source code:

			Rudimentary C++20 xorshiro256** uniform random bit generator implementation:
			https://github.com/Reputeless/Xoshiro-cpp/

			A C++ implementation of SplitMix:
			https://gist.github.com/imneme/6179748664e88ef3c34860f44309fc71

			https://gist.github.com/wreien/442e6f89f125f9b4a9919299a7536fd5 (Removed public share)
		*/
		namespace Xorshiro
		{
			/*
				golden ratio is 0x9e3779b97f4a7c13 with 64 bit number
			*/

			// An implementation of xorshiro (https://vigna.di.unimi.it/xorshift/)
			// wrapped to fit the C++11 RandomNumberGenerator requirements.
			// This allows us to use it with all the other facilities in <random>.
			//
			// Credits go to David Blackman and Sebastiano Vigna.
			//
			// TODO: make generic? (parameterise scrambler/width/hyperparameters/etc.)
			// Not as easy to do nicely as it might sound,
			// and this as it is is good enough for my purposes.

			struct xorshiro128 : UniformRandomBitGenerator<std::uint64_t>
			{
				static constexpr std::uint32_t num_state_words = 2;
				using state_type = std::array<std::uint64_t, num_state_words>;

				// cannot initialize with an all-zero state
				constexpr xorshiro128() noexcept
					: state{ 12, 34 }
				{
				}

				// using SplitMix64 generator to initialize the state;
				// using a different generator helps prevent seed correlation
				explicit constexpr xorshiro128(result_type seed) noexcept
				{
					auto splitmix64 = [seed_value = seed]() mutable {
						auto z = (seed_value += 0x9e3779b97f4a7c15);
						z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
						z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
						return z ^ (z >> 31);
					};
					std::ranges::generate(state, splitmix64);
				}

				explicit xorshiro128(std::initializer_list<result_type> initializer_list_args)
				{
					*this = xorshiro128(initializer_list_args.begin(), initializer_list_args.end());
				}

				template <std::input_or_output_iterator SeedDataIteratorType>
					requires
				(
					not std::convertible_to<SeedDataIteratorType, result_type>
					)
					explicit xorshiro128(SeedDataIteratorType&& begin, SeedDataIteratorType&& end)
				{
					std::vector<result_type> seed_vector{ begin, end };
					this->generate_number_state_seeds(seed_vector);
					seed_vector.clear();
					seed_vector.shrink_to_fit();
				}

				explicit xorshiro128(std::span<const result_type> seed_span)
				{
					this->generate_number_state_seeds(seed_span);
				}

				explicit xorshiro128(std::seed_seq& s_q)
				{
					this->generate_number_state_seeds(s_q);
				}

				constexpr void seed() noexcept
				{
					*this = xorshiro128();
				}
				constexpr void seed(result_type s) noexcept
				{
					*this = xorshiro128(s);
				}
				template <typename SeedSeq>
					requires(not std::convertible_to<SeedSeq, result_type>)
				constexpr void seed(SeedSeq& q)
				{
					*this = xorshiro128(q);
				}

				constexpr result_type operator()() noexcept
				{
					// xorshiro128+:
					/*
						const auto a = state[0];
						auto b = state[1];
						const auto result = a + b;

						b ^= a;
						state[0] = rotl(a, 24) ^ b ^ (b << 16); // a, b
						state[1] = rotl(b, 37); // c
					*/

					// xorshiro128++:
					/*
						const auto a = state[0];
						auto b = state[1];
						const auto result = std::rotl(a + b, 17) + a;

						b ^= a;
						state[0] = std::rotl(a, 49) ^ b ^ (b << 21); // a, b
						state[1] = std::rotl(b, 28); // c
					*/

					// xorshiro128**:
					const auto a = state[0];
					auto b = state[1];
					const auto result = std::rotl(a * 5, 7) * 9;

					b ^= a;
					state[0] = std::rotl(a, 24) ^ b ^ (b << 16); // a, b
					state[1] = std::rotl(b, 37); // c

					return result;
				}

				constexpr void discard(std::uint64_t round) noexcept
				{
					if (round == 0)
						return;

					while (round--)
						operator()();
				}

				/*
					This is the jump function for the generator.
					It is equivalent to 2^64 calls to operator()();
					It can be used to generate 2^64 non-overlapping subsequences for parallel computations.
				*/
				constexpr void jump() noexcept
				{
					constexpr std::uint64_t jump_table[] = {
							0xdf900294d8f554a5, 0x170865df4b3201fc
					};

					state_type temporary_state{};
					for (std::uint32_t jump_table_index = 0; jump_table_index < std::ssize(jump_table); jump_table_index++)
					{
						for (std::uint32_t b = 0; b < 64; b++)
						{
							if (jump_table[jump_table_index] & (static_cast<std::uint64_t>(1) << b))
							{
								temporary_state[0] ^= state[0];
								temporary_state[1] ^= state[1];
							}
							operator()();
						}
					}

					temporary_state[0] = state[0];
					temporary_state[1] = state[1];
				}

				/*
					This is the long-jump function for the generator.
					It is equivalent to 2^96 calls to operator()();
					It can be used to generate 2^32 starting points,
					From each of which jump() will generate 2^32 non-overlapping subsequences for parallel distributed computations.
				*/
				constexpr void long_jump() noexcept
				{
					constexpr std::uint64_t long_jump_table[] = {
							0xd2a98b26625eee7b, 0xdddf9b1090aa7ac1
					};

					state_type temporary_state{};
					for (std::uint32_t long_jump_table_index = 0; long_jump_table_index < std::ssize(long_jump_table); long_jump_table_index++)
					{
						for (std::uint32_t b = 0; b < 64; b++)
						{
							if (long_jump_table[long_jump_table_index] & (static_cast<std::uint64_t>(1) << b))
							{
								temporary_state[0] ^= state[0];
								temporary_state[1] ^= state[1];

							}
							operator()();
						}
					}

					temporary_state[0] = state[0];
					temporary_state[1] = state[1];

				}

				constexpr bool operator==(const xorshiro128&) const noexcept = default;

				template <typename CharT, typename Traits>
				friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os, const xorshiro128& e)
				{
					os << e.state[0];
					for (int i = 1; i < num_state_words; ++i)
					{
						os.put(os.widen(' '));
						os << e.state[i];
					}
					return os;
				}

				template <typename CharT, typename Traits>
				friend std::basic_istream<CharT, Traits&> operator>>(std::basic_istream<CharT, Traits>& is, xorshiro128& e)
				{
					xorshiro128 r;
					// TODO: what if ' ' is not considered whitespace?
					// Maybe more appropriate is to `.get` each space
					for (auto& s : r.state)
						is >> s;
					if (is)
						e = r;
					return is;
				}

			private:
				state_type state;

				void generate_number_state_seeds(std::seed_seq& s_q)
				{
					std::uint32_t this_temparory_state[num_state_words * 2];
					s_q.generate(std::begin(this_temparory_state), std::end(this_temparory_state));
					for (std::uint32_t index = 0; index < num_state_words; ++index)
					{
						state[index] = this_temparory_state[index * 2];
						state[index] <<= 32;
						state[index] |= this_temparory_state[index * 2 + 1];
					}
				}

				void generate_number_state_seeds(std::span<const result_type> seed_span)
				{
					std::uint32_t this_temparory_state[num_state_words * 2];

					auto seed_span_begin = seed_span.begin();
					auto seed_span_end = seed_span.end();
					result_type seed = 0;
					auto splitmix64 = [&seed_span_begin, &seed_span_end, &seed]() mutable {

						auto z = (seed += 0x9e3779b97f4a7c15);
						z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
						z = (z ^ (z >> 27)) * 0x94d049bb133111eb;

						if (seed_span_begin != seed_span_end)
						{
							++seed_span_begin;
						}

						return z ^ (z >> 31);
					};
					std::ranges::generate(this_temparory_state, splitmix64);
					seed = 0;

					for (std::uint32_t index = 0; index < num_state_words; ++index)
					{
						state[index] = this_temparory_state[index * 2];
						state[index] <<= 32;
						state[index] |= this_temparory_state[index * 2 + 1];
					}
				}
			};

			struct xorshiro256 : UniformRandomBitGenerator<std::uint64_t>
			{
				static constexpr std::uint32_t num_state_words = 4;
				using state_type = std::array<std::uint64_t, num_state_words>;

				// cannot initialize with an all-zero state
				constexpr xorshiro256() noexcept
					: state{ 12, 34 }
				{
				}

				// using SplitMix64 generator to initialize the state;
				// using a different generator helps prevent seed correlation
				explicit constexpr xorshiro256(result_type seed) noexcept
				{
					auto splitmix64 = [seed_value = seed]() mutable {
						auto z = (seed_value += 0x9e3779b97f4a7c15);
						z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
						z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
						return z ^ (z >> 31);
					};
					std::ranges::generate(state, splitmix64);
				}

				explicit xorshiro256(std::initializer_list<result_type> initializer_list_args)
				{
					*this = xorshiro256(initializer_list_args.begin(), initializer_list_args.end());
				}

				template <std::input_or_output_iterator SeedDataIteratorType>
					requires
				(
					not std::convertible_to<SeedDataIteratorType, result_type>
					)
					explicit xorshiro256(SeedDataIteratorType&& begin, SeedDataIteratorType&& end)
				{
					std::vector<result_type> seed_vector{ begin, end };
					this->generate_number_state_seeds(seed_vector);
					seed_vector.clear();
					seed_vector.shrink_to_fit();
				}

				explicit xorshiro256(std::span<const result_type> seed_span)
				{
					this->generate_number_state_seeds(seed_span);
				}

				explicit xorshiro256(std::seed_seq& s_q)
				{
					this->generate_number_state_seeds(s_q);
				}

				constexpr void seed() noexcept
				{
					*this = xorshiro256();
				}
				constexpr void seed(result_type s) noexcept
				{
					*this = xorshiro256(s);
				}
				template <typename SeedSeq>
					requires(not std::convertible_to<SeedSeq, result_type>)
				constexpr void seed(SeedSeq& q)
				{
					*this = xorshiro256(q);
				}

				constexpr result_type operator()() noexcept
				{
					// xorshiro256+:
					// const auto result = state[0] + state[3];
					// xorshiro256++:
					// const auto result = std::rotl(state[0] + state[3], 23) + state[0];

					// xorshiro256**:
					const auto result = std::rotl(state[1] * 5, 7) * 9;
					const auto t = state[1] << 17;

					state[2] ^= state[0];
					state[3] ^= state[1];
					state[1] ^= state[2];
					state[0] ^= state[3];

					state[2] ^= t;
					state[3] = std::rotl(state[3], 45);

					return result;
				}

				constexpr void discard(std::uint64_t round) noexcept
				{
					if (round == 0)
						return;

					while (round--)
						operator()();
				}

				/*
					This is the jump function for the generator.
					It is equivalent to 2^128 calls to operator()();
					It can be used to generate 2^128 non-overlapping subsequences for parallel computations.
				*/
				constexpr void jump() noexcept
				{
					constexpr std::uint64_t jump_table[] = {
							0x180ec6d33cfd0aba,
							0xd5a61266f0c9392c,
							0xa9582618e03fc9aa,
							0x39abdc4529b1661c,
					};

					state_type temporary_state{};
					for (std::uint32_t jump_table_index = 0; jump_table_index < std::ssize(jump_table); jump_table_index++)
					{
						for (std::uint32_t b = 0; b < 64; b++)
						{
							if (jump_table[jump_table_index] & (static_cast<std::uint64_t>(1) << b))
							{
								temporary_state[0] ^= state[0];
								temporary_state[1] ^= state[1];
								temporary_state[2] ^= state[2];
								temporary_state[3] ^= state[3];
							}
							operator()();
						}
					}

					state[0] = temporary_state[0];
					state[1] = temporary_state[1];
					state[2] = temporary_state[2];
					state[3] = temporary_state[3];
				}

				/*
					This is the jump function for the generator.
					It is equivalent to 2^192 calls to operator()();
					It can be used to generate 2^64 starting points,
					From each of which jump() will generate 2^64 non-overlapping subsequences for parallel distributed computations.
				*/
				constexpr void long_jump() noexcept
				{
					constexpr std::uint64_t long_jump_table[] = {
							0x76e15d3efefdcbbf,
							0xc5004e441c522fb3,
							0x77710069854ee241,
							0x39109bb02acbe635,
					};

					state_type temporary_state{};
					for (std::uint32_t long_jump_table_index = 0; long_jump_table_index < std::ssize(long_jump_table); long_jump_table_index++)
					{
						for (std::uint32_t b = 0; b < 64; b++)
						{
							if (long_jump_table[long_jump_table_index] & (static_cast<std::uint64_t>(1) << b))
							{
								temporary_state[0] ^= state[0];
								temporary_state[1] ^= state[1];
								temporary_state[2] ^= state[2];
								temporary_state[3] ^= state[3];
							}
							operator()();
						}
					}

					state[0] = temporary_state[0];
					state[1] = temporary_state[1];
					state[2] = temporary_state[2];
					state[3] = temporary_state[3];
				}

				constexpr bool operator==(const xorshiro256&) const noexcept = default;

				template <typename CharT, typename Traits>
				friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os, const xorshiro256& e)
				{
					os << e.state[0];
					for (int i = 1; i < num_state_words; ++i)
					{
						os.put(os.widen(' '));
						os << e.state[i];
					}
					return os;
				}

				template <typename CharT, typename Traits>
				friend std::basic_istream<CharT, Traits&> operator>>(std::basic_istream<CharT, Traits>& is, xorshiro256& e)
				{
					xorshiro256 r;
					// TODO: what if ' ' is not considered whitespace?
					// Maybe more appropriate is to `.get` each space
					for (auto& s : r.state)
						is >> s;
					if (is)
						e = r;
					return is;
				}

			private:
				state_type state;

				void generate_number_state_seeds(std::seed_seq& s_q)
				{
					std::uint32_t this_temparory_state[num_state_words * 2];
					s_q.generate(std::begin(this_temparory_state), std::end(this_temparory_state));
					for (std::uint32_t index = 0; index < num_state_words; ++index)
					{
						state[index] = this_temparory_state[index * 2];
						state[index] <<= 32;
						state[index] |= this_temparory_state[index * 2 + 1];
					}
				}

				void generate_number_state_seeds(std::span<const result_type> seed_span)
				{
					std::uint32_t this_temparory_state[num_state_words * 2];

					auto seed_span_begin = seed_span.begin();
					auto seed_span_end = seed_span.end();
					result_type seed = 0;
					auto splitmix64 = [&seed_span_begin, &seed_span_end, &seed]() mutable {

						auto z = (seed += 0x9e3779b97f4a7c15);
						z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
						z = (z ^ (z >> 27)) * 0x94d049bb133111eb;

						if (seed_span_begin != seed_span_end)
						{
							++seed_span_begin;
						}

						return z ^ (z >> 31);
					};
					std::ranges::generate(this_temparory_state, splitmix64);
					seed = 0;

					for (std::uint32_t index = 0; index < num_state_words; ++index)
					{
						state[index] = this_temparory_state[index * 2];
						state[index] <<= 32;
						state[index] |= this_temparory_state[index * 2 + 1];
					}
				}
			};

			struct xorshiro512 : UniformRandomBitGenerator<std::uint64_t>
			{
				static constexpr std::uint32_t num_state_words = 8;
				using state_type = std::array<std::uint64_t, num_state_words>;

				std::size_t state_position = 0;

				// cannot initialize with an all-zero state
				constexpr xorshiro512() noexcept
					: state{ 12, 34 }
				{
				}

				// using SplitMix64 generator to initialize the state;
				// using a different generator helps prevent seed correlation
				explicit constexpr xorshiro512(result_type seed) noexcept
				{
					auto splitmix64 = [seed_value = seed]() mutable {
						auto z = (seed_value += 0x9e3779b97f4a7c15);
						z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
						z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
						return z ^ (z >> 31);
					};
					std::ranges::generate(state, splitmix64);
				}

				explicit xorshiro512(std::initializer_list<result_type> initializer_list_args)
				{
					*this = xorshiro512(initializer_list_args.begin(), initializer_list_args.end());
				}

				template <std::input_or_output_iterator SeedDataIteratorType>
					requires
				(
					not std::convertible_to<SeedDataIteratorType, result_type>
					)
					explicit xorshiro512(SeedDataIteratorType&& begin, SeedDataIteratorType&& end)
				{
					std::vector<result_type> seed_vector{ begin, end };
					this->generate_number_state_seeds(seed_vector);
					seed_vector.clear();
					seed_vector.shrink_to_fit();
				}

				explicit xorshiro512(std::span<const result_type> seed_span)
				{
					this->generate_number_state_seeds(seed_span);
				}

				explicit xorshiro512(std::seed_seq& s_q)
				{
					this->generate_number_state_seeds(s_q);
				}

				constexpr void seed() noexcept
				{
					*this = xorshiro512();
				}
				constexpr void seed(result_type s) noexcept
				{
					*this = xorshiro512(s);
				}
				template <typename SeedSeq>
					requires(not std::convertible_to<SeedSeq, result_type>)
				constexpr void seed(SeedSeq& q)
				{
					*this = xorshiro512(q);
				}

				constexpr result_type operator()() noexcept
				{
					const std::size_t this_state_position = this->state_position;
					this->state_position = (this->state_position + 1) & 15;

					// xorshiro512+:
					// const auto result = s[0] + s[2];
					// xorshiro512++:
					// const auto result = std::rotl(s[0] + s[2], 17) + s[2];

					// xorshiro512**:
					const auto result = std::rotl(state[1] * 5, 7) * 9;

					const auto t = state[1] << 11;

					state[2] ^= state[0];
					state[5] ^= state[1];
					state[1] ^= state[2];
					state[7] ^= state[3];
					state[3] ^= state[4];
					state[4] ^= state[5];
					state[0] ^= state[6];
					state[6] ^= state[7];

					state[6] ^= t;

					state[7] = std::rotl(state[7], 21);

					return result;
				}

				constexpr void discard(std::uint64_t round) noexcept
				{
					if (round == 0)
						return;

					while (round--)
						operator()();
				}

				/*
					This is the jump function for the generator.
					It is equivalent to 2^256 calls to operator()();
					It can be used to generate 2^256 non-overlapping subsequences for parallel computations.
				*/
				constexpr void jump() noexcept
				{
					constexpr std::uint64_t jump_table[] = {
							0x33ed89b6e7a353f9, 0x760083d7955323be,
							0x2837f2fbb5f22fae, 0x4b8c5674d309511c,
							0xb11ac47a7ba28c25, 0xf1be7667092bcc1c,
							0x53851efdb6df0aaf, 0x1ebbc8b23eaf25db
					};

					state_type temporary_state{};
					for (std::uint32_t jump_table_index = 0; jump_table_index < std::ssize(jump_table); jump_table_index++)
					{
						for (std::uint32_t b = 0; b < 64; b++)
						{
							if (jump_table[jump_table_index] & (static_cast<std::uint64_t>(1) << b))
							{
								temporary_state[0] ^= state[0];
								temporary_state[1] ^= state[1];
								temporary_state[2] ^= state[2];
								temporary_state[3] ^= state[3];
								temporary_state[4] ^= state[4];
								temporary_state[5] ^= state[5];
								temporary_state[6] ^= state[6];
								temporary_state[7] ^= state[7];
							}
							operator()();
						}
					}

					temporary_state[0] = state[0];
					temporary_state[1] = state[1];
					temporary_state[2] = state[2];
					temporary_state[3] = state[3];
					temporary_state[4] = state[4];
					temporary_state[5] = state[5];
					temporary_state[6] = state[6];
					temporary_state[7] = state[7];
				}

				/*
					This is the long-jump function for the generator.
					It is equivalent to 2^384 calls to operator()();
					It can be used to generate 2^128 starting points,
					from each of which jump() will generate 2^128 non-overlapping subsequences for parallel distributed computations.
				*/
				constexpr void long_jump() noexcept
				{
					constexpr std::uint64_t long_jump_table[] = {
							0x11467fef8f921d28, 0xa2a819f2e79c8ea8,
							0xa8299fc284b3959a, 0xb4d347340ca63ee1,
							0x1cb0940bedbff6ce, 0xd956c5c4fa1f8e17,
							0x915e38fd4eda93bc, 0x5b3ccdfa5d7daca5
					};

					state_type temporary_state{};
					for (std::uint32_t long_jump_table_index = 0; long_jump_table_index < std::ssize(long_jump_table); long_jump_table_index++)
					{
						for (std::uint32_t b = 0; b < 64; b++)
						{
							if (long_jump_table[long_jump_table_index] & (static_cast<std::uint64_t>(1) << b))
							{
								temporary_state[0] ^= state[0];
								temporary_state[1] ^= state[1];
								temporary_state[2] ^= state[2];
								temporary_state[3] ^= state[3];
								temporary_state[4] ^= state[4];
								temporary_state[5] ^= state[5];
								temporary_state[6] ^= state[6];
								temporary_state[7] ^= state[7];

							}
							operator()();
						}
					}

					temporary_state[0] = state[0];
					temporary_state[1] = state[1];
					temporary_state[2] = state[2];
					temporary_state[3] = state[3];
					temporary_state[4] = state[4];
					temporary_state[5] = state[5];
					temporary_state[6] = state[6];
					temporary_state[7] = state[7];
				}

			private:
				state_type state;

				void generate_number_state_seeds(std::seed_seq& s_q)
				{
					std::uint32_t this_temparory_state[num_state_words * 2];
					s_q.generate(std::begin(this_temparory_state), std::end(this_temparory_state));
					for (std::uint32_t index = 0; index < num_state_words; ++index)
					{
						state[index] = this_temparory_state[index * 2];
						state[index] <<= 32;
						state[index] |= this_temparory_state[index * 2 + 1];
					}
				}

				void generate_number_state_seeds(std::span<const result_type> seed_span)
				{
					std::uint32_t this_temparory_state[num_state_words * 2];

					auto seed_span_begin = seed_span.begin();
					auto seed_span_end = seed_span.end();
					result_type seed = 0;
					auto splitmix64 = [&seed_span_begin, &seed_span_end, &seed]() mutable {

						auto z = (seed += 0x9e3779b97f4a7c15);
						z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
						z = (z ^ (z >> 27)) * 0x94d049bb133111eb;

						if (seed_span_begin != seed_span_end)
						{
							++seed_span_begin;
						}

						return z ^ (z >> 31);
					};
					std::ranges::generate(this_temparory_state, splitmix64);
					seed = 0;

					for (std::uint32_t index = 0; index < num_state_words; ++index)
					{
						state[index] = this_temparory_state[index * 2];
						state[index] <<= 32;
						state[index] |= this_temparory_state[index * 2 + 1];
					}
				}
			};

			struct xorshiro1024 : UniformRandomBitGenerator<std::uint64_t>
			{
				static constexpr std::uint32_t num_state_words = 16;
				using state_type = std::array<std::uint64_t, num_state_words>;

				std::size_t state_position = 0;

				// cannot initialize with an all-zero state
				constexpr xorshiro1024() noexcept
					: state{ 12, 34 }
				{
				}

				// using SplitMix64 generator to initialize the state;
				// using a different generator helps prevent seed correlation
				explicit constexpr xorshiro1024(result_type seed) noexcept
				{
					auto splitmix64 = [seed_value = seed]() mutable {
						auto z = (seed_value += 0x9e3779b97f4a7c15);
						z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
						z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
						return z ^ (z >> 31);
					};
					std::ranges::generate(state, splitmix64);
				}

				explicit xorshiro1024(std::initializer_list<result_type> initializer_list_args)
				{
					*this = xorshiro1024(initializer_list_args.begin(), initializer_list_args.end());
				}

				template <std::input_or_output_iterator SeedDataIteratorType>
					requires
				(
					not std::convertible_to<SeedDataIteratorType, result_type>
					)
					explicit xorshiro1024(SeedDataIteratorType&& begin, SeedDataIteratorType&& end)
				{
					std::vector<result_type> seed_vector{ begin, end };
					this->generate_number_state_seeds(seed_vector);
					seed_vector.clear();
					seed_vector.shrink_to_fit();
				}

				explicit xorshiro1024(std::span<const result_type> seed_span)
				{
					this->generate_number_state_seeds(seed_span);
				}

				explicit xorshiro1024(std::seed_seq& s_q)
				{
					this->generate_number_state_seeds(s_q);
				}

				constexpr void seed() noexcept
				{
					*this = xorshiro1024();
				}
				constexpr void seed(result_type s) noexcept
				{
					*this = xorshiro1024(s);
				}
				template <typename SeedSeq>
					requires(not std::convertible_to<SeedSeq, result_type>)
				constexpr void seed(SeedSeq& q)
				{
					*this = xorshiro1024(q);
				}

				constexpr result_type operator()() noexcept
				{
					const std::size_t this_state_position = this->state_position;
					this->state_position = (this->state_position + 1) & 15;

					// xorshiro1024++:
					// const auto result = std::rotl(a + b, 23) + a;
					// xorshiro1024*:
					// const auto result = a * 0x9e3779b97f4a7c13;

					// xorshiro1024**:
					const auto a = state[this->state_position];
					const auto result = std::rotl(a * 5, 7) * 9;
					auto b = state[this_state_position];

					b ^= a;
					state[this_state_position] = std::rotl(a, 25) ^ b ^ (b << 27);
					state[this->state_position] = std::rotl(b, 36);

					return result;
				}

				constexpr void discard(std::uint64_t round) noexcept
				{
					if (round == 0)
						return;

					while (round--)
						operator()();
				}

				/*
					This is the jump function for the generator.
					It is equivalent to 2^512 calls to operator()();
					It can be used to generate 2^512 non-overlapping subsequences for parallel computations.
				*/
				constexpr void jump() noexcept
				{
					constexpr std::uint64_t jump_table[] = {
							0x931197d8e3177f17, 0xb59422e0b9138c5f,
							0xf06a6afb49d668bb, 0xacb8a6412c8a1401,
							0x12304ec85f0b3468, 0xb7dfe7079209891e,
							0x405b7eec77d9eb14, 0x34ead68280c44e4a,
							0xe0e4ba3e0ac9e366, 0x8f46eda8348905b7,
							0x328bf4dbad90d6ff, 0xc8fd6fb31c9effc3,
							0xe899d452d4b67652, 0x45f387286ade3205,
							0x03864f454a8920bd, 0xa68fa28725b1b384
					};

					state_type temporary_state{};
					for (std::uint32_t jump_table_index = 0; jump_table_index < std::ssize(jump_table); jump_table_index++)
					{
						for (std::uint32_t b = 0; b < 64; b++)
						{
							if (jump_table[jump_table_index] & (static_cast<std::uint64_t>(1) << b))
							{
								temporary_state[0] ^= state[0];
								temporary_state[1] ^= state[1];
								temporary_state[2] ^= state[2];
								temporary_state[3] ^= state[3];
								temporary_state[4] ^= state[4];
								temporary_state[5] ^= state[5];
								temporary_state[6] ^= state[6];
								temporary_state[7] ^= state[7];
								temporary_state[8] ^= state[8];
								temporary_state[9] ^= state[9];
								temporary_state[10] ^= state[10];
								temporary_state[11] ^= state[11];
								temporary_state[12] ^= state[12];
								temporary_state[13] ^= state[13];
								temporary_state[14] ^= state[14];
								temporary_state[15] ^= state[15];
							}
							operator()();
						}
					}

					temporary_state[0] = state[0];
					temporary_state[1] = state[1];
					temporary_state[2] = state[2];
					temporary_state[3] = state[3];
					temporary_state[4] = state[4];
					temporary_state[5] = state[5];
					temporary_state[6] = state[6];
					temporary_state[7] = state[7];
					temporary_state[8] = state[8];
					temporary_state[9] = state[9];
					temporary_state[10] = state[10];
					temporary_state[11] = state[11];
					temporary_state[12] = state[12];
					temporary_state[13] = state[13];
					temporary_state[14] = state[14];
					temporary_state[15] = state[15];
				}

				/*
					This is the long-jump function for the generator.
					It is equivalent to 2^768 calls to operator()();
					It can be used to generate 2^256 starting points,
					from each of which jump() will generate 2^256 non-overlapping subsequences for parallel distributed computations.
				*/
				constexpr void long_jump() noexcept
				{
					constexpr std::uint64_t long_jump_table[] = {
							0x7374156360bbf00f, 0x4630c2efa3b3c1f6,
							0x6654183a892786b1, 0x94f7bfcbfb0f1661,
							0x27d8243d3d13eb2d, 0x9701730f3dfb300f,
							0x2f293baae6f604ad, 0xa661831cb60cd8b6,
							0x68280c77d9fe008c, 0x50554160f5ba9459,
							0x2fc20b17ec7b2a9a, 0x49189bbdc8ec9f8f,
							0x92a65bca41852cc1, 0xf46820dd0509c12a,
							0x52b00c35fbf92185, 0x1e5b3b7f589e03c1
					};

					state_type temporary_state{};
					for (std::uint32_t long_jump_table_index = 0; long_jump_table_index < std::ssize(long_jump_table); long_jump_table_index++)
					{
						for (std::uint32_t b = 0; b < 64; b++)
						{
							if (long_jump_table[long_jump_table_index] & (static_cast<std::uint64_t>(1) << b))
							{
								temporary_state[0] ^= state[0];
								temporary_state[1] ^= state[1];
								temporary_state[2] ^= state[2];
								temporary_state[3] ^= state[3];
								temporary_state[4] ^= state[4];
								temporary_state[5] ^= state[5];
								temporary_state[6] ^= state[6];
								temporary_state[7] ^= state[7];
								temporary_state[8] ^= state[8];
								temporary_state[9] ^= state[9];
								temporary_state[10] ^= state[10];
								temporary_state[11] ^= state[11];
								temporary_state[12] ^= state[12];
								temporary_state[13] ^= state[13];
								temporary_state[14] ^= state[14];
								temporary_state[15] ^= state[15];

							}
							operator()();
						}
					}

					temporary_state[0] = state[0];
					temporary_state[1] = state[1];
					temporary_state[2] = state[2];
					temporary_state[3] = state[3];
					temporary_state[4] = state[4];
					temporary_state[5] = state[5];
					temporary_state[6] = state[6];
					temporary_state[7] = state[7];
					temporary_state[8] = state[8];
					temporary_state[9] = state[9];
					temporary_state[10] = state[10];
					temporary_state[11] = state[11];
					temporary_state[12] = state[12];
					temporary_state[13] = state[13];
					temporary_state[14] = state[14];
					temporary_state[15] = state[15];
				}

			private:
				state_type state;

				void generate_number_state_seeds(std::seed_seq& s_q)
				{
					std::uint32_t this_temparory_state[num_state_words * 2];
					s_q.generate(std::begin(this_temparory_state), std::end(this_temparory_state));
					for (std::uint32_t index = 0; index < num_state_words; ++index)
					{
						state[index] = this_temparory_state[index * 2];
						state[index] <<= 32;
						state[index] |= this_temparory_state[index * 2 + 1];
					}
				}

				void generate_number_state_seeds(std::span<const result_type> seed_span)
				{
					std::uint32_t this_temparory_state[num_state_words * 2];

					auto seed_span_begin = seed_span.begin();
					auto seed_span_end = seed_span.end();
					result_type seed = 0;
					auto splitmix64 = [&seed_span_begin, &seed_span_end, &seed]() mutable {

						auto z = (seed += 0x9e3779b97f4a7c15);
						z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
						z = (z ^ (z >> 27)) * 0x94d049bb133111eb;

						if (seed_span_begin != seed_span_end)
						{
							++seed_span_begin;
						}

						return z ^ (z >> 31);
					};
					std::ranges::generate(this_temparory_state, splitmix64);
					seed = 0;

					for (std::uint32_t index = 0; index < num_state_words; ++index)
					{
						state[index] = this_temparory_state[index * 2];
						state[index] <<= 32;
						state[index] |= this_temparory_state[index * 2 + 1];
					}
				}
			};

		}  // namespace RNG_Xorshiro
	}

	//CryptographicallySecurePseudoRandomNumberGenerator
	namespace CSPRNG
	{
		/*
		C++20 isaac cryptographically secure pseudorandom number generator implementation
		ISAAC (indirection, shift, accumulate, add, and count) is a cryptographically secure pseudorandom number generator and a stream cipher designed by Robert J. Jenkins Jr. in 1993.[1]
		The reference implementation source code was dedicated to the public domain.[2]
		https://en.wikipedia.org/wiki/ISAAC_(cipher)
		http://rosettacode.org/wiki/The_ISAAC_Cipher

		This work is derived from the ISAAC random number generator, created by Bob Jenkins,
		which he has generously put in the public domain.
		All design credit goes to Bob Jenkins.
		Details of the algorithm, and the original C source can be found at
		http://burtleburtle.net/bob/rand/isaacafa.html.
		This work is a C++ translation and re-packaging of the original C code to make it meet the requirements for a random number engine,
		as specified in paragraph 26.5.1.4 of the C++ language standard.
		As such, it can be used in conjunction with other elements in the random number generation facility,
		such as distributions and engine adaptors. Created by David Curtis, 2016. Public Domain.

		Plus versions of the ISAAC and ISAAC64 algorithms, referenced by Twilight-Dream from Bob Jenkins' paper, upgrade the original algorithms and implement them.

		A cryptographically secure pseudorandom number generator (CSPRNG) or cryptographic pseudorandom number generator (CPRNG)[1] is a pseudorandom number generator (PRNG) with properties that make it suitable for use in cryptography.
		It is also loosely known as a cryptographic random number generator (CRNG) (see Random number generation § "True" vs. pseudo-random numbers).[2][3]

		Most cryptographic applications require random numbers, for example:
		key generation
		nonces
		salts in certain signature schemes, including ECDSA, RSASSA-PSS
		The "quality" of the randomness required for these applications varies. For example, creating a nonce in some protocols needs only uniqueness.
		On the other hand, the generation of a master key requires a higher quality, such as more entropy.
		And in the case of one-time pads, the information-theoretic guarantee of perfect secrecy only holds if the key material comes from a true random source with high entropy, and thus any kind of pseudorandom number generator is insufficient.

		Ideally, the generation of random numbers in CSPRNGs uses entropy obtained from a high-quality source, generally the operating system's randomness API.
		However, unexpected correlations have been found in several such ostensibly independent processes.
		From an information-theoretic point of view, the amount of randomness, the entropy that can be generated, is equal to the entropy provided by the system.
		But sometimes, in practical situations, more random numbers are needed than there is entropy available.
		Also, the processes to extract randomness from a running system are slow in actual practice. In such instances, a CSPRNG can sometimes be used.
		A CSPRNG can "stretch" the available entropy over more bits.
		https://en.wikipedia.org/wiki/Cryptographically-secure_pseudorandom_number_generator

		Reference source code:
		https://github.com/edgeofmagic/ISAAC-engine/
		https://github.com/rubycon/isaac.js/blob/master/isaac.js

		Reference paper:
		http://eprint.iacr.org/2006/438.pdf
	*/
		namespace ISAAC
		{

			/*
				RNG_ISAAC contains code common to isaac and isaac64.
				It uses CRTP (a.k.a. 'static polymorphism') to invoke specialized methods in the derived class templates,
				avoiding the cost of virtual method invocations and allowing those methods to be placed inline by the compiler.
				Applications should not specialize or instantiate this template directly.
			*/

			template<std::size_t Alpha, class T>
			class RNG_ISAAC
			{
			public:
				using result_type = T;

				static constexpr std::size_t state_size = 1 << Alpha;

				static constexpr result_type default_seed = 0;

				RNG_ISAAC()
				{
					seed(default_seed);
				}

				explicit RNG_ISAAC(result_type seed_number)
					: issac_base_member_counter(state_size)
				{
					seed(seed_number);
				}

				template <typename SeedSeq>
					requires(not std::convertible_to<SeedSeq, result_type>)
				explicit RNG_ISAAC(SeedSeq& number_sequence)
					: issac_base_member_counter(state_size)
				{
					seed(number_sequence);
				}

				RNG_ISAAC(const std::vector<result_type>& seed_vector)
					: issac_base_member_counter(state_size)
				{
					seed(seed_vector);
				}

				template<class IteratorType>
				RNG_ISAAC
				(
					IteratorType begin,
					IteratorType end,
					typename std::enable_if
					<
					std::is_integral<typename std::iterator_traits<IteratorType>::value_type>::value&&
					std::is_unsigned<typename std::iterator_traits<IteratorType>::value_type>::value
					>::type* = nullptr
				)
					: issac_base_member_counter(state_size)
				{
					seed(begin, end);
				}

				RNG_ISAAC(std::random_device& random_device_object)
					: issac_base_member_counter(state_size)
				{
					seed(random_device_object);
				}

				RNG_ISAAC(const RNG_ISAAC& other)
					: issac_base_member_counter(state_size)
				{
					for (std::size_t index = 0; index < state_size; ++index)
					{
						issac_base_member_result[index] = other.issac_base_member_result[index];
						issac_base_member_memory[index] = other.issac_base_member_memory[index];
					}
					issac_base_member_register_a = other.issac_base_member_register_a;
					issac_base_member_register_b = other.issac_base_member_register_b;
					issac_base_member_register_c = other.issac_base_member_register_c;
					issac_base_member_counter = other.issac_base_member_counter;
				}

			public:

				static constexpr result_type min()
				{
					return std::numeric_limits<result_type>::min();
				}
				static constexpr result_type max()
				{
					return std::numeric_limits<result_type>::max();
				}

				inline void seed(result_type seed_number)
				{
					for (std::size_t index = 0; index < state_size; ++index)
					{
						issac_base_member_result[index] = seed_number;
					}
					init();
				}

				template <typename SeedSeq>
					requires(not std::convertible_to<SeedSeq, result_type>)
				void seed(SeedSeq& number_sequence)
				{
					std::seed_seq my_seed_sequence(number_sequence.begin(), number_sequence.end());
					std::array<result_type, state_size> seed_array;
					my_seed_sequence.generate(seed_array.begin(), seed_array.end());
					for (std::size_t index = 0; index < state_size; ++index)
					{
						issac_base_member_result[index] = seed_array[index];
					}
					init();
				}

				template<class IteratorType>
				inline typename std::enable_if
					<
					std::is_integral<typename std::iterator_traits<IteratorType>::value_type>::value&&
					std::is_unsigned<typename std::iterator_traits<IteratorType>::value_type>::value, void
					>::type
					seed(IteratorType begin, IteratorType end)
				{
					IteratorType iterator = begin;
					for (std::size_t index = 0; index < state_size; ++index)
					{
						if (iterator == end)
						{
							iterator = begin;
						}
						issac_base_member_result[index] = *iterator;
						++iterator;
					}
					init();
				}

				void seed(std::random_device& random_device_object)
				{
					std::vector<result_type> random_seed_vector;
					random_seed_vector.reserve(state_size);
					for (std::size_t round = 0; round < state_size; ++round)
					{
						result_type seed_number_value = GenerateSecureRandomNumberSeed<result_type>(random_device_object);

						std::size_t bytes_filled{ sizeof(std::random_device::result_type) };
						while (bytes_filled < sizeof(result_type))
						{
							result_type seed_number_value2 = GenerateSecureRandomNumberSeed<result_type>(random_device_object);

							seed_number_value <<= (sizeof(std::random_device::result_type) * 8);
							seed_number_value |= seed_number_value2;
							bytes_filled += sizeof(std::random_device::result_type);
						}
						random_seed_vector.push_back(seed_number_value);
					}
					seed(random_seed_vector.begin(), random_seed_vector.end());
				}

				inline result_type operator()()
				{
					if (issac_base_member_counter - 1 == std::numeric_limits<std::size_t>::max())
						issac_base_member_counter = state_size - 1;

					return (!issac_base_member_counter--) ? (do_isaac(), issac_base_member_result[issac_base_member_counter]) : issac_base_member_result[issac_base_member_counter];
				}

				inline void discard(unsigned long long z)
				{
					for (; z; --z) operator()();
				}

				friend bool operator==(const RNG_ISAAC& left, const RNG_ISAAC& right)
				{
					bool equal = true;
					if (left.issac_base_member_register_a != right.issac_base_member_register_a || left.issac_base_member_register_b != right.issac_base_member_register_b || left.issac_base_member_register_c != right.issac_base_member_register_c || left.issac_base_member_counter != right.issac_base_member_counter)
					{
						equal = false;
					}
					else
					{
						for (std::size_t index = 0; index < state_size; ++index)
						{
							if (left.issac_base_member_result[index] != right.issac_base_member_result[index] || left.issac_base_member_memory[index] != right.issac_base_member_memory[index])
							{
								equal = false;
								break;
							}
						}
					}
					return equal;
				}

				friend bool operator!=(const RNG_ISAAC& left, const RNG_ISAAC& right)
				{
					return !(left == right);
				}

				template <class CharT, class Traits>
				friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os, const RNG_ISAAC& isaac_base_object)
				{
					auto format_flags = os.flags();
					os.flags(std::ios_base::dec | std::ios_base::left);
					CharT sp = os.widen(' ');
					os.fill(sp);
					os << isaac_base_object.issac_base_member_counter;

					for (std::size_t index = 0; index < state_size; ++index)
					{
						os << sp << isaac_base_object.issac_base_member_result[index];
					}

					for (std::size_t index = 0; index < state_size; ++index)
					{
						os << sp << isaac_base_object.issac_base_member_memory[index];
					}
					os << sp << isaac_base_object.issac_base_member_register_a << sp << isaac_base_object.issac_base_member_register_b << sp << isaac_base_object.issac_base_member_register_c;

					os.flags(format_flags);
					return os;
				}

				template <class CharT, class Traits>
				friend std::basic_istream<CharT, Traits>&
					operator>>(std::basic_istream<CharT, Traits>& is, RNG_ISAAC& isaac_base_object)
				{
					bool failed = false;
					result_type temporary_result[state_size];
					result_type temporary_memory[state_size];
					result_type temporary_register_a = 0;
					result_type temporary_register_b = 0;
					result_type temporary_register_c = 0;
					std::size_t temporary_register_counter = 0;

					auto format_flags = is.flags();
					is.flags(std::ios_base::dec | std::ios_base::skipws);

					is >> temporary_register_counter;
					if (is.fail())
					{
						failed = true;
					}

					std::size_t process_counter = 0;

					while (process_counter != 5)
					{
						for (std::size_t index = 0; index < state_size; ++index)
						{
							is >> temporary_result[index];
							if (is.fail())
							{
								failed = true;
								break;
							}
						}

						++process_counter;

						for (std::size_t index = 0; index < state_size; ++index)
						{
							is >> temporary_memory[index];
							if (is.fail())
							{
								failed = true;
								break;
							}
						}

						++process_counter;

						is >> temporary_register_a;
						if (is.fail())
						{
							failed = true;
							break;
						}

						++process_counter;

						is >> temporary_register_b;
						if (is.fail())
						{
							failed = true;
							break;
						}

						++process_counter;

						is >> temporary_register_c;
						if (is.fail())
						{
							failed = true;
							break;
						}

						++process_counter;
					}

					if (!failed)
					{
						for (std::size_t i = 0; i < state_size; ++i)
						{
							isaac_base_object.issac_base_member_result[i] = temporary_result[i];
							isaac_base_object.issac_base_member_memory[i] = temporary_memory[i];
						}
						isaac_base_object.issac_base_member_register_a = temporary_register_a;
						isaac_base_object.issac_base_member_register_b = temporary_register_b;
						isaac_base_object.issac_base_member_register_c = temporary_register_c;
						isaac_base_object.issac_base_member_counter = temporary_register_counter;
					}
					else
					{
						is.setstate(std::ios::failbit); // should already be set, just making certain
					}

					is.flags(format_flags);
					return is;
				}

				~RNG_ISAAC() = default;

			private:

				/*
					ISAAC (Indirection, Shift, Accumulate, Add, and Count) generates 32-bit random numbers.
					Averaged out, it requires 18.75 machine cycles to generate each 32-bit value.
					Cycles are guaranteed to be at least 2(^)40 values long, and they are 2(^)8295 values long on average.
					The results are uniformly distributed, unbiased, and unpredictable unless you know the seed.
				*/

				//Use ISAAC+ Algorithm (32 bit)?
#if 1

				void implementation_isaac()
				{
					using TwilightDreamOfMagical::BaseOperation::rotate_left;
					using TwilightDreamOfMagical::BaseOperation::rotate_right;

					/*
						Modulo a power of two, the following works (assuming twos complement representation):

						i mod n == i & (n-1) when n is a power of two and mod is the aforementioned positive mod.
						(FYI: modulus is the common mathematical term for the "divisor" when a modulo operation is considered).

						return i & (n-1);

						auto lambda_Modulo = [](result_type value, result_type modulo_value)
						{
							return modulo_value & ( modulo_value - 1) ? value % modulo_value : value & ( modulo_value - 1);
						};
					*/

					result_type index = 0, x = 0, y = 0, state_random_value = 0;

					result_type accumulate = this->issac_base_member_register_a;
					result_type bit_result = this->issac_base_member_register_b + (++(this->issac_base_member_register_c)); //b ← (c + 1)

					for (index = 0; index < this->state_size; ++index)
					{
						//x ← state[index]
						x = this->issac_base_member_memory[index];
						/*
							//barrel shift

							function(a, index)
							{
								if index ≡ 0 mod 4
									return a ^= a << 13
								if index ≡ 1 mod 4
									return a ^= a << 6
								if index ≡ 2 mod 4
									return a ^= a << 2
								if index ≡ 3 mod 4
									return a ^= a << 16
							}

							mix_index ← function(a, index);
						*/
						switch (index & 3)
						{
						case 0:
							accumulate ^= accumulate << 13;
							break;
						case 1:
							accumulate ^= accumulate >> 6;
							break;
						case 2:
							accumulate ^= accumulate << 2;
							break;
						case 3:
							accumulate ^= accumulate >> 16;
							break;
						}
						// a(mix_index) + state[index] + 128 mod 256
						accumulate += this->issac_base_member_memory[(index + this->state_size / 2) & (this->state_size - 1)];
						//state[index] ← a(mix_index) ⊕ b + (state[x] >>> 2) mod 256
						//y == state[index]
						state_random_value = this->issac_base_member_memory[rotate_right(x, 2) & (this->state_size - 1)];
						y = accumulate ^ bit_result + state_random_value;
						this->issac_base_member_memory[index] = y;
						//result[index] ← x + a(mix_index) ⊕ (state[state[index]] >>> 10) mod 256
						//b == result[index]
						state_random_value = this->issac_base_member_memory[rotate_right(y, 10) & (this->state_size - 1)];
						bit_result = x + accumulate ^ state_random_value;
						this->issac_base_member_result[index] = bit_result;
					}
				}

#else

				//Diffusion of integer numbers by indirection memory address
			//通过指示性内存地址扩散整数
				inline result_type diffusion_with_indirection_memory_address(result_type* memory_pointer, result_type current_value)
				{
					/*
						Modulo a power of two, the following works (assuming twos complement representation):

						i mod n == i & (n-1) when n is a power of two and mod is the aforementioned positive mod.
						(FYI: modulus is the common mathematical term for the "divisor" when a modulo operation is considered).

						return i & (n-1);
					*/

					constexpr result_type mask = (this->state_size - 1) << 2;
					//access state[index]
					return *reinterpret_cast<result_type*>(reinterpret_cast<std::uint8_t*>(memory_pointer) + (current_value & mask));
				}

				inline void RNG_do_step
				(
					const result_type mix,
					result_type& a,
					result_type& b,
					result_type*& old_memory_array,
					result_type*& update_memory_array,
					result_type*& new_memory_array,
					result_type*& current_result_array,
					result_type& x,
					result_type& y
				)
				{
					//x ← state[index]
					//x == state[index]
					x = *update_memory_array;
					/*
					This should use the modulo operation to address memory with state values, because this->state_size is a value that belongs to a power of 2.
					So assuming that Alpha is an 8-bit state, the value of this->state_size is: "1 << 8 == 256"
					And after understanding the bit manipulation, we know that the calculation of the power of 2 is: "2 & (number - 1)".
					So the ISAAC paper gives the calculation of "state[index] + 128 mod 256, and the derivation should be: state[index + (this->state_size / 2) & (this-> state_size - 1)]"

					This is the same as the initialization part of the previous for loop
					new_memory_array_address = new_memory_array = update_memory_array + (this->state_size / 2);
					*/
					//a ← function(a, mix_index) + state[index] + 128 mod 256
					a = (a ^ (mix)) + *(new_memory_array++);
					//state[index] ← a + b + (state[x] >> 2) mod 256
					//y == state[index]
					*(update_memory_array++) = y = a + b + diffusion_with_indirection_memory_address(old_memory_array, x);
					//result[index] ← x + (state[state[index]] >> 10) mod 256
					//b == result[index]
					*(current_result_array++) = b = x + diffusion_with_indirection_memory_address(old_memory_array, y >> Alpha);
				}

				void implementation_isaac()
				{
					result_type x = 0;
					result_type y = 0;

					result_type* update_memory_array = nullptr;
					result_type* new_memory_array = nullptr;
					result_type* new_memory_array_address = nullptr;

					result_type* old_memory_array = this->issac_base_member_memory;
					result_type* current_result_array = this->issac_base_member_result;
					result_type a = this->issac_base_member_register_a;
					result_type b = this->issac_base_member_register_b + (++(this->issac_base_member_register_c)); //b ← (c + 1)

					for (update_memory_array = old_memory_array, new_memory_array_address = new_memory_array = update_memory_array + (this->state_size / 2); update_memory_array < new_memory_array_address; )
					{
						RNG_do_step(a << 13, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step(a >> 6, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step(a << 2, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step(a >> 16, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					}
					for (new_memory_array = old_memory_array; new_memory_array < new_memory_array_address; )
					{
						RNG_do_step(a << 13, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step(a >> 6, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step(a << 2, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step(a >> 16, a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					}
					this->issac_base_member_register_b = b;
					this->issac_base_member_register_a = a;
				}

#endif

				/*
					ISAAC-64 generates a different sequence than ISAAC, but it uses the same principles. It uses 64-bit arithmetic.
					It generates a 64-bit result every 19 instructions. All cycles are at least 2(^)72 values, and the average cycle length is 2(^)16583.

					The following files implement ISAAC-64.
					The constants were tuned for a 64-bit machine, and a complement was thrown in so that all-zero states become nonzero faster.
				*/

				//Use ISAAC+ Algorithm (64 bit)?
#if 1

				void implementation_isaac64()
				{
					using TwilightDreamOfMagical::BaseOperation::rotate_left;
					using TwilightDreamOfMagical::BaseOperation::rotate_right;

					/*
						Modulo a power of two, the following works (assuming twos complement representation):

						i mod n == i & (n-1) when n is a power of two and mod is the aforementioned positive mod.
						(FYI: modulus is the common mathematical term for the "divisor" when a modulo operation is considered).

						return i & (n-1);

						auto lambda_Modulo = [](result_type value, result_type modulo_value)
						{
							return modulo_value & ( modulo_value - 1) ? value % modulo_value : value & ( modulo_value - 1);
						};
					*/

					result_type index = 0, x = 0, y = 0, state_random_value = 0;

					result_type accumulate = this->issac_base_member_register_a;
					result_type bit_result = this->issac_base_member_register_b + (++(this->issac_base_member_register_c)); //b ← (c + 1)

					for (index = 0; index < this->state_size; ++index)
					{
						//x ← state[index]
						x = this->issac_base_member_memory[index];
						/*
							//barrel shift

							function(a, index)
							{
								if index ≡ 0 mod 4
									return a ^= ~(a << 21)
								if index ≡ 1 mod 4
									return a ^= a << 5
								if index ≡ 2 mod 4
									return a ^= a << 12
								if index ≡ 3 mod 4
									return a ^= a << 33
							}

							mix_index ← function(a, index);
						*/
						switch (index & 3)
						{
						case 0:
							accumulate ^= ~(accumulate << 21);
							break;
						case 1:
							accumulate ^= accumulate >> 5;
							break;
						case 2:
							accumulate ^= accumulate << 12;
							break;
						case 3:
							accumulate ^= accumulate >> 33;
							break;
						}
						// a(mix_index) + state[index] + 128 mod 256
						accumulate += this->issac_base_member_memory[(index + this->state_size / 2) & (this->state_size - 1)];
						//state[index] ← a(mix_index) ⊕ b + (state[x] >>> 2) mod 256
						//y == state[index]
						state_random_value = this->issac_base_member_memory[rotate_right(x, 2) & (this->state_size - 1)];
						y = accumulate ^ bit_result + state_random_value;
						this->issac_base_member_memory[index] = y;
						//result[index] ← x + a(mix_index) ⊕ (state[state[index]] >>> 10) mod 256
						//b == result[index]
						state_random_value = this->issac_base_member_memory[rotate_right(y, 10) & (this->state_size - 1)];
						bit_result = x + accumulate ^ state_random_value;
						this->issac_base_member_result[index] = bit_result;
					}
				}

#else

				//Diffusion of integer numbers by indirection memory address
			//通过指示性内存地址扩散整数
				inline result_type diffusion_with_indirection_memory_address64(result_type* memory_pointer, result_type current_value)
				{
					/*
						Modulo a power of two, the following works (assuming twos complement representation):

						i mod n == i & (n-1) when n is a power of two and mod is the aforementioned positive mod.
						(FYI: modulus is the common mathematical term for the "divisor" when a modulo operation is considered).

						return i & (n-1);
					*/

					//access state[index]
					constexpr result_type mask = (this->state_size - 1) << 3;
					return *reinterpret_cast<result_type*>(reinterpret_cast<std::uint8_t*>(memory_pointer) + (current_value & mask));
				}

				inline void RNG_do_step64
				(
					const result_type mix,
					result_type& a,
					result_type& b,
					result_type*& old_memory_array,
					result_type*& update_memory_array,
					result_type*& new_memory_array,
					result_type*& current_result_array,
					result_type& x,
					result_type& y
				)
				{
					//x ← state[index]
					//x == state[index]
					x = *update_memory_array;

					/*
					This should use the modulo operation to address memory with state values, because this->state_size is a value that belongs to a power of 2.
					So assuming that Alpha is an 8-bit state, the value of this->state_size is: "1 << 8 == 256"
					And after understanding the bit manipulation, we know that the calculation of the power of 2 is: "2 & (number - 1)".
					So the ISAAC paper gives the calculation of "state[index] + 128 mod 256, and the derivation should be: state[index + (this->state_size / 2) & (this-> state_size - 1)]"

					This is the same as the initialization part of the previous for loop
					new_memory_array_address = new_memory_array = update_memory_array + (this->state_size / 2);
					*/
					//a ← function(a, mix_index) + state[index] + 128 mod 256
					a = (a ^ (mix)) + *(new_memory_array++);
					//state[index] ← a + b + (state[x] >> 2) mod 512
					//y == state[index]
					*(update_memory_array++) = y = a + b + diffusion_with_indirection_memory_address64(old_memory_array, x);
					//result[index] ← x + (state[state[index]] >> 10) mod 512
					//b == result[index]
					*(current_result_array++) = b = x + diffusion_with_indirection_memory_address64(old_memory_array, y >> Alpha);
				}

				void implementation_isaac64()
				{
					result_type x = 0;
					result_type y = 0;

					result_type* update_memory_array = nullptr;
					result_type* new_memory_array = nullptr;
					result_type* new_memory_array_address = nullptr;

					result_type* old_memory_array = this->issac_base_member_memory;
					result_type* current_result_array = this->issac_base_member_result;
					result_type a = this->issac_base_member_register_a;
					result_type b = this->issac_base_member_register_b + (++(this->issac_base_member_register_c)); //b ← (c + 1)

					for (update_memory_array = old_memory_array, new_memory_array_address = new_memory_array = update_memory_array + (this->state_size / 2); update_memory_array < new_memory_array_address; )
					{
						RNG_do_step64(~(a ^ (a << 21)), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step64(a ^ (a >> 5), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step64(a ^ (a << 12), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step64(a ^ (a >> 33), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					}
					for (new_memory_array = old_memory_array; new_memory_array < new_memory_array_address; )
					{
						RNG_do_step64(~(a ^ (a << 21)), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step64(a ^ (a >> 5), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step64(a ^ (a << 12), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
						RNG_do_step64(a ^ (a >> 33), a, b, old_memory_array, update_memory_array, new_memory_array, current_result_array, x, y);
					}
					this->issac_base_member_register_b = b;
					this->issac_base_member_register_a = a;
				}

#endif

				void init()
				{
					result_type a = golden();
					result_type b = golden();
					result_type c = golden();
					result_type d = golden();
					result_type e = golden();
					result_type f = golden();
					result_type g = golden();
					result_type h = golden();

					issac_base_member_register_a = 0;
					issac_base_member_register_b = 0;
					issac_base_member_register_c = 0;

					/* scramble it */
					for (std::size_t index = 0; index < 4; ++index)
					{
						mix(a, b, c, d, e, f, g, h);
					}

					/* initialize using the contents of issac_base_member_result[] as the seed */
					for (std::size_t index = 0; index < state_size; index += 8)
					{
						a += issac_base_member_result[index];
						b += issac_base_member_result[index + 1];
						c += issac_base_member_result[index + 2];
						d += issac_base_member_result[index + 3];
						e += issac_base_member_result[index + 4];
						f += issac_base_member_result[index + 5];
						g += issac_base_member_result[index + 6];
						h += issac_base_member_result[index + 7];

						mix(a, b, c, d, e, f, g, h);

						issac_base_member_memory[index] = a;
						issac_base_member_memory[index + 1] = b;
						issac_base_member_memory[index + 2] = c;
						issac_base_member_memory[index + 3] = d;
						issac_base_member_memory[index + 4] = e;
						issac_base_member_memory[index + 5] = f;
						issac_base_member_memory[index + 6] = g;
						issac_base_member_memory[index + 7] = h;
					}

					/* do a second pass to make all of the seed affect all of issac_base_member_memory */
					for (std::size_t index = 0; index < state_size; index += 8)
					{
						a += issac_base_member_memory[index];
						b += issac_base_member_memory[index + 1];
						c += issac_base_member_memory[index + 2];
						d += issac_base_member_memory[index + 3];
						e += issac_base_member_memory[index + 4];
						f += issac_base_member_memory[index + 5];
						g += issac_base_member_memory[index + 6];
						h += issac_base_member_memory[index + 7];

						mix(a, b, c, d, e, f, g, h);

						issac_base_member_memory[index] = a;
						issac_base_member_memory[index + 1] = b;
						issac_base_member_memory[index + 2] = c;
						issac_base_member_memory[index + 3] = d;
						issac_base_member_memory[index + 4] = e;
						issac_base_member_memory[index + 5] = f;
						issac_base_member_memory[index + 6] = g;
						issac_base_member_memory[index + 7] = h;
					}

					/* fill in the first set of results */
					do_isaac();
				}

				inline void do_isaac()
				{
					if constexpr (std::same_as<result_type, std::uint32_t>)
						this->implementation_isaac();
					else if constexpr (std::same_as<result_type, std::uint64_t>)
						this->implementation_isaac64();
				}

				/* the golden ratio */
				inline result_type golden()
				{
					if constexpr (std::same_as<result_type, std::uint32_t>)
						return static_cast<std::uint32_t>(0x9e3779b9);
					else if constexpr (std::same_as<result_type, std::uint64_t>)
						return static_cast<std::uint64_t>(0x9e3779b97f4a7c13);
				}

				inline void mix(result_type& a, result_type& b, result_type& c, result_type& d, result_type& e, result_type& f, result_type& g, result_type& h)
				{
					if constexpr (std::same_as<result_type, std::uint32_t>)
					{
						a ^= b << 11;
						d += a;
						b += c;

						b ^= c >> 2;
						e += b;
						c += d;

						c ^= d << 8;
						f += c;
						d += e;

						d ^= e >> 16;
						g += d;
						e += f;

						e ^= f << 10;
						h += e;
						f += g;

						f ^= g >> 4;
						a += f;
						g += h;

						g ^= h << 8;
						b += g;
						h += a;

						h ^= a >> 9;
						c += h;
						a += b;
					}
					else if constexpr (std::same_as<result_type, std::uint64_t>)
					{
						a -= e;
						f ^= h >> 9;
						h += a;

						b -= f;
						g ^= a << 9;
						a += b;

						c -= g;
						h ^= b >> 23;
						b += c;

						d -= h;
						a ^= c << 15;
						c += d;

						e -= a;
						b ^= d >> 14;
						d += e;

						f -= b;
						c ^= e << 20;
						e += f;

						g -= c;
						d ^= f >> 17;
						f += g;

						h -= d;
						e ^= g << 14;
						g += h;
					}
				}

				std::array<result_type, state_size> issac_base_member_result{};
				std::array<result_type, state_size> issac_base_member_memory{};
				result_type issac_base_member_register_a = 0;
				result_type issac_base_member_register_b = 0;
				result_type issac_base_member_register_c = 0;
				std::size_t	issac_base_member_counter = 0;
			};

			template<std::size_t Alpha = 8>
			using isaac = RNG_ISAAC<Alpha, std::uint32_t>;

			template<std::size_t Alpha = 8>
			using isaac64 = RNG_ISAAC<Alpha, std::uint64_t>;
		}

		//https://zh.wikipedia.org/wiki/%E6%B7%B7%E6%B2%8C%E7%90%86%E8%AE%BA
		//https://en.wikipedia.org/wiki/Chaos_theory
		namespace ChaoticTheory
		{
			//模拟双段摆锤物理系统，根据二进制密钥生成伪随机数
			//Simulate a two-segment pendulum physical system to generate pseudo-random numbers based on a binary key
			//https://zh.wikipedia.org/wiki/%E5%8F%8C%E6%91%86
			//https://en.wikipedia.org/wiki/Double_pendulum
			//https://www.researchgate.net/publication/345243089_A_Pseudo-Random_Number_Generator_Using_Double_Pendulum
			//https://github.com/robinsandhu/DoublePendulumPRNG/blob/master/prng.cpp
			class SimulateDoublePendulum
			{

			private:

				using result_type = std::uint64_t;

				std::array<long double, 2> BackupTensions{};
				std::array<long double, 2> BackupVelocitys{};
				std::array<long double, 10> SystemData{};

				static constexpr long double gravity_coefficient = 9.8;
				static constexpr long double hight = 0.002;

				void run_system(bool is_initialize_mode, std::uint64_t time)
				{
					const long double& length1 = this->SystemData[0];
					const long double& length2 = this->SystemData[1];
					const long double& mass1 = this->SystemData[2];
					const long double& mass2 = this->SystemData[3];
					long double& tension1 = this->SystemData[4];
					long double& tension2 = this->SystemData[5];

					long double& velocity1 = this->SystemData[8];
					long double& velocity2 = this->SystemData[9];

					for (std::uint64_t counter = 0; counter < time; ++counter)
					{
						long double denominator = 2 * mass1 + mass2 - mass2 * ::cos(2 * tension1 - 2 * tension2);

						long double alpha1 = -1 * gravity_coefficient * (2 * mass1 + mass2) * ::sin(tension1)
							- mass2 * gravity_coefficient * ::sin(tension1 - 2 * tension2)
							- 2 * ::sin(tension1 - tension2) * mass2
							* (velocity2 * velocity2 * length2 + velocity1 * velocity1 * length1 * ::cos(tension1 - tension2));

						alpha1 /= length1 * denominator;

						long double alpha2 = 2 * ::sin(tension1 - tension2)
							* (velocity1 * velocity1 * length1 * (mass1 + mass2) + gravity_coefficient * (mass1 + mass2) * ::cos(tension1) + velocity2 * velocity2 * length2 * mass2 * ::cos(tension1 - tension2));

						alpha2 /= length2 * denominator;

						velocity1 += hight * alpha1;
						velocity2 += hight * alpha2;
						tension1 += hight * velocity1;
						tension2 += hight * velocity2;
					}

					if (is_initialize_mode)
					{
						this->BackupTensions[0] = tension1;
						this->BackupTensions[1] = tension2;

						this->BackupVelocitys[0] = velocity1;
						this->BackupVelocitys[1] = velocity2;
					}
				}

				void initialize(std::vector<std::int8_t>& binary_key_sequence)
				{
					if (binary_key_sequence.empty())
						my_cpp2020_assert(false, "RNG_ChaoticTheory::SimulateDoublePendulum: This binary key sequence must be not empty!", std::source_location::current());

					const std::size_t binary_key_sequence_size = binary_key_sequence.size();
					std::vector<std::vector<std::int8_t>> binary_key_sequence_2d(4, std::vector<std::int8_t>());
					for (std::size_t index = 0; index < binary_key_sequence_size / 4; index++)
					{
						binary_key_sequence_2d[0].push_back(binary_key_sequence[index]);
						binary_key_sequence_2d[1].push_back(binary_key_sequence[binary_key_sequence_size / 4 + index]);
						binary_key_sequence_2d[2].push_back(binary_key_sequence[binary_key_sequence_size / 2 + index]);
						binary_key_sequence_2d[3].push_back(binary_key_sequence[binary_key_sequence_size * 3 / 4 + index]);
					}

					std::vector<std::vector<std::int8_t>> binary_key_sequence_2d_param(7, std::vector<std::int8_t>());
					std::int32_t key_outer_round_count = 0;
					std::int32_t key_inner_round_count = 0;
					while (key_outer_round_count < 64)
					{
						while (key_inner_round_count < binary_key_sequence_size / 4)
						{
							binary_key_sequence_2d_param[0].push_back(binary_key_sequence_2d[0][key_inner_round_count] ^ binary_key_sequence_2d[1][key_inner_round_count]);
							binary_key_sequence_2d_param[1].push_back(binary_key_sequence_2d[0][key_inner_round_count] ^ binary_key_sequence_2d[2][key_inner_round_count]);
							binary_key_sequence_2d_param[2].push_back(binary_key_sequence_2d[0][key_inner_round_count] ^ binary_key_sequence_2d[3][key_inner_round_count]);
							binary_key_sequence_2d_param[3].push_back(binary_key_sequence_2d[1][key_inner_round_count] ^ binary_key_sequence_2d[2][key_inner_round_count]);
							binary_key_sequence_2d_param[4].push_back(binary_key_sequence_2d[1][key_inner_round_count] ^ binary_key_sequence_2d[3][key_inner_round_count]);
							binary_key_sequence_2d_param[5].push_back(binary_key_sequence_2d[2][key_inner_round_count] ^ binary_key_sequence_2d[3][key_inner_round_count]);
							binary_key_sequence_2d_param[6].push_back(binary_key_sequence_2d[0][key_inner_round_count]);

							++key_inner_round_count;
							++key_outer_round_count;
							if (key_outer_round_count >= 64)
							{
								break;
							}
						}
						key_inner_round_count = 0;
					}
					key_outer_round_count = 0;

					long double& radius = this->SystemData[6];
					long double& current_binary_key_sequence_size = this->SystemData[7];

					for (std::int32_t i = 0; i < 64; i++)
					{
						for (std::int32_t j = 0; j < 6; j++)
						{
							if (binary_key_sequence_2d_param[j][i] == 1)
								this->SystemData[j] += 1 * ::powl(2.0, 0 - i);
						}
						if (binary_key_sequence_2d_param[6][i] == 1)
							radius += 1 * ::powl(2.0, 4 - i);
					}

					current_binary_key_sequence_size = static_cast<long double>(binary_key_sequence_size);

					//This is initialize mode
					this->run_system(true, static_cast<std::uint64_t>(::round(radius * current_binary_key_sequence_size)));
				}

				//交错串接
				//Interleaved concatenate one-by-one bits
				std::int64_t concat(std::int32_t a, std::int32_t b)
				{
					std::string result_binary_string;
					for (int i = 0; i < 32; i++)
					{
						result_binary_string.push_back((b % 2) == 1 ? '1' : '0');
						b /= 2;
						result_binary_string.push_back((a % 2) == 1 ? '1' : '0');
						a /= 2;
					}
					std::bitset<64> concate_bitset(result_binary_string);
					std::int64_t c = static_cast<std::int64_t>(concate_bitset.to_ullong());
					return c;
				}

				std::int64_t generate()
				{
					//This is generate mode
					this->run_system(false, 1);

					long double temporary_floating_a = 0.0;
					long double temporary_floating_b = 0.0;

					std::int64_t left_number = 0, right_number = 0;

					temporary_floating_a = this->SystemData[0] * ::sin(this->SystemData[4]) + this->SystemData[1] * ::sin(this->SystemData[5]);
					temporary_floating_b = -(this->SystemData[0]) * ::sin(this->SystemData[4]) - this->SystemData[1] * ::sin(this->SystemData[5]);

					left_number = ::floor(::fmod(temporary_floating_a * 1000, 1.0) * 4294967296);
					right_number = ::floor(::fmod(temporary_floating_b * 1000, 1.0) * 4294967296);

					return this->concat(static_cast<std::int32_t>(left_number), static_cast<std::int32_t>(right_number));
				}

			public:

				static constexpr result_type min()
				{
					return 0LL;
				}

				static constexpr result_type max()
				{
					return 0xFFFFFFFFFFFFFFFFLL;
				};

				std::vector<result_type> operator()(std::size_t generated_count, std::uint64_t min_number, std::uint64_t max_number)
				{
					std::int64_t modulus = static_cast<std::int64_t>(max_number) - static_cast<std::int64_t>(min_number) + 1;

					std::vector<result_type> random_numbers(generated_count, 0);
					for (auto& random_number : random_numbers)
					{
						std::int64_t temporary_random_number = this->generate();

						if (modulus != 0)
							temporary_random_number %= modulus;

						if (temporary_random_number < 0)
							temporary_random_number += modulus;

						random_number = static_cast<result_type>(static_cast<std::int64_t>(min_number) + temporary_random_number);
					}

					return random_numbers;
				}

				result_type operator()(std::uint64_t min_number, std::uint64_t max_number)
				{
					std::int64_t modulus = static_cast<std::int64_t>(max_number) - static_cast<std::int64_t>(min_number) + 1;

					result_type random_number = 0;
					std::int64_t temporary_random_number = this->generate();

					if (modulus != 0)
						temporary_random_number %= modulus;

					if (temporary_random_number < 0)
						temporary_random_number += modulus;

					random_number = static_cast<result_type>(static_cast<std::int64_t>(min_number) + temporary_random_number);

					return random_number;
				}

				void reset()
				{
					this->SystemData[4] = this->BackupTensions[0];
					this->SystemData[5] = this->BackupTensions[1];
					this->SystemData[8] = this->BackupVelocitys[0];
					this->SystemData[9] = this->BackupVelocitys[1];
				}

				void seed_with_binary_string(std::string binary_key_sequence_string)
				{
					std::vector<int8_t> binary_key_sequence;
					std::string_view view_only_string(binary_key_sequence_string);
					const char binary_zero_string = '0';
					const char binary_one_string = '1';
					for (const char& data : view_only_string)
					{
						if (data != binary_zero_string && data != binary_one_string)
							continue;

						binary_key_sequence.push_back(data == binary_zero_string ? 0 : 1);
					}

					if (binary_key_sequence.empty())
						return;
					else
						this->initialize(binary_key_sequence);
				}

				template<typename SeedNumberType>
					requires std::signed_integral<SeedNumberType> || std::unsigned_integral<SeedNumberType> || std::same_as<SeedNumberType, std::string>
				void seed(SeedNumberType seed_value)
				{
					if constexpr (std::same_as<SeedNumberType, std::int32_t>)
						this->seed_with_binary_string(UtilTools::DataFormating::Decimal_Binary::FromLongIntegerToBinaryString(seed_value, seed_value < 0));
					else if constexpr (std::same_as<SeedNumberType, std::int64_t>)
						this->seed_with_binary_string(UtilTools::DataFormating::Decimal_Binary::FromLongLongIntegerToBinaryString(seed_value, seed_value < 0));
					else if constexpr (std::same_as<SeedNumberType, std::uint32_t>)
						this->seed_with_binary_string(UtilTools::DataFormating::Decimal_Binary::FromUnsignedLongIntegerToBinaryString(seed_value));
					else if constexpr (std::same_as<SeedNumberType, std::uint64_t>)
						this->seed_with_binary_string(UtilTools::DataFormating::Decimal_Binary::FromUnsignedLongLongIntegerToBinaryString(seed_value));
					else if constexpr (std::same_as<std::remove_cvref_t<SeedNumberType>, std::string>)
						this->seed_with_binary_string(seed_value);

				}

				explicit SimulateDoublePendulum(auto number)
				{
					using SeedNumberType = decltype(number);
					this->seed<SeedNumberType>(number);
				}

				~SimulateDoublePendulum()
				{
					this->BackupVelocitys.fill(0.0);
					this->BackupTensions.fill(0.0);
					this->SystemData.fill(0.0);
				}
			};
		}

		namespace FeedbackShiftRegister
		{
			//一种使用线性反馈移位寄存器算法的随机数发生器
			//A random number generator using linear feedback shift register algorithm
			class LinearFeedbackShiftRegister
			{

			public:

				using result_type = std::uint64_t;

			private:

				/*
					数组位置0是当前的随机数
					数组位置1是当前的随机数的种子
					Array position 0 is the current random number
					Array position 1 is the current random number seed
				*/
				std::array<result_type, 2> state{};

			public:

				result_type generate_bits(std::size_t bits_size)
				{
					result_type& NumberA = state[0];
					result_type& NumberB = state[1];

					result_type current_random_bit = 0;

					//多项式的初始值可以是：128,126,101,99
					//The initial values of the polynomial can be: 128,126,101,99
					result_type answer = 128;
					for (std::size_t round_counter = 0; round_counter < bits_size; ++round_counter)
					{
						//计算二进制的伪随机比特序列
						//Compute pseudo-random bit sequences in binary
						//这个多项式是 : x^128 + x^41 + x^39 + x + 1
						//This polynomial is : x^128 + x^41 + x^39 + x + 1
						//举一个例子，这个多项式的最高系数是128
						//As an example, the highest coefficient of this polynomial is 128.
						std::uint64_t&& irreducible_primitive_polynomial = NumberB ^ (NumberA >> 23) ^ (NumberA >> 25) ^ (NumberA >> 63);

						//只保留一个二进制的随机比特位
						//Only one binary random bit is retained
						current_random_bit = irreducible_primitive_polynomial & 0x01; //Feedback bit

						//左移答案的比特位
						//Shift the bits of the answer to the left
						answer <<= 1;

						//用当前随机位切换答案位
						//Toggle the answer bit with the current random bit
						answer ^= current_random_bit;

						//右移状态寄存器比特位
						//Shift the bits of the status register to the right
						NumberB >>= 1;
						NumberB |= (NumberA & 0x01) << 63;
						NumberA >>= 1;
						NumberA |= current_random_bit << 63;
					}
					return answer;
				}

				result_type operator() (void)
				{
					return this->generate_bits(63);
				}

				static constexpr result_type min()
				{
					return 0ULL;
				}

				static constexpr result_type max()
				{
					return 0xFFFFFFFFFFFFFFFFULL;
				};

				void seed(result_type seed)
				{
					*this = LinearFeedbackShiftRegister(seed);
				}

				void discard(std::size_t round_number)
				{
					for (std::size_t round_counter = 0; round_counter < round_number; ++round_counter)
						this->generate_bits(64);
				}

#ifndef BOOST_RANDOM_NO_STREAM_OPERATORS

				/**  Writes a @c rand48 to a @c std::ostream. */
				template<class CharT, class Traits>
				friend std::basic_ostream<CharT, Traits>&
					operator<<(std::basic_ostream<CharT, Traits>& os, const LinearFeedbackShiftRegister& lfsr)
				{
					os << lfsr.state[0]; os << ","; os << lfsr.state[1]; return os;
				}

				/** Reads a @c rand48 from a @c std::istream. */
				template<class CharT, class Traits>
				friend std::basic_istream<CharT, Traits>&
					operator>>(std::basic_istream<CharT, Traits>& is, LinearFeedbackShiftRegister& lfsr)
				{
					char command; is >> lfsr.state[0]; is >> command; is >> lfsr.state[1]; return is;
				}

#endif

				LinearFeedbackShiftRegister(result_type seed)
				{
					state[0] = 0;
					state[1] = seed;
					this->generate_bits(64);
					this->generate_bits(64);
				}

				LinearFeedbackShiftRegister() : LinearFeedbackShiftRegister(1)
				{

				}

				LinearFeedbackShiftRegister(LinearFeedbackShiftRegister const& lfsr)
				{
					state[0] = lfsr.state[0];
					state[1] = lfsr.state[1];
				}

				~LinearFeedbackShiftRegister()
				{
					state[0] = 0;
					state[1] = 0;
				}
			};

#define SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION 2

			//一种使用非线性反馈移位寄存器算法的随机数发生器
			//A random number generator using non-linear feedback shift register algorithm
			class NonlinearFeedbackShiftRegister
			{

			public:

				using result_type = std::uint64_t;

			private:

#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

				/*
				数组位置0是当前的随机数的种子
				数组位置1是当前的随机数
				Array position 0 is the current random number seed
				Array position 1 is the current random number
			*/
				std::array<result_type, 2> state{};

#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

				/*
					数组位置0是当前的随机数的种子
					数组位置1是当前的随机数
					Array position 0 is is the current random number seed
					Array position 1,2,3 the current random number
				*/
				std::array<result_type, 4> state{};

#endif

				//应用不可约的本源多项式的复杂性质生成非线性的随机比特流的数字
				//Apply complex properties of irreducible primitive polynomials to generate nonlinear random bit streams of numbers
				result_type random_bits(std::uint64_t& state_number, std::uint64_t irreducible_polynomial_count, const std::uint8_t bit)
				{
					//二进制多项式数据源：https://users.ece.cmu.edu/~koopman/lfsr/index.html
					//Binary polynomial data source : https://users.ece.cmu.edu/~koopman/lfsr/index.html
					//x is 2, for example: x ^ 3 = 2 * 2 * 2;

					/*
						//Plan A:

						std::uint64_t linear_feed_back_register = state_value & 0x01;
						state_value >>= 1; //state_value <<= 1;
						if(linear_feed_back_register == 0x01)
							state_value ^= polynomial

						//Plan B:

						state_value >>= 1; //state_value <<= 1;
						state_value ^= -(state_value & 0x01) & polynomial;
					*/

					switch (irreducible_polynomial_count)
					{
					case 0:
					{
						//Primitive polynomial degree is 24
						//x^23 + x^10 + x^9 + x^8 + x^6 + x^4 + x^3 + 1
						state_number >>= 1;
						state_number ^= (~(state_number & 0x01) + 1) & 0x80'0759ULL;

						break;
					}
					case 1:
					{
						//Primitive polynomial degree is 55
						//x^54 - x^10 - x^9 - x^8 - x^7 - x^6 - x^5 - x^4 - x^3 - x^2
						state_number >>= 1;
						state_number ^= (~(state_number & 0x01) + 1) & 0x40'0000'0000'07FCULL;

						break;
					}
					case 2:
					{
						//Primitive polynomial degree is 48
						//x^47 + x^11 + x^10 + x^8 + x^5 + x^4 + x^3 + 1
						state_number >>= 1;
						state_number ^= (~(state_number & 0x01) + 1) & 0x8000'0000'0D39ULL;

						break;
					}
					case 3:
					{
						//Primitive polynomial degree is 31
						//x^30 - x^9 - x^8 - x^7 - x^5 - x^4 - x^3 - x^2 - x - 1
						state_number >>= 1;
						state_number ^= (~(state_number & 0x01) + 1) & 0x4000'03BFULL;

						break;
					}
					case 4:
					{
						//Primitive polynomial degree is 64
						//x^63 + x^12 + x^9 + x^8 + x^5 + x^2
						state_number >>= 1;
						state_number ^= (~(state_number & 0x01) + 1) & 0x8000'0000'0000'1324ULL;

						break;
					}
					case 5:
					{
						//Primitive polynomial degree is 27
						//x^26 - x^10 - x^3 - x^2 - x - 1
						state_number >>= 1;
						state_number ^= (~(state_number & 0x01) + 1) & 0x400'040FULL;

						break;
					}
					case 6:
					{
						//Primitive polynomialdegree is 7
						//x^6 + 1
						state_number >>= 1;
						state_number ^= (~(state_number & 0x01) + 1) & 0x41ULL;

						break;
					}
					case 7:
					{
						//Primitive polynomial degree is 16
						//x^15 - x^10 - x^7 - x^5 - x^4 - x^3 - x^2 - x
						state_number >>= 1;
						state_number ^= (~(state_number & 0x01) + 1) & 0x84BEULL;

						break;
					}
					default:
					{
						//Primitive polynomial degree is 42
						//x^41 + x^11 + x^10 + x^8 + x^6 + x^5 + x^4 + x^3 + x^2 + x
						state_number >>= 1;
						state_number ^= (~(state_number & 0x01) + 1) & 0x200'0000'0D7EULL;

						break;
					}
					}

					return state_number ^ bit;
				}

			public:

				/*
					Reference URL:
					http://www.numberworld.org/constants.html
					https://www.exploringbinary.com/pi-and-e-in-binary/
					https://oeis.org/A001113
					https://oeis.org/A001622
					https://oeis.org/A000796

					斐波那契数列的值的组合
					Combination of the values of the Fibonacci sequence
					123581321345589144 == 0x1B70C8E97AD5F98

					PI π ≈ 3.1415926535897932384626433832795028841971693993751058209749445923078
					圆周率是一个数学常数，为一个圆的周长和其直径的比率
					Circumference is a mathematical constant that is the ratio of the circumference of a circle to its diameter
					Binary format: 11.0010010000111111011010101000100010000101101000110000100011010011
					二进制数字被剥离了浮点部分，并转换为十六进制，即 0x243F6A8885A308D3
					The binary numbers are stripped of the floating point portion and converted to hexadecimal, i.e: 0x243F6A8885A308D3

					e ≈ 2.7182818284590452353602874713526624977572470936999595749669676277240
					欧拉数是自然对数的基数，不要与欧拉-马斯切罗尼常数混淆
					The Euler number is the base of the natural logarithm, not to be confused with the Euler-Mascheroni constant
					Binary format: 10.1011011111100001010100010110001010001010111011010010101001101010
					二进制数字被剥离了浮点部分，并转换为十六进制，即 0xB7E151628AED2A6A
					The binary numbers are stripped of the floating point portion and converted to hexadecimal, i.e: 0xB7E151628AED2A6A

					phi ≈ 1.618033988749894848204586834365638618033988749894848204586834365638
					在数学中，如果两个量的比值与这两个量中较大的一个的比值相同，那么这两个量就处于黄金比例。
					用代数法表示，对于a和b的数量，a>b>0
					其中希腊字母phi表示黄金比例。
					常数phi满足二次方程 phi^2 = phi+1，是一个无理数，其值为phi =（ 1 + sqrt（5））/ 2
					In mathematics, two quantities are in the golden ratio if their ratio is the same as the ratio of their sum to the larger of the two quantities. Expressed algebraically, for quantities.
					Expressed algebraically, for quantities a and b with a>b>0
					where the Greek letter phi denotes the golden ratio.
					The constant phi satisfies the quadratic equation phi^2 = phi + 1, and is an irrational number with a value of phi = (1 + sqrt(5)) / 2
					Binary format: 01.1001111000110111011110011011100101111111010010100111110000010101
					二进制数字被剥离了浮点部分，并转换为十六进制，即 0x9E3779B97F4A7C15A
					The binary numbers are stripped of the floating point portion and converted to hexadecimal, i.e: 0x9E3779B97F4A7C15
				*/
				result_type generate_chaotic_number(std::size_t algorithm_execute_count)
				{
					/*
						Hamming weights (number of bits with 1)
						汉明权重(比特位为1的数量)
						std::popcount(Value);
					*/

					//32
					constexpr std::uint64_t FibonacciSequence = 0x1B70C8E97AD5F98ULL;
					//27
					constexpr std::uint64_t CircumferenceSequence = 0x243F6A8885A308D3ULL;
					//38
					constexpr std::uint64_t GoldenRatioSequence = 0x9E3779B97F4A7C15ULL;
					//32
					constexpr std::uint64_t EulerNumberSequence = 0xB7E151628AED2A6AULL;

					using TwilightDreamOfMagical::CustomSecurity::GaloisFiniteField256;
					using CommonToolkit::IntegerExchangeBytes::MemoryDataFormatExchange;
					MemoryDataFormatExchange memory_data_format_exchanger;
					GaloisFiniteField256<std::uint8_t>& GF256_Instance = GaloisFiniteField256<std::uint8_t>::get_instance();

					std::span<std::uint8_t> ByteSpan = memory_data_format_exchanger.Unpacker_8Byte(FibonacciSequence);
					const std::vector<std::uint8_t> FibonacciSequenceBytes(ByteSpan.begin(), ByteSpan.end());

					ByteSpan = memory_data_format_exchanger.Unpacker_8Byte(CircumferenceSequence);
					const std::vector<std::uint8_t> CircumferenceSequenceBytes(ByteSpan.begin(), ByteSpan.end());

					ByteSpan = memory_data_format_exchanger.Unpacker_8Byte(GoldenRatioSequence);
					const std::vector<std::uint8_t> GoldenRatioSequenceBytes(ByteSpan.begin(), ByteSpan.end());

					ByteSpan = memory_data_format_exchanger.Unpacker_8Byte(EulerNumberSequence);
					const std::vector<std::uint8_t> EulerNumberSequenceBytes(ByteSpan.begin(), ByteSpan.end());

					constexpr std::uint64_t Number2Power64Modulus = std::numeric_limits<result_type>::digits - static_cast<result_type>(1);

					/*
						Designed by: Twilight-Dream
						设计者：Twilight-Dream
					*/

#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

					/*
					Method of random number quality test:
					https://www.pcg-random.org/posts/how-to-test-with-practrand.html

					Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS ~/PractRand/[PRNG-TEST]
					# g++ -std=c++20 -O3 -Wall -o my-nlfsr_test ./my-nlfsr.cpp -static

					Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS ~/PractRand/[PRNG-TEST]
					# ./my-nlfsr_test-version1.exe | ./RNG_test.exe stdin64 -tlmin 1TB -tlmax 512TB -tf 2 -te 1 -multithreaded
					RNG_test using PractRand version 0.95
					RNG = RNG_stdin64, seed = unknown
					test set = expanded, folding = extra

					rng=RNG_stdin64, seed=unknown
					length= 1 terabyte (2^40 bytes), time= 37829 seconds
					  no anomalies in 2460 test result(s)

					rng=RNG_stdin64, seed=unknown
					length= 2 terabytes (2^41 bytes), time= 83022 seconds
					  no anomalies in 2530 test result(s)
				*/

					if (algorithm_execute_count < 8)
						algorithm_execute_count = 8;

					result_type answer = 0;
					for (std::size_t round_counter = 0; round_counter < algorithm_execute_count; ++round_counter)
					{
						std::uint8_t bit = (state[0] ^ state[1]) & 0x01;

						answer <<= 1;
						answer |= bit;

						if ((std::popcount(answer) & 0x01) != 0)
						{
							//Equivalent to function
							//GF256_Instance.addition_or_subtraction(reinterpret_cast<std::uint8_t*>(&answer)[index], FibonacciSequenceByteSpan);
							answer ^= FibonacciSequence;
						}
						else
						{
							auto multiplied_number_byte_span = memory_data_format_exchanger.Unpacker_8Byte(answer);

							for (std::uint8_t index = 0; index < sizeof(std::uint64_t); ++index)
								multiplied_number_byte_span[index] = GF256_Instance.multiplication(multiplied_number_byte_span[index], CircumferenceSequenceBytes[index]);

							//Equivalent to function
							//GF256_Instance.addition_or_subtraction(multiplied_number_byte_span, reinterpret_cast<std::uint8_t*>(answer)[index]);
							answer ^= memory_data_format_exchanger.Packer_8Byte(multiplied_number_byte_span);
						}

						if (algorithm_execute_count % 2 == 0)
						{
							auto& [value_0, value_1] = state;

							//可引起雪崩效应的二进制Mixed线性反馈移位寄存器处理
							//Binary Mixed linear feedback shift register processing that can cause avalanche effects
							//该函数被频繁调用时，非常消耗CPU的计算能力
							//When this function is called frequently, it consumes a lot of CPU computing power
							std::uint64_t&& random_number = static_cast<std::uint64_t>((answer >> static_cast<std::uint64_t>(53) ^ answer) ^ value_0);

							value_1 &= value_0;
							if (value_1 == 0)
								value_1 += value_0 * 2;

							answer ^= this->random_bits(value_1, random_number % 9ULL, static_cast<std::uint8_t>((value_1 & 0x01) ^ bit));

							value_0 &= value_1;
							if (value_0 == 0)
								value_0 += value_1 * 2;
						}
						else
						{
							//应用所有状态的混合数据
							//Apply mixed data for all states

							state[0] ^= result_type{ 1 } << (state[1] & Number2Power64Modulus);

							std::uint64_t a = state[0] & state[1];
							a ^= answer;

							std::uint64_t b = state[1] & answer;
							b ^= state[0];

							std::uint64_t c = answer & state[0];
							c ^= state[1];

							answer = ~((a | b) & c);

							state[1] ^= result_type{ 1 } << (state[0] & Number2Power64Modulus);

							a = 0;
							b = 0;
							c = 0;
						}

						if ((std::popcount(state[1]) & 0x01) == 0)
						{
							auto multiplied_number_byte_span = memory_data_format_exchanger.Unpacker_8Byte(state[1]);

							for (std::uint8_t index = 0; index < sizeof(std::uint64_t); ++index)
								multiplied_number_byte_span[index] = GF256_Instance.multiplication(multiplied_number_byte_span[index], GoldenRatioSequenceBytes[index]);

							//Equivalent to function
							//GF256_Instance.addition_or_subtraction(state[1], multiplied_number_byte_span);
							state[1] ^= memory_data_format_exchanger.Packer_8Byte(multiplied_number_byte_span);

							if (state[1] == 0)
							{
								//Equivalent to function
								//GF256_Instance.addition_or_subtraction(state[1], FibonacciSequenceByteSpan);
								state[1] ^= FibonacciSequence;
							}
						}
						else
						{
							//Equivalent to function
							//GF256_Instance.addition_or_subtraction(state[1], EulerNumberSequenceByteSpan);
							//GF256_Instance.addition_or_subtraction(state[1], reinterpret_cast<std::uint8_t*>(&answer)[index]);
							state[1] ^= EulerNumberSequence ^ answer;
						}
					}

					/*
						重要说明:
						这里的两个step常数17和42，可以互换位置；比特位左移（<<）和比特位右移（>>），也可以互换位置。
						注意，这个比特数互斥的或操作不能被删除，而且操作数必须是一个变量ANSWER！
						虽然两个step常数可以是 step ∈ [0 ，63]的任意数字，但是它们必须不相等而且需是1个奇数和1个偶数!

						Important Notes:
						The two step constants here, 17 and 42, can swap positions; bitwise left shifts (<<) and bitwise right shifts (>>), can also swap positions.
						Note that this bitwise exclusive-or operation cannot be removed, and the operand must be a variable ANSWER!
						Although the two step constants can be any number of step ∈ [0 , 63], they must be unequal and need to be 1 odd and 1 even!
					*/
					return answer ^ ((answer >> 42) | (answer << 17));

					//state[0] = std::rotl(state[0], 42) >> 1;
					//state[1] = std::rotr(state[1], 17) << 1;
					//answer ^= ( 0x01ULL << ( ( state[0] | state[1] ) & Number2Power64Modulus) );
					//return answer;

#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

					/*

					Method of random number quality test:
					https://www.pcg-random.org/posts/how-to-test-with-practrand.html

					Twilight-Dream@TWILIGHT-DREAM_HOME_COMPUTER MSYS ~/PractRand/[MY-PRNG-TEST]
					# ./my-nlfsr_test-version3.exe | ./RNG_test.exe stdin64 -tlmin 1TB -tlmax 512TB -tf 2 -te 1 -multithreaded

					*/

					if (algorithm_execute_count < 8)
						algorithm_execute_count = 8;

					result_type answer = 0;
					std::uint8_t bit = 0;
					for (std::size_t round_counter = 0; round_counter < algorithm_execute_count; ++round_counter)
					{
						bit = (state[0] ^ state[1] ^ state[2] ^ state[3]) & 0x01;

						answer <<= 1;
						answer |= bit;

						if ((std::popcount(answer) & 0x01) != 0)
						{
							//Equivalent to function
							//GF256_Instance.addition_or_subtraction(reinterpret_cast<std::uint8_t*>(&answer)[index], CircumferenceSequenceByteSpan);
							answer ^= CircumferenceSequence;
						}
						else
						{
							auto multiplied_number_byte_span = memory_data_format_exchanger.Unpacker_8Byte(answer);

							auto& SequenceBytes = (answer ^ state[1]) & 0x01 ? FibonacciSequenceBytes : GoldenRatioSequenceBytes;

							for (std::uint8_t index = 0; index < sizeof(std::uint64_t); ++index)
								multiplied_number_byte_span[index] = GF256_Instance.multiplication(multiplied_number_byte_span[index], SequenceBytes[index]);

							//Equivalent to function
							//GF256_Instance.addition_or_subtraction(multiplied_number_byte_span, FibonacciSequenceByteSpan);
							answer ^= memory_data_format_exchanger.Packer_8Byte(multiplied_number_byte_span);
						}

						if ((std::popcount(state[2]) & 0x01) == 0)
						{
							auto multiplied_number_byte_span = memory_data_format_exchanger.Unpacker_8Byte(state[2]);

							auto& SequenceBytes = (answer ^ state[3]) & 0x01 ? EulerNumberSequenceBytes : CircumferenceSequenceBytes;

							for (std::uint8_t index = 0; index < sizeof(std::uint64_t); ++index)
								multiplied_number_byte_span[index] = GF256_Instance.multiplication(multiplied_number_byte_span[index], SequenceBytes[index]);

							//GF256 addition_or_subtraction
							state[2] ^= memory_data_format_exchanger.Packer_8Byte(multiplied_number_byte_span);

							if ((state[2] & 0x01) == 0)
							{
								state[2] ^= FibonacciSequence;
							}
						}
						else
						{
							state[2] ^= GoldenRatioSequence ^ answer;

							if ((state[2] & 0x01) != 0)
							{
								state[2] ^= CircumferenceSequence;
							}
						}

						if (round_counter % 2 == 0)
						{
							auto& [value_0, value_1, value_2, value_3] = state;

							//可引起雪崩效应的二进制哈希处理
							//Binary hash processing that can cause an avalanche effect
							//该函数被频繁调用时，非常消耗CPU的计算能力
							//When this function is called frequently, it consumes a lot of CPU computing power
							std::uint64_t&& random_number = static_cast<std::uint64_t>((answer >> static_cast<std::uint64_t>(17) ^ value_1) ^ value_2);

							value_0 &= value_3;
							if (value_0 == 0)
								value_0 += (value_2 * 2);

							answer ^= this->random_bits(value_0, random_number % 9ULL, static_cast<std::uint8_t>((value_3 & 0x01) ^ bit));

							value_3 &= value_0;
							if (value_3 == 0)
								value_3 -= value_1 * 2;

							//Deprecated code:
							//std::uint64_t&& random_number = static_cast<std::uint64_t>( ( answer >> 53 ^ state[1] ) ^ state[2] );
							//answer ^= this->random_bits( random_number & static_cast<std::uint64_t>(8 - 1), (state[2] & 0x01) ^ bit);
						}
						else
						{
							auto& [value_0, value_1, value_2, value_3] = state;

							//Bit Data Mixing Function
							//比特数据混合函数
							value_1 ^= std::rotr(answer ^ value_0, static_cast<result_type>(value_3 - value_2) & Number2Power64Modulus);
							value_2 ^= value_1 << (static_cast<result_type>(value_0 + value_3) & Number2Power64Modulus);
							value_3 ^= value_2 >> (static_cast<result_type>(value_1 + value_0) & Number2Power64Modulus);
							value_0 ^= std::rotl(answer ^ value_3, static_cast<result_type>(value_1 - value_2) & Number2Power64Modulus);

							//Pseudo-Hadamard Transform
							//伪哈达马德变换

							result_type value_a = (value_0 + value_1) == 0ULL ? bit : (value_0 + value_1);
							result_type value_b = (value_0 + value_1 * 2ULL) == 0ULL ? bit : (value_0 + value_1 * 2ULL);
							result_type value_c = (value_3 - value_2) == 0ULL ? bit : (value_3 - value_2);
							result_type value_d = (value_2 * 2ULL - value_3) == 0ULL ? bit : (value_2 * 2ULL - value_3);

							//Forward form
							value_0 ^= value_a;
							value_1 ^= value_b;

							//Backward form
							value_2 ^= value_c;
							value_3 ^= value_d;

							value_a = value_b = value_c = value_d = 0ULL;

							//应用所有状态的混合数据
							//Apply mixed data for all states
							answer ^= state[0] ^ state[1] ^ state[2] ^ state[3];
						}

						//对于内部状态的比特位集进行(左旋转和右旋转)1位
						//For the internal state the set of bits is performed (left rotation and right rotation) 1 bit
						//state[0] = ( state[0] << 1 ) | ( state[1] >> 63 );
						//state[1] = ( state[1] >> 1 ) | ( state[2] << 63 );
						//state[2] = ( state[2] << 1 ) | ( state[3] >> 63 );
						//state[3] = ( state[3] >> 1 ) | ( state[0] << 63 );

					}
					bit = 0ULL;

					/*
						重要说明:
						这里的两个step常数17和42，可以互换位置；比特位左移（<<）和比特位右移（>>），也可以互换位置。
						注意，这个比特数互斥的或操作不能被删除，而且操作数必须是一个变量ANSWER！
						虽然两个step常数可以是 step ∈ [0 ，63]的任意数字，但是它们必须不相等而且需是1个奇数和1个偶数!

						Important Notes:
						The two step constants here, 17 and 42, can swap positions; bitwise left shifts (<<) and bitwise right shifts (>>), can also swap positions.
						Note that this bitwise exclusive-or operation cannot be removed, and the operand must be a variable ANSWER!
						Although the two step constants can be any number of step ∈ [0 , 63], they must be unequal and need to be 1 odd and 1 even!
					*/

					return answer ^ ((answer << 17) | (answer >> 42));

					//state[0] = std::rotr(state[0], 17) << 42;
					//state[1] = std::rotl(state[1], 42) >> 17;
					//state[2] = std::rotr(state[2], 17) << 42;
					//state[3] = std::rotl(state[3], 42) >> 17;
					//result_type random_number = (state[1] & state[3]) ^ (state[0] | state[2]);
					//answer ^= ( 0x01ULL << (random_number & Number2Power64Modulus) );
					//return answer

#endif
				}

				//产生不可预测的比特序列
				//Generate unpredictable bit sequences
				result_type unpredictable_bits(std::uint64_t base_number, std::size_t number_bits)
				{
					/*

						使用同一种数字种子，构造一个非线性反馈移位寄存器的对象，然后调用这个函数。
						根据基础数字(base_number)参数是否是奇数还是偶数，来决定即将生成的两种不同的比特序列的一种。

						Using the same numeric seed, construct an object of a nonlinear feedback shift register and call this function.
						Depending on whether the (base_number) argument is odd or even, it determines one of the two different bit sequences that will be generated.

						然而，有一种例外情况
						如果在(number_bit)参数大于等于64
						因为比特右移或者比特左移的次数大于了64，所以线性反馈移位寄存器(结果值 - answer)的特征被破坏了
						那么这个序列将会呈现一种就连线性反馈移位寄存器都不可知的混沌状态。
						尽管提供的所有参数和内部的状态是相同的，你也能还原出这些序列

						当序列处于混沌状态时，有可能处于线性和非线性状态之间，请自行记录所有提供的参数和数字种子。

						However, there is an exception to this rule
						If the (number_bit) parameter is greater than or equal to 64
						the linear feedback shift register (result value - answer) is broken because the number of bits shifted right or left is greater than 64
						Then the sequence will be chaotic in a way that even the linear feedback shift register is not known.
						Even though all the parameters provided and the internal state are the same, you can restore these sequences

						When the sequence is in a chaotic state, it may be in between linear and non-linear states, so please record all the provided parameters and numerical seeds yourself.
					*/

					result_type answer = base_number;
					result_type current_random_bit = 0U;

					std::array<std::uint8_t, 4> current_random_bits{ 0,0,0,0 };

					for (std::size_t round_counter = 0; round_counter < number_bits; ++round_counter)
					{
#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

						current_random_bit = state[1] & 0x01;
						//丢弃答案随机数的最高比特位，最低位由'0'补上
						//Discard the highest bit of the answer random number, the lowest bit is complemented by '0'
						answer <<= 1;
						//答案的随机数 BIT_OR 0ULL || 1ULL
						//The answer random number BIT_OR 0ULL || 1ULL
						answer |= current_random_bit;

						//计算二进制的伪随机比特序列
						//Compute pseudo-random bit sequences in binary
						//我这里把不同程度的线性反馈移位寄存器组合在一起
						//它们构成了一个非线性反馈移位寄存器，由这些状态混合然后生成的数字都是不能被预测的
						//I have combined different degrees of linear feedback shift registers here
						//They form a nonlinear feedback shift register, and the numbers generated by mixing these states are not predictable
						state[0] = this->random_bits(state[0], state[0] % 9ULL, current_random_bit);

						//只保留一个二进制的随机比特位
						//Only one binary random bit is retained
						current_random_bit = state[0] & 0x01;

						//根据当前状态(随机数种子或者随机数)，获取比特序列的最低比特位;
						//并且把那个比特位设置到下一个状态(随机数种子或者随机数)的最高比特位
						//Get the lowest bit of the bit sequence according to the current state (random number seed or random number);
						//and set that bit to the highest bit of the next state (random number seed or random number)

						state[1] >>= 1;
						state[1] |= (state[0] & 0x01ULL) << 63;

						state[0] >>= 1;
						state[0] |= current_random_bit << 63;

#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

						current_random_bit = ((state[0] ^ state[1] ^ state[2] ^ state[3]) >> 63) & 0x01;

						//丢弃答案随机数的最高比特位，最低位由'0'补上
						//Discard the highest bit of the answer random number, the lowest bit is complemented by '0'
						answer <<= 1;

						//答案的随机数 BIT_OR 0ULL || 1ULL
						//The answer random number BIT_OR 0ULL || 1ULL
						answer ^= current_random_bit;

						//计算二进制的伪随机比特序列
						//Compute pseudo-random bit sequences in binary
						//我这里把不同程度的线性反馈移位寄存器组合在一起
						//它们构成了一个非线性反馈移位寄存器，由这些状态混合然后生成的数字都是不能被预测的
						//I have combined different degrees of linear feedback shift registers here
						//They form a nonlinear feedback shift register, and the numbers generated by mixing these states are not predictable
						state[0] = this->random_bits(state[0], (state[3] ^ state[2]) % 9ULL, current_random_bit);

						//只保留一个二进制的随机比特位
						//Only one binary random bit is retained
						current_random_bits[0] ^= state[0] & 0x01;

						state[1] = this->random_bits(state[1], (state[2] ^ state[1]) % 9ULL, current_random_bit);

						//只保留一个二进制的随机比特位
						//Only one binary random bit is retained
						current_random_bits[1] ^= state[1] & 0x01;

						state[2] = this->random_bits(state[2], (state[1] ^ state[0]) % 9ULL, current_random_bit);

						//只保留一个二进制的随机比特位
						//Only one binary random bit is retained
						current_random_bits[2] ^= state[2] & 0x01;

						state[3] = this->random_bits(state[3], (state[0] ^ state[3]) % 9ULL, current_random_bit);

						//只保留一个二进制的随机比特位
						//Only one binary random bit is retained
						current_random_bits[3] ^= state[3] & 0x01;

						current_random_bit = (current_random_bits[0] | current_random_bits[1])
							^ (current_random_bits[1] & current_random_bits[2])
							^ (current_random_bits[2] | current_random_bits[3])
							^ (current_random_bits[3] & current_random_bits[0]);

						//丢弃答案随机数的最高比特位，最低位由'0'补上
						//Discard the highest bit of the answer random number, the lowest bit is complemented by '0'
						answer <<= 1;

						answer |= current_random_bit;

						std::iter_swap(current_random_bits.begin() + (state[0] % current_random_bits.size()), current_random_bits.end() - 1);
						std::iter_swap(current_random_bits.begin() + (state[1] % current_random_bits.size()), current_random_bits.end() - 1);
						std::iter_swap(current_random_bits.begin() + (state[2] % current_random_bits.size()), current_random_bits.end() - 1);
						std::iter_swap(current_random_bits.begin() + (state[3] % current_random_bits.size()), current_random_bits.end() - 1);

						//根据当前状态(随机数种子或者随机数)，获取比特序列的最低比特位;
						//并且把那个比特位设置到下一个状态(随机数种子或者随机数)的最高比特位
						//Get the lowest bit of the bit sequence according to the current state (random number seed or random number);
						//and set that bit to the highest bit of the next state (random number seed or random number)

						state[1] >>= 1;
						state[1] |= (state[0] & 0x01ULL) << 63;

						state[2] >>= 1;
						state[2] |= (state[1] & 0x01ULL) << 63;

						state[3] >>= 1;
						state[3] |= (state[2] & 0x01ULL) << 63;

						state[0] >>= 1;
						state[0] |= (state[3] & 0x01ULL) << 63;

						/*
						current_random_bit = (state[0] ^ state[1] ^ state[2]) & 0x01;

						answer ^= current_random_bit;
						*/

#endif
					}

					volatile void* CheckPointer = std::memset(current_random_bits.data(), 0, current_random_bits.size());
					CheckPointer = nullptr;

					return answer;
				}

				result_type operator() (void)
				{

#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

					//这里的参数影响随机数生成算法的时间复杂度
				//The parameters here affect the time complexity of the random number generate algorithm
				//Recommended number of executions(建议执行次数): algorithm_execute_count ∈ [8, 1024]
				//Example value is: 8,9,10,11,12,13,14,15,16 ...... 1024
					return this->generate_chaotic_number(8);

#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

					//这里的参数影响随机数生成算法的时间复杂度
					//The parameters here affect the time complexity of the random number generate algorithm
					//Recommended number of executions(建议执行次数): algorithm_execute_count ∈ [8, 1024]
					//Example value is: 8,9,10,11,12,13,14,15,16 ...... 1024
					return this->generate_chaotic_number(8);

#endif
				}

				static constexpr result_type min()
				{
					return 0;
				}

				static constexpr result_type max()
				{
					return 0xFFFFFFFFFFFFFFFF;
				};

				void seed(result_type seed)
				{
					*this = NonlinearFeedbackShiftRegister(seed);
				}

				void discard(std::size_t round_number)
				{
					if (round_number == 0)
						++round_number;

#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1
					this->generate_chaotic_number(round_number * 4);

#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2
					this->generate_chaotic_number(round_number * 2);

#endif
				}

#ifndef BOOST_RANDOM_NO_STREAM_OPERATORS

				/**  Writes a @c rand48 to a @c std::ostream. */
				template<class CharT, class Traits>
				friend std::basic_ostream<CharT, Traits>&
					operator<<(std::basic_ostream<CharT, Traits>& os, const NonlinearFeedbackShiftRegister& nlfsr)
				{
					os << nlfsr.state[0]; os << ","; os << nlfsr.state[1]; return os;
				}

				/** Reads a @c rand48 from a @c std::istream. */
				template<class CharT, class Traits>
				friend std::basic_istream<CharT, Traits>&
					operator>>(std::basic_istream<CharT, Traits>& is, NonlinearFeedbackShiftRegister& nlfsr)
				{
					char command; is >> nlfsr.state[0]; is >> command; is >> nlfsr.state[1]; return is;
				}

#endif

				explicit NonlinearFeedbackShiftRegister(result_type seed)
				{
					if (seed == 0)
						++seed;

#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

					//Initial state
					state[0] = seed;
					state[1] = (seed * 2) + 1;

					//Update state
					for (std::size_t initial_round = 32; initial_round > 0; initial_round--)
					{
						//应用所有状态的混合数据
						//Apply mixed data for all states

						state[0] ^= result_type{ 1 } << (state[1] & (std::numeric_limits<result_type>::digits - result_type{ 1 }));

						std::uint64_t a = state[0] & state[1];
						a ^= seed;

						std::uint64_t b = this->random_bits(state[0], a % 9ULL, state[0] ^ state[1]) & state[1];
						b ^= state[0];

						std::uint64_t c = this->random_bits(state[1], (a ^ b) % 9ULL, (state[0] | state[1]) & 0x01) & state[0];
						c ^= state[1];

						seed = a ^ b ^ c;

						state[1] ^= result_type{ 1 } << (seed & (std::numeric_limits<result_type>::digits - result_type{ 1 }));

						a = 0;
						b = 0;
						c = 0;
					}

#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

					//Initial state
					state[0] = seed;
					state[1] = (seed * 2) + 1;
					state[2] = (seed * 3) + 2;
					state[3] = (seed * 4) + 3;

					//Mix state (stage 1/2)
					state[0] += (state[1] ^ state[2]) ^ ~(state[3]);
					state[1] -= (state[2] & state[3]) | state[0];
					state[2] += (state[3] ^ state[0]) ^ ~(state[1]);
					state[3] -= (state[0] | state[1]) & state[2];

					//Mix state (stage 2/2)
					state[3] *= (seed << 48) & 0xffffffff;
					state[2] *= (seed << 32) & 0xffffffff;
					state[1] *= (seed << 16) & 0xffffffff;
					state[0] *= (seed) & 0xffffffff;

					//Update state
					for (std::size_t initial_round = 128; initial_round > 0; initial_round--)
					{
						state[2] ^= this->random_bits(state[0], static_cast<std::uint64_t>((state[0] >> 6 ^ state[1]) ^ state[3] ^ seed) % 9, state[1] & 0x01);
						state[3] ^= this->random_bits(state[1], static_cast<std::uint64_t>((state[1] << 57 ^ state[0]) ^ state[2] ^ seed) % 9, state[0] & 0x01);
						state[0] ^= this->random_bits(state[2], static_cast<std::uint64_t>((state[2] >> 24 ^ state[3]) ^ state[1] ^ seed) % 9, state[3] & 0x01);
						state[1] ^= this->random_bits(state[3], static_cast<std::uint64_t>((state[3] << 37 ^ state[2]) ^ state[0] ^ seed) % 9, state[2] & 0x01);

						//Current random bit
						std::uint64_t bit = (state[0] & 0x01) ^ (state[1] & 0x01) ^ (state[2] & 0x01) ^ (state[3] & 0x01);

						//Perform the nonlinear feedback function
						std::uint64_t temporary_state = (state[0] ^ state[1]) & state[2] | state[3];

						//Override seed number values
						seed = std::rotr(seed, 49) * std::rotl(state[0], 13);

						//Shift the values in the state array
						state[0] = state[1];
						state[1] = state[2];
						state[2] = state[3];
						state[3] = temporary_state;

						//In the (MSB/LSB) position, set a random bit
						seed |= (temporary_state & 0x01) ? (bit << 63) : bit & 0x01;
					}

#endif
				}

				NonlinearFeedbackShiftRegister() : NonlinearFeedbackShiftRegister(1)
				{

				}

				NonlinearFeedbackShiftRegister(NonlinearFeedbackShiftRegister const& nlfsr)
				{
#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

					state[0] = nlfsr.state[0];
					state[1] = nlfsr.state[1];

#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

					state[0] = nlfsr.state[0];
					state[1] = nlfsr.state[1];
					state[2] = nlfsr.state[2];
					state[3] = nlfsr.state[3];

#endif
				}

				NonlinearFeedbackShiftRegister(NonlinearFeedbackShiftRegister&& other_object)
					:
					state{ other_object.state }
				{

				}

				NonlinearFeedbackShiftRegister& operator=(NonlinearFeedbackShiftRegister&& other_object)
				{
					//Do not move from ourselves or all hell will break loose
					//不要离开我们自己，否则大祸临头。
					if (this == &other_object)
						return *this;

					//Call our own destructor to clean up the class object before moving it
					//在移动类对象之前，调用我们自己的析构器来清理它
					std::destroy_at(this);

					//Moving class objects from calling our own copy constructor or move constructor
					//从调用我们自己的复制构造函数或移动构造函数来移动类对象
					std::construct_at(this, other_object);

					return *this;
				}

				~NonlinearFeedbackShiftRegister()
				{
#if defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 1

					state[0] = 0;
					state[1] = 0;

#elif defined(SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION) && SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION == 2

					state[0] = 0;
					state[1] = 0;
					state[2] = 0;
					state[3] = 0;

#endif
				}
			};

#undef SELECT_TWILIGHT_DREAM_NLFSR_RANDOMIZER_VERSION
		}
	}
}

#endif //ALGORITHM_OALDRESPUZZLECRYPTIC_PRNGS_HPP
