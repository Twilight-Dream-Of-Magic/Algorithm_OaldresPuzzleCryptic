#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <bit>	// std::rotl

namespace TwilightDreamOfMagical::CustomSecurity::CSPRNG
{
	// -------------------------------------------------------------------------
	// XCR (Xor-Constant-Rotation)
	// -------------------------------------------------------------------------
	// Experimental / analysis-friendly stateful generator core.
	//
	// Design goals:
	// - Experimental: this is NOT claimed to be a proven CSPRNG.
	// - Hybrid-analysis friendly: remove native add/sub from the core permutation and keep nonlinear operations explicit.
	// - Engineering friendly: integer-only, branch-free core, no heavy runtime math.
	// - Constant discipline: runtime mixing constants come only from
	//   `XCR_ROUND_CONSTANTS[]` (plus the fixed default seed constant used by ctor).
	//
	// State model:
	// - Internal state is 256-bit: (w, x, y, z), each lane is uint64_t.
	// - A public schedule variable `counter` is also maintained.
	//
	// External inputs:
	// - `seed` enters only through ctor / Seed(), then is absorbed by StateInitialize().
	// - `number_once` is the per-call external input of the permutation path.
	//
	// Important API semantics (current implementation):
	// - `GenerateSubKey128(number_once)`
	//      Stateful production call. It mutates (w,x,y,z), returns {x ^ y, z ^ w},
	//      and DOES advance `counter += COUNTER_STEP` via StateIteration().
	// - `operator()(number_once)`
	//      Same public behavior as GenerateSubKey128() in the current implementation:
	//      one permutation, one output extraction, one explicit counter advance.
	// - `StateIteration(number_once)`
	//      Private helper path used internally, and also the common stepping backend
	//      for the current public production calls.
	//
	// Therefore:
	// - Public production calls evolve through BOTH:
	//      (1) internal state mutation,
	//      (2) explicit public-counter progression.
	// - The warm-up path also uses the same stepping rule, but after warm-up
	//   `counter` is reset to the fixed public start value.
	//
	// Permutation-level Hybrid8-Shadow constraint:
	// - Native modular add/sub operations are intentionally removed from the core step.
	// - Public period-4 H-round uses alternating Hybrid8 byte substitutions.
	// - The remaining S-rounds use bounded shadow carry/borrow word operations.
	// - Everything else in the round is XOR / ROTL / public table lookup.
	//
	// Seed separation rule:
	// - The seed is consumed only during StateInitialize().
	// - Production calls do not directly re-inject the seed.
	// -------------------------------------------------------------------------

	class XorConstantRotation
	{
	
	public:
		/*
			Seed = 20260221
			Found in tries = 493
			Prime (hex) = 0xadb136136669d153
			HW total = 32
			HW low32/high32 = 16 / 16
			max_run low/high = 3 / 4
		*/
		static constexpr std::uint64_t XCR_CSPRNG_DEFAULT_INITIALIZE_CONSTANT = 0xADB136136669D153;
		// ROUND_CONSTANT.size() == 300
		// gcd(COUNTER_STEP, ROUND_CONSTANT_SIZE) = 1, popcount(COUNTER_STEP) = 32
		static constexpr std::uint64_t COUNTER_STEP = 0xC8522A96E53AF749;

		struct GeneratedSubKey128
		{
			uint64_t a, b;

			GeneratedSubKey128() = default;
			GeneratedSubKey128(std::uint64_t left, std::uint64_t right)
				: a(left), b(right) {}

			std::uint64_t& operator[](std::size_t index)
			{
				return (index == 0) ? a : b;
			}

			const std::uint64_t& operator[](std::size_t index) const
			{
				return (index == 0) ? a : b;
			}

			GeneratedSubKey128 operator^(const GeneratedSubKey128& other) const
			{
				return { a ^ other.a, b ^ other.b };
			}

			GeneratedSubKey128& operator^=(const GeneratedSubKey128& other)
			{
				a ^= other.a;
				b ^= other.b;
				return *this;
			}

			bool operator==(const GeneratedSubKey128& other) const = default;

			std::uint64_t GetBit(std::size_t bit_index) const
			{
				if (bit_index < 64)
				{
					return static_cast<std::uint64_t>((a >> bit_index) & 1ULL);
				}
				return static_cast<std::uint64_t>((b >> (bit_index - 64)) & 1ULL);
			}
		};

	private:
		void			   PermutationARX( const std::uint64_t number_once );
		GeneratedSubKey128 StateIteration( std::uint64_t number_once );
		void			   StateInitialize();

	public:

		XorConstantRotation()
		: w(XCR_CSPRNG_DEFAULT_INITIALIZE_CONSTANT), x(0), y(0), z(0), counter(COUNTER_STEP)
		{
			StateInitialize();
		}

		XorConstantRotation(std::uint64_t seed)
			: w(seed), x(0), y(0), z(0), counter(COUNTER_STEP)
		{
			StateInitialize();
		}

		void Seed(std::uint64_t seed)
		{
			
			// Reset lanes for explicit key path
			x = 0;
			y = 0;
			z = 0;
			// key slot
			w = seed;
			// Reset to fixed public start value for production phase
			counter = COUNTER_STEP;
			StateInitialize();
		}

		GeneratedSubKey128 operator()( std::uint64_t number_once );
		GeneratedSubKey128 GenerateSubKey128( std::uint64_t number_once );

		// 256-bit state
		std::uint64_t w = 0;
		std::uint64_t x = 0;
		std::uint64_t y = 0;
		std::uint64_t z = 0;

		// public counter
		std::uint64_t counter = 0;

		// NOTE:
		// - First 4 constants are "manually mixed anchors"
		// - The rest are generated by your high-order continuous function discretization.
		// - This code never introduces any other constants.
		// GenerateAndDisplay_XorConstantRotation_RoundConstant.py generate this
		static constexpr std::array<std::uint64_t, 300> XCR_ROUND_CONSTANTS =
		{
			// [0..3] manual anchors: Fibonacci-bit concat, pi/phi-style, etc.
			0x01B70C8E97AD5F98ULL, 0x243F6A8885A308D3ULL, 0x9E3779B97F4A7C15ULL, 0xB7E151628AED2A6AULL,

			// [4..299] generated stream (truncated here in this snippet).
			//x ∈ [1, 150]
			// V2 polynomial Weyl with all high-precision constants
			// f(x) = frac( frac( frac( frac( frac( frac( frac( frac(0 + e·x)
			//              + π·x²) + φ·x³) + √2·x⁴) + √3·x⁵) + γ·x⁶) + δ·x⁷) + ρ·x⁸ )
			//
			// where frac(t) = t − ⌊t⌋,  x ∈ ℕ (e.g., [1, 150])
			0xc7fed6d75df59ae9ULL, 0x20b23e1962e49836ULL, 0xe91e4940fe913bb5ULL, 0x97de4bff5dfc30baULL,
			0xea49951290ea2540ULL, 0xb3383d9dab30ae94ULL, 0x5621f313742832d0ULL, 0x995116b66478bba4ULL,
			0x010441338f759db8ULL, 0x536398d10308029dULL, 0x2894ed6378c5fb69ULL, 0xad85fa88c56d7b09ULL,
			0xb86c2492a5407da3ULL, 0x1fd735150a7fc7f8ULL, 0x02c0801e8d2ad5c4ULL, 0x345b92dda0378c7bULL,
			0xc858e896facbd0ecULL, 0x0d7e068ff47062a5ULL, 0x4dc82f0a88eaba49ULL, 0xdead923252d8b51eULL,
			0x02236f27027eec7bULL, 0x8bfd5a2cd7d0dfe1ULL, 0xb2d91055e1680ec7ULL, 0x447f69d7bbb2de96ULL,
			0xf24675a6731d39b1ULL, 0x74e6924e74f3f522ULL, 0x273d55b4f2f77942ULL, 0x4ec79e443fe532aeULL,
			0x29884015291e47cdULL, 0xf535ca62c5946508ULL, 0x194d875b9340054eULL, 0x7dff309c505e61d3ULL,
			0x33f089308e7d76f6ULL, 0x66d8aca59455423dULL, 0x5443a4614fb8b79aULL, 0x8860a0331815a37fULL,
			0x94490b5c348488e3ULL, 0x2aca9822e5516650ULL, 0x733050d3dd13b717ULL, 0xf333ffb03119bcfbULL,
			0x8994c64cc9ce655bULL, 0xd1c78bb7fbf62cbcULL, 0x9ce1b356d7fd08eaULL, 0x529095a30fb494bcULL,
			0x894413382f7750fbULL, 0x8e244af81eea7291ULL, 0x8f678cfc9b2d509dULL, 0x9b3c82a2ec6bb9a6ULL,
			0x7cec3e3bddc61b85ULL, 0x2ea6563b009e077eULL, 0x12a5327207526f19ULL, 0xc4cb57d77bef7619ULL,
			0xe7c7edf59a172e38ULL, 0x356b6d4bbb9e2252ULL, 0x606a34fcaf87622bULL, 0x8614cb5cdabd7b2eULL,
			0x6601482c230d6a6bULL, 0x7c5670b353a5474aULL, 0xd6632cfec4c04a7eULL, 0x128f463deafa672bULL,
			0x5c7ad57132be6d99ULL, 0x66d84709d4c2c125ULL, 0xdb7713d125404702ULL, 0xda87b7f935c26251ULL,
			0x0283a7e70abef3fcULL, 0x00a2056879c6d403ULL, 0xb581bda3f9472b77ULL, 0x546b6f54c7e6d880ULL,
			0xb95d731a19e3a5e5ULL, 0xfc7b4fb032470fd8ULL, 0x280588bcd42aa267ULL, 0x788b5830d262515aULL,
			0x6b85d6c080678f74ULL, 0xea8ed898d6ecb981ULL, 0x67d60e41bb8008c2ULL, 0x6773f7f99e997275ULL,
			0xd620fc33328703f4ULL, 0xdb5d284693d0c501ULL, 0xccd1485ffee19ddcULL, 0xba423bf2cfcbf84dULL,
			0x10038a54845bc465ULL, 0x72f9bcb93f278861ULL, 0xcf5610e8d98eea9fULL, 0xa8c611ff76712442ULL,
			0x8f5107f7835a2743ULL, 0xe582e5371d41f3a6ULL, 0x2a6a41817ad64a1fULL, 0xe1284d87d0461dd8ULL,
			0x5cc60669d6133c09ULL, 0x5a36fec5cd11724eULL, 0x645ed91ceffb0fe1ULL, 0x29480de78f4a1f66ULL,
			0x0ad6643fcc72994bULL, 0x5ef91e9d64c388efULL, 0x0934f85bf11c3a26ULL, 0x924252b668e465e4ULL,
			0xf2c4e7935494be68ULL, 0xf5303d0fdb1cef2aULL, 0x6284e1f5efede4a2ULL, 0x5d51abe2cc906eb3ULL,
			0x07d0a125283799baULL, 0xf1857876b708c71dULL, 0xca7edcca5a57f378ULL, 0x1606487fb80ba32bULL,
			0xc880e89d05a25051ULL, 0x9f11b85e1b76708dULL, 0x20e033151e08c2c9ULL, 0x080446531ed145a5ULL,
			0x89d051c6ab320d8aULL, 0x09cf59743a58763fULL, 0xafd20c8650719fc6ULL, 0x8c9827c610851d36ULL,
			0xe6823b3ee36b03ecULL, 0x9b88e73002cfaf2fULL, 0x3259d6e322745dc5ULL, 0xd4380355d061e914ULL,
			0x7ec7b283d4e5cf83ULL, 0x3bc07bbe3d5de00eULL, 0x03b76ca9748b0829ULL, 0x996d690fc620872bULL,
			0x84fd544e588c6dc5ULL, 0x62f56a662af4c27aULL, 0xecbf3492b48777beULL, 0xeb022ee345562417ULL,
			0xd64f319faf3877bfULL, 0x10f6afc24765674eULL, 0x462fb541297e4e47ULL, 0x5830e8fb6298ddc5ULL,
			0x72177a6ca01d4160ULL, 0xc9ec7db4c500d928ULL, 0xf07669f3bd4bdbf1ULL, 0x10bca5be25e4c519ULL,
			0xea9957226b48cabeULL, 0x32bdec964180aa7cULL, 0x73060ec748740ddfULL, 0x2f3740a4b808f6f3ULL,
			0x5b5f24c00870223cULL, 0x37834e526eb85528ULL, 0x342b94c1d614e690ULL, 0x0c8f744af722738aULL,
			0x25b1fe35877a6681ULL, 0x96ca440448a0dd4aULL, 0x83c0f58d0d952779ULL, 0x978ace71c34fcb6bULL,
			0xe85605ca4aceb32cULL, 0x2e4ed59fb92b0bcfULL, 0xba1f41b35b1eea12ULL, 0xb44b1352b69058cdULL,
			0xba3ceca3e27d32f9ULL, 0x5a7441c6528131e9ULL, 0xedeb8055c017c2d7ULL, 0x147efc6cb7dac993ULL,
			0x3690bf3b60cfbf1fULL, 0xfeda458d3b67d4deULL, 0xd9bcb6b2fb353ff0ULL, 0x906fe8490f900801ULL,
			0x4b71ed710366b9f0ULL, 0xc969ef0a4e9c1107ULL, 0x90572c255c96834fULL, 0x5f3eb2edbe4ac0b3ULL,
			0x634f3a1b98d9933dULL, 0x6f0f361ee182539eULL, 0xebea4c97f7c64d8aULL, 0x1cd3159ca76b6d85ULL,
			0xcda3a82a5d66a4a5ULL, 0x85339303bb54b830ULL, 0x349f8b78600a084cULL, 0x1c3f55fe2af85f36ULL,
			0x02b1d6d131c2ca0dULL, 0x865732e0782dcff9ULL, 0x275a0b26c8078906ULL, 0xcc2fd8020350fd07ULL,
			0xe475319860cbee73ULL, 0xc9c6e475780bba5cULL, 0xf7ddb43214f431b2ULL, 0xa60fd32705228cb7ULL,
			0xc2d119cc67a24dbaULL, 0xa590929d94e6373eULL, 0x64102108958672a8ULL, 0xff38b0e1252eedacULL,
			0x551540277911dfc8ULL, 0x7e82148109cce0efULL, 0xd029b9df9eaedb44ULL, 0x42840c2794b543a8ULL,
			0xd6f053a12f2ad5beULL, 0x666157855db0fd29ULL, 0x2c8364d46812dd0fULL, 0x3a2bf7697fe971c9ULL,
			0xb217b28f07654afdULL, 0x0964d6a25e0c0674ULL, 0x6b78d335c4b26354ULL, 0xb3a0d240490834bbULL,
			0x7cbdf7e25cf5e2e8ULL, 0x66096b450186248dULL, 0x3f957dc892bab775ULL, 0x204be476cb0e6204ULL,
			0x2e93270c352877a0ULL, 0xcf3c54fcf7e25340ULL, 0xed466b3a6aa99784ULL, 0x687ee87389d3ce44ULL,
			0xfce153fc6f3f0a12ULL, 0x538554fa09d45b61ULL, 0x0eb22bdbcbd2e657ULL, 0x99eeff7b2dd6af18ULL,
			0x9820d3f84a539881ULL, 0xf1ca001532e7c261ULL, 0x7fed339969bd2c3cULL, 0xbcf5b28dc2c218c9ULL,
			0xcfb439da5c0aa91aULL, 0x07c8c143feb901ceULL, 0xc9dfebacc4962fe9ULL, 0xa578a3e9fbb8b2c5ULL,
			0x0b70dd4a8d1ff46cULL, 0xd50d0ca3e67516a6ULL, 0x1b0d9ab302075e3aULL, 0xcc65e117fd8e4c5bULL,
			0xf02b8f19187dfd52ULL, 0x14180b374125aa9fULL, 0x953c0c06d6a98a04ULL, 0x4057b8bb6c200930ULL,
			0x0dc2f04b27661c6fULL, 0xa1df060a256b02f7ULL, 0x010cf06e893f27a5ULL, 0xd1a080d145080455ULL,
			0x229ff6b6e7640df1ULL, 0xd24b66100d9479f5ULL, 0xceb0b1f750e7ceb0ULL, 0xe2e6dbece5714183ULL,
			0xf67045ae46918afdULL, 0x7a872dea312a9fd8ULL, 0x94297bdd53ab20f8ULL, 0x4dae2ef810bbe342ULL,
			0xc1054ff43ad21fc4ULL, 0x26ebf6433551b4b2ULL, 0x11e3a876d6a1351fULL, 0x295d26f5462909acULL,
			0x402c466e92a438eaULL, 0x1cc8e5c9da286632ULL, 0xe43fd84c98af9eaaULL, 0x70c12a97ae6d8a4eULL,
			0x7b68298191a178b8ULL, 0xfe27c41b52815151ULL, 0xb7cb37f9a5786ee3ULL, 0x8b7ec6586bfaf9e4ULL,
			0x16ea247a1b8eff1eULL, 0x7a08eee72ce4dc99ULL, 0xf8563c4f27161a69ULL, 0x67776334a28721a1ULL,
			0x143997e86de1f9b6ULL, 0x1c00f33ca5d83e43ULL, 0x0ecbf99e2f8da830ULL, 0xbcb6a5b4641902aeULL,
			0x5add72af71ec10daULL, 0x3cb671fb55910acbULL, 0xb556cbe0c235c663ULL, 0xbf7582d30c7b7b9bULL,
			0xe6419e49d98970dbULL, 0x94c02a4e57e78417ULL, 0x8a90e51246212fc6ULL, 0x08e74b091203eba1ULL,
			0xbc8e2b48be85990dULL, 0x60984e2a9011efeaULL, 0x7f13660985641607ULL, 0xa70628a5966dbe6aULL,
			0x11668a250121376fULL, 0x98e2fb9ba6830b7dULL, 0xfbcb881bd8e04362ULL, 0x818b615d377d79e8ULL,
			0xd363eaf614a598aaULL, 0xb98ef05d4f0fa7a0ULL, 0xa1e43deb0e801ee6ULL, 0x09e89d231ce3c300ULL,
			0x32b97dcc525c6c1cULL, 0xe783951df5595388ULL, 0xd19bb2b7ec16093aULL, 0x66c4177f7c1d79bfULL,
			0x7ac7eef4150fb82cULL, 0xad5e164ab4c0d474ULL, 0x85b10215b554d1fbULL, 0xe075a3032fa906ddULL,
			0xa80eb743bc799201ULL, 0x0f01944c84b85959ULL, 0x757529145922cd25ULL, 0x19e0eadc8379ba3cULL,
			0x1e72937f49943a41ULL, 0x136c3db980bb2ddeULL, 0x2900ffffebe647ddULL, 0xc292f1aed24bb838ULL,
			0x6dc406a8d9a846a8ULL, 0x9d4d0d3846ae9fcbULL, 0xb1b5b679ec677686ULL, 0x2da508234e18b51bULL,
			0xb67732180c341acaULL, 0x4ffb9be0b5ee605aULL, 0x15d5f9e38f2044cbULL, 0x352c030d11302197ULL
		};

		static constexpr std::size_t ROUND_CONSTANT_SIZE = XCR_ROUND_CONSTANTS.size();
	};
}  // namespace TwilightDreamOfMagical::CustomSecurity::CSPRNG
