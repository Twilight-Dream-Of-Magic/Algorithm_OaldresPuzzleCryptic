#include "XorConstantRotation.h"
#include <numeric>

namespace TwilightDreamOfMagical::CustomSecurity::CSPRNG
{
	/*
		import random

		SEED = 20260221
		rng = random.Random(SEED)

		# -------- Miller-Rabin (deterministic for 64-bit) --------
		def is_prime(n: int) -> bool:
			if n < 2:
				return False

			small_primes = [2,3,5,7,11,13,17,19,23,29,31,37]
			for p in small_primes:
				if n % p == 0:
					return n == p

			d = n - 1
			s = 0
			while (d & 1) == 0:
				d >>= 1
				s += 1

			bases = [2, 325, 9375, 28178, 450775, 9780504, 1795265022]
			for a in bases:
				if a % n == 0:
					return True
				x = pow(a, d, n)
				if x == 1 or x == n - 1:
					continue
				for _ in range(s - 1):
					x = (x * x) % n
					if x == n - 1:
						break
				else:
					return False
			return True


		def rotl32(x: int, r: int) -> int:
			r &= 31
			return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


		def reverse32(x: int) -> int:
			# bit-reversal of 32-bit
			x &= 0xFFFFFFFF
			x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555)
			x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333)
			x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F)
			x = ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF)
			x = ((x & 0x0000FFFF) << 16) | ((x >> 16) & 0x0000FFFF)
			return x & 0xFFFFFFFF


		def popcount32(x: int) -> int:
			return (x & 0xFFFFFFFF).bit_count()


		def hamming_distance32(a: int, b: int) -> int:
			return ((a ^ b) & 0xFFFFFFFF).bit_count()


		def max_run_length32(x: int) -> int:
			# longest run of equal bits in 32-bit word
			x &= 0xFFFFFFFF
			max_run = 1
			cur_run = 1
			prev = x & 1
			for i in range(1, 32):
				bit = (x >> i) & 1
				if bit == prev:
					cur_run += 1
				else:
					if cur_run > max_run:
						max_run = cur_run
					cur_run = 1
					prev = bit
			if cur_run > max_run:
				max_run = cur_run
			return max_run


		def nibble_uniformity32(x: int, nib_min=1, nib_max=3, max_dist=6) -> bool:
			# 8 nibbles; ideal=2 ones per nibble
			dist = 0
			for i in range(8):
				nib = (x >> (4*i)) & 0xF
				pc = nib.bit_count()
				if pc < nib_min or pc > nib_max:
					return False
				dist += abs(pc - 2)
			return dist <= max_dist


		def byte_uniformity32(x: int, byte_min=2, byte_max=6, max_dist=4) -> bool:
			# 4 bytes; ideal=4 ones per byte
			dist = 0
			for i in range(4):
				b = (x >> (8*i)) & 0xFF
				pc = b.bit_count()
				if pc < byte_min or pc > byte_max:
					return False
				dist += abs(pc - 4)
			return dist <= max_dist


		def sliding_window_checks32(x: int,
									max_dev8=3,   # 8-bit window ideal=4, allow [1..7] default
									max_dev16=5   # 16-bit window ideal=8, allow [3..13] default
									) -> bool:
			x &= 0xFFFFFFFF

			# 8-bit windows (25 windows)
			for i in range(0, 32 - 8 + 1):
				w = (x >> i) & 0xFF
				pc = w.bit_count()
				if abs(pc - 4) > max_dev8:
					return False

			# 16-bit windows (17 windows)
			for i in range(0, 32 - 16 + 1):
				w = (x >> i) & 0xFFFF
				pc = w.bit_count()
				if abs(pc - 8) > max_dev16:
					return False

			return True


		def anti_self_similarity32(x: int,
								   min_rot_hd=10,
								   min_rev_hd=12) -> bool:
			# forbid too-close rotations (structure repeats)
			for r in (1, 3, 5, 7, 11, 13, 17):
				if hamming_distance32(x, rotl32(x, r)) < min_rot_hd:
					return False

			# forbid too-close bit-reversal similarity
			if hamming_distance32(x, reverse32(x)) < min_rev_hd:
				return False

			return True


		def small_mod_bias_filter(n: int) -> bool:
			# cheap extra: avoid tiny congruence patterns that show up suspiciously often
			# (this does NOT prove RK security; it's just a cheap "no obvious stink" filter)
			bad_mods = [3, 5, 7, 11, 13, 17, 19]
			for m in bad_mods:
				r = n % m
				# avoid r=1 or r=m-1 simultaneously across many mods? too strict if stacked,
				# but we can still avoid a few obvious residues.
				if r == 0:
					return False
			return True


		def strict_uniform_half32(x: int) -> bool:
			# you can tighten these numbers further, but default already brutal
			if popcount32(x) != 16:
				return False
			if max_run_length32(x) > 7:
				return False
			if not nibble_uniformity32(x, nib_min=1, nib_max=3, max_dist=6):
				return False
			if not byte_uniformity32(x, byte_min=2, byte_max=6, max_dist=4):
				return False
			if not sliding_window_checks32(x, max_dev8=3, max_dev16=5):
				return False
			if not anti_self_similarity32(x, min_rot_hd=10, min_rev_hd=12):
				return False
			return True


		def random_candidate_exact_16_16() -> int:
			# generate exactly: low32 has 16 ones, high32 has 16 ones (no bit fixing!)
			low_positions  = rng.sample(range(0, 32), 16)
			high_positions = rng.sample(range(32, 64), 16)
			n = 0
			for pos in low_positions:
				n |= 1 << pos
			for pos in high_positions:
				n |= 1 << pos
			return n


		def find_extreme_constant64(max_tries: int = 200_000_000):
			for tries in range(1, max_tries + 1):
				n = random_candidate_exact_16_16()

				# prime implies odd (>2), so even candidates are rejected (not modified)
				if (n & 1) == 0:
					continue

				# small mod filter first (cheap), then primality (expensive)
				if not small_mod_bias_filter(n):
					continue
				if not is_prime(n):
					continue

				low32  = n & 0xFFFFFFFF
				high32 = (n >> 32) & 0xFFFFFFFF

				if not strict_uniform_half32(low32):
					continue
				if not strict_uniform_half32(high32):
					continue

				return n, tries

			raise RuntimeError("Not found within max_tries")


		if __name__ == "__main__":
			value, tries = find_extreme_constant64()
			low32 = value & 0xFFFFFFFF
			high32 = (value >> 32) & 0xFFFFFFFF

			print("Seed =", SEED)
			print("Found in tries =", tries)
			print("Prime (hex) =", hex(value))
			print("HW total =", value.bit_count())
			print("HW low32/high32 =", low32.bit_count(), "/", high32.bit_count())
			print("max_run low/high =", max_run_length32(low32), "/", max_run_length32(high32))
	*/

	/*
		Seed = 20260221
		Found in tries = 493
		Prime (hex) = 0xadb136136669d153
		HW total = 32
		HW low32/high32 = 16 / 16
		max_run low/high = 3 / 4
	*/
	static constexpr std::uint64_t XCR_CSPRNG_DEFAULT_INITIALIZE_CONSTANT = 0xADB136136669D153;

	XorConstantRotation::XorConstantRotation()
		: w(XCR_CSPRNG_DEFAULT_INITIALIZE_CONSTANT), x(0), y(0), z(0)
	{
		StateInitialize();
	}

	XorConstantRotation::XorConstantRotation(std::uint64_t seed)
		: w(seed), x(0), y(0), z(0)
	{
		StateInitialize();
	}

	void XorConstantRotation::Seed(std::uint64_t seed)
	{
		// key slot
		w = seed;
		StateInitialize();
	}

	XorConstantRotation::result_type XorConstantRotation::operator()(std::size_t number_once)
	{
		return StateIteration(number_once);
	}

	XorConstantRotation::GeneratedSubKey128 XorConstantRotation::GenerateSubKey128(std::uint64_t number_once)
	{
		const std::uint64_t subkey0 = StateIteration(static_cast<std::size_t>(number_once));
		// Domain separation for the 2nd call: XOR + ROTL only (no add/mul).
		// Any fixed pattern is fine; keep it simple and deterministic.
		const std::uint64_t ds = std::rotl(number_once ^ subkey0, 17) ^ 0xA5A5A5A5A5A5A5A5ULL;
		const std::uint64_t subkey1 = StateIteration(static_cast<std::size_t>(ds));

		return { subkey0, subkey1 };
	}
	
	// ROUND_CONSTANT.size() == 300
	// gcd(counter_step, ROUND_CONSTANT_SIZE) = 1, popcountcounter_step) = 32
	static constexpr std::uint64_t counter_step = 0xC8522A96E53AF749;

	// ---------------------------------------------------------------------
	// White-box init / warm-up phase (analysis-friendly):
	//
	// Roles:
	// - key/seed is provided ONLY via ctor/Seed() and enters ONLY through `w`.
	// - This function performs a short warm-up to diffuse the key into (w,x,y,z)
	//   and to avoid trivial early structure (e.g., zero lanes).
	//
	// Phase separation (intentional):
	// - During warm-up we do advance `counter` because StateIteration() uses it.
	// - After warm-up we RESET `counter` to a fixed public start value so that
	//   the production phase has a clean, reproducible counter schedule.
	//   (Warm-up and production are intentionally separated.)
	//
	// Warm-up input:
	// - During warm-up, the per-call input `number_once` is fed from evolving
	//   internal `random` so the warm-up is self-contained.
	// - In production, `number_once` comes from the caller (nonce-like / one-time).
	// ---------------------------------------------------------------------
	void XorConstantRotation::StateInitialize()
	{
		// Ensure w != 0 without branch:
		const std::uint64_t nonzero_flag = (w | (0ULL - w)) >> 63;
		const std::uint64_t is_zero = nonzero_flag ^ 1ULL;
		w = w + is_zero;

		// Reset lanes for explicit key path
		x = 0;
		y = 0;
		z = 0;

		std::uint64_t random = w;

		// ------------------------------------------------------------
		// - Split 64-bit seed into two 32-bit halves.
		// - Each half runs "GGM-like" expansion for 2 rounds, 32 bits/round.
		// - Stitch back to 64-bit: (left32 << 32) | right32.
		//
		// Total StateIteration calls: 2 halves * 2 rounds * 32 bits = 128
		// (lighter than previous 256)
		// ------------------------------------------------------------

		auto ggm32_rounds = [&](std::uint32_t seed32) -> std::uint32_t
		{
			constexpr std::uint64_t WARMUP = 0x5741524D5550ULL; // "WARMUP"
			std::uint64_t out = static_cast<std::uint64_t>(seed32);

			// 2 rounds, each round produces 32 bits by LSB extraction
			for (int round = 0; round < 2; ++round)
			{
				std::uint32_t next32 = 0;
				for (int bit_index = 0; bit_index < 32; ++bit_index)
				{
					const std::uint64_t in = (WARMUP<<48) ^ (std::uint64_t(std::uint32_t(out)) << 16) ^ (round<<8) ^ bit_index;
					out = StateIteration(static_cast<std::size_t>(in));
					const std::uint32_t bit = static_cast<std::uint32_t>(out >> 63);
					next32 = (next32 << 1) | bit;
				}
				out = static_cast<std::uint64_t>(next32);
			}

			return static_cast<std::uint32_t>(out);
		};

		// split
		const std::uint32_t left_seed  = static_cast<std::uint32_t>((random >> 32) ^ ROUND_CONSTANTS[ROUND_CONSTANT_SIZE - 1]);
		const std::uint32_t right_seed = static_cast<std::uint32_t>((random & 0xFFFFFFFFU) ^ ROUND_CONSTANTS[ROUND_CONSTANT_SIZE - 2]);

		// expand halves (warmup consumes StateIteration internally)
		const std::uint32_t left_out  = ggm32_rounds(left_seed);
		x = 0, y = 0, z = 0, counter = counter_step;
		const std::uint32_t right_out = ggm32_rounds(right_seed);

		// stitch
		random = (static_cast<std::uint64_t>(left_out) << 32) | static_cast<std::uint64_t>(right_out);

		// Minimal fold-back (key whitening)
		w ^= random;

		// Reset to fixed public start value for production phase
		counter = counter_step;
	}

	// ---------------------------------------------------------------------
	// White-box iteration (production phase):
	//
	// External input:
	// - `number_once` is the ONLY per-call external input (nonce-like / one-time).
	// - The key/seed MUST NOT be injected here.
	// - Key influence exists only via the initialized internal state (w,x,y,z).
	//
	// Public counter:
	// - `counter` is a public/trackable schedule variable used to select
	//   ROUND_CONSTANT indices and to avoid tiny-period patterns.
	// - Its starting value is defined by StateInitialize() after warm-up.
	//
	// ARX modeling constraint:
	// - Exactly 4 modular add/sub on 64-bit lanes (carry sources):
	//	 w += yy;  x -= zz;  y += ww;  z -= xx;
	// - Everything else is XOR/ROTL + table lookup (indices depend on public values).
	// ---------------------------------------------------------------------

	XorConstantRotation::result_type XorConstantRotation::StateIteration(std::size_t number_once)
	{
		const std::uint64_t n = static_cast<std::uint64_t>(number_once);
		
		static_assert((counter_step % ROUND_CONSTANT_SIZE) != 0, "counter step must be nonzero mod ROUND_CONSTANT size");
		static_assert(std::gcd(counter_step, ROUND_CONSTANT_SIZE) == 1, "counter step must be coprime with ROUND_CONSTANT size");

		// Table-driven constants (public indices).
		// Using different index "views" of n to avoid trivial repetition.
		const std::uint64_t RC0 = ROUND_CONSTANTS[( n ) % ROUND_CONSTANT_SIZE];
		const std::uint64_t RC1 = ROUND_CONSTANTS[( counter ) % ROUND_CONSTANT_SIZE];
		const std::uint64_t RC2 = ROUND_CONSTANTS[( n + counter ) % ROUND_CONSTANT_SIZE];
		const std::uint64_t RC3 = ROUND_CONSTANTS[( (n ^ std::rotl(n ^ counter,3)) ) % ROUND_CONSTANT_SIZE];

		// Pre-mix (XOR-only) -> feeds the 4 carries below.
		std::uint64_t ww = x ^ RC0;
		std::uint64_t xx = y ^ RC1;
		std::uint64_t yy = z ^ RC2;
		std::uint64_t zz = w ^ RC3;

		// --- Exactly 4 modular add/sub operations (the only carry sources) ---
		w += yy;  // (1) add
		x -= zz;  // (2) sub
		y += ww;  // (3) add
		z -= xx;  // (4) sub

		// Rotation/XOR-only diffusion layer (no more add/sub).
		ww = (w ^ std::rotl(x,  7)) ^ (std::rotl(y, 19) ^ z);
		xx = (x ^ std::rotl(y, 11)) ^ (std::rotl(z, 23) ^ w);
		yy = (y ^ std::rotl(z, 17)) ^ (std::rotl(w, 29) ^ x);
		zz = (z ^ std::rotl(w, 13)) ^ (std::rotl(x, 31) ^ y);

		// Rebind lanes with number_once injection (XOR/ROTL-only).
		// This keeps the per-call input explicit and modelable.
		z = ww ^ n;
		w = xx ^ std::rotl(n,  9);
		x = yy ^ std::rotl(n, 27);
		y = zz ^ std::rotl(n, 43);

		// Output: combine all lanes (XOR/ROTL-only).
		std::uint64_t out = w ^ x ^ y ^ z;
		out ^= std::rotl(out, 47) ^ std::rotl(out, 53);
		
		// Public counter (unifrom add; kept for period expansion & external modeling)
		counter += counter_step;
		
		return out;
	}
}