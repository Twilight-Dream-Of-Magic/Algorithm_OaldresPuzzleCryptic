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
	
	from math import gcd


	# ============================================================
	#  Deterministic Miller-Rabin primality test for n < 2^64
	# ============================================================

	SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
	MR_BASES_64 = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)


	def is_prime64(n: int) -> bool:
		"""
		Deterministic Miller-Rabin primality test for unsigned 64-bit integers.
		Valid for 0 <= n < 2^64.
		"""
		if n < 2:
			return False

		if n >= (1 << 64):
			raise ValueError("is_prime64 only supports n < 2^64")

		for p in SMALL_PRIMES:
			if n % p == 0:
				return n == p

		d = n - 1
		s = 0
		while (d & 1) == 0:
			d >>= 1
			s += 1

		for a in MR_BASES_64:
			a %= n
			if a == 0:
				continue

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


	# ============================================================
	#  Bit utility functions
	# ============================================================

	def popcount32(x: int) -> int:
		return (x & 0xFFFFFFFF).bit_count()


	def rotl32(x: int, r: int) -> int:
		x &= 0xFFFFFFFF
		return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


	def bit_reverse32(x: int) -> int:
		x &= 0xFFFFFFFF
		y = 0

		for _ in range(32):
			y = (y << 1) | (x & 1)
			x >>= 1

		return y


	def hamming32(a: int, b: int) -> int:
		return ((a ^ b) & 0xFFFFFFFF).bit_count()


	def max_run_length(x: int, bits: int) -> int:
		"""
		Return the maximum consecutive 0/1 run length in a fixed-width bit string.
		"""
		s = f"{x & ((1 << bits) - 1):0{bits}b}"

		best = 1
		cur = 1

		for a, b in zip(s, s[1:]):
			if a == b:
				cur += 1
				best = max(best, cur)
			else:
				cur = 1

		return best


	def has_run_of_ones(x: int, run_len: int) -> bool:
		"""
		Fast test: whether x contains run_len consecutive one-bits.
		"""
		y = x

		for i in range(1, run_len):
			y &= x >> i
			if y == 0:
				return False

		return y != 0


	def max_run_leq(x: int, bits: int, limit: int) -> bool:
		"""
		Fast predicate: maximum consecutive 0/1 run length <= limit.
		"""
		mask = (1 << bits) - 1
		x &= mask

		# Forbid limit+1 consecutive ones.
		if has_run_of_ones(x, limit + 1):
			return False

		# Forbid limit+1 consecutive zeros.
		inv = (~x) & mask
		if has_run_of_ones(inv, limit + 1):
			return False

		return True


	def nibble_popcounts32(x: int) -> list[int]:
		"""
		Big-endian nibble popcounts of a 32-bit word.
		"""
		return [
			((x >> (4 * (7 - i))) & 0xF).bit_count()
			for i in range(8)
		]


	def byte_popcounts(x: int, byte_count: int) -> list[int]:
		"""
		Big-endian byte popcounts.
		"""
		return [
			((x >> (8 * (byte_count - 1 - i))) & 0xFF).bit_count()
			for i in range(byte_count)
		]


	def nibble_uniformity32(
		x: int,
		nib_min: int = 1,
		nib_max: int = 3,
		max_dist: int = 6,
	) -> bool:
		pcs = nibble_popcounts32(x)

		return (
			all(nib_min <= v <= nib_max for v in pcs)
			and max(pcs) - min(pcs) <= max_dist
		)


	def byte_uniformity32(
		x: int,
		byte_min: int = 2,
		byte_max: int = 6,
		max_dist: int = 4,
	) -> bool:
		pcs = byte_popcounts(x, 4)

		return (
			all(byte_min <= v <= byte_max for v in pcs)
			and max(pcs) - min(pcs) <= max_dist
		)


	def sliding_window_popcount_range(x: int, bits: int, win: int) -> tuple[int, int]:
		"""
		Linear sliding-window popcount range over a fixed-width bit string.
		"""
		x &= (1 << bits) - 1
		wmask = (1 << win) - 1

		values = [
			((x >> shift) & wmask).bit_count()
			for shift in range(bits - win, -1, -1)
		]

		return min(values), max(values)


	def sliding_window_checks32(
		x: int,
		max_dev8: int = 3,
		max_dev16: int = 5,
	) -> bool:
		"""
		Check whether all 8-bit and 16-bit linear windows stay near half density.
		"""
		mn8, mx8 = sliding_window_popcount_range(x, 32, 8)
		mn16, mx16 = sliding_window_popcount_range(x, 32, 16)

		return (
			4 - max_dev8 <= mn8 <= mx8 <= 4 + max_dev8
			and 8 - max_dev16 <= mn16 <= mx16 <= 8 + max_dev16
		)


	def anti_self_similarity32(
		x: int,
		min_rot_hd: int = 10,
		min_rev_hd: int = 12,
	) -> bool:
		"""
		Reject words that are too similar to their rotations or bit-reversal.
		"""
		min_rot_hd_actual = min(
			hamming32(x, rotl32(x, r))
			for r in range(1, 32)
		)

		rev_hd_actual = hamming32(x, bit_reverse32(x))

		return (
			min_rot_hd_actual >= min_rot_hd
			and rev_hd_actual >= min_rev_hd
		)


	# ============================================================
	#  Asymmetric 64-bit bit-shape predicate
	# ============================================================

	def asymmetric_uniform_halves64(x: int) -> bool:
		"""
		Global-balanced but locally asymmetric 64-bit shape predicate.

		The whole word has Hamming weight 32, but the two 32-bit halves
		are deliberately shifted from 16:16 to 13:19.
		"""
		high = x >> 32
		low = x & 0xFFFFFFFF

		return (
			# Global balance, local imbalance.
			x.bit_count() == 32
			and popcount32(high) == 13
			and popcount32(low) == 19

			# Bounded local runs.
			and max_run_length(high, 32) <= 4
			and max_run_length(low, 32) <= 4

			# High half: sparse but uniform.
			and nibble_uniformity32(high, nib_min=1, nib_max=3, max_dist=6)
			and byte_uniformity32(high, byte_min=2, byte_max=6, max_dist=4)
			and sliding_window_checks32(high, max_dev8=3, max_dev16=5)

			# Low half: denser, but still controlled.
			and sliding_window_checks32(low, max_dev8=3, max_dev16=5)
			and anti_self_similarity32(low, min_rot_hd=10, min_rev_hd=12)

			# Cross-half parity asymmetry.
			and (high & 1) == 0
			and (low & 1) == 1
		)


	# ============================================================
	#  Number-theoretic derivation
	# ============================================================

	def prime_factors(n: int) -> list[int]:
		"""
		Return distinct prime factors of n.
		"""
		factors = []

		if n % 2 == 0:
			factors.append(2)
			while n % 2 == 0:
				n //= 2

		d = 3
		while d * d <= n:
			if n % d == 0:
				factors.append(d)
				while n % d == 0:
					n //= d
			d += 2

		if n > 1:
			factors.append(n)

		return factors


	def previous_prime(n: int) -> int:
		"""
		Return the largest prime strictly smaller than n.
		"""
		x = n - 1

		if x == 2:
			return 2

		if x % 2 == 0:
			x -= 1

		while x >= 2:
			if is_prime64(x):
				return x
			x -= 2

		raise RuntimeError("no previous prime found")


	def derive_sigma_rho(table_size: int) -> tuple[int, int, int]:
		"""
		Derive sigma and rho from the table size.

		For table_size = 300:
			pmax  = largest_prime_factor(300) = 5
			sigma = previous_prime(300 / (2 * 5)) = previous_prime(30) = 29
			rho   = sigma^2 mod 300 = 29^2 mod 300 = 241
		"""
		pmax = max(prime_factors(table_size))
		sigma = previous_prime(table_size // (2 * pmax))
		rho = (sigma * sigma) % table_size

		return pmax, sigma, rho


	def derive_small_factor(table_size: int, sigma: int) -> tuple[int, int]:
		"""
		Derive the small prime factor P.

		Rule:
			P is the largest 21-bit prime satisfying:
				P mod table_size = sigma
				popcount(P) = 11
		"""
		bitlen = 21
		target_weight = (bitlen + 1) // 2

		lo = 1 << (bitlen - 1)
		hi = (1 << bitlen) - 1

		p = hi - ((hi - sigma) % table_size)

		steps = 0

		while p >= lo:
			steps += 1

			# Cheap filters first, primality last.
			if p.bit_count() == target_weight and is_prime64(p):
				return p, steps

			p -= table_size

		raise RuntimeError("small factor P not found")


	# ============================================================
	#  Large factor and final kappa filters
	# ============================================================

	def cheap_large_factor_filter(q: int) -> bool:
		"""
		Cheap pre-primality filters for Q.
		"""
		return (
			q.bit_length() == 43
			and q.bit_count() == 18
			and max_run_leq(q, 43, 5)
			and byte_popcounts(q, 6) == [2, 3, 3, 4, 3, 3]
		)


	def kappa_filter(kappa: int, table_size: int, rho: int) -> bool:
		"""
		Final acceptance filter for the 64-bit KappaCounter step.
		"""
		high = kappa >> 32
		low = kappa & 0xFFFFFFFF

		return (
			kappa.bit_length() == 64
			and kappa.bit_count() == 32
			and high.bit_count() == 13
			and low.bit_count() == 19
			and (high & 1) == 0
			and (low & 1) == 1
			and max_run_length(kappa, 64) == 4
			and kappa % table_size == rho
			and gcd(kappa, table_size) == 1
			and byte_popcounts(kappa, 8) == [3, 3, 3, 4, 5, 4, 7, 3]
			and asymmetric_uniform_halves64(kappa)
		)


	def derive_large_factor(
		table_size: int,
		sigma: int,
		rho: int,
		p: int,
	) -> tuple[int, int, int]:
		"""
		Derive the large prime factor Q.

		The search anchor is derived from P, rho, and the target 64-bit scale:

			shift  = 64 - 2 * bit_length(P)
			anchor = floor(P * 2^shift * rho / table_size)

		Starting from the first q >= anchor with q mod table_size = sigma,
		scan q += table_size until the first Q passing the cheap filters,
		primality test, and final KappaCounter acceptance filter.
		"""
		shift = 64 - 2 * p.bit_length()
		anchor = (p * (1 << shift) * rho) // table_size

		q = anchor + ((sigma - anchor) % table_size)

		steps = 0

		while True:
			steps += 1

			# Cheap filters first.
			if cheap_large_factor_filter(q):
				# Expensive primality test last.
				if is_prime64(q):
					kappa = p * q

					if kappa_filter(kappa, table_size, rho):
						return q, anchor, steps

			q += table_size


	def derive_kappa_counter() -> dict[str, int]:
		"""
		Canonical public derivation procedure for KappaCounter.
		"""
		table_size = 300

		pmax, sigma, rho = derive_sigma_rho(table_size)

		p, p_steps = derive_small_factor(table_size, sigma)
		q, anchor, q_steps = derive_large_factor(table_size, sigma, rho, p)

		kappa = p * q

		return {
			"table_size": table_size,
			"pmax": pmax,
			"sigma": sigma,
			"rho": rho,
			"P": p,
			"Q": q,
			"anchor": anchor,
			"kappa": kappa,
			"P_search_steps": p_steps,
			"Q_search_steps": q_steps,
		}


	# ============================================================
	#  Diagnostic printer
	# ============================================================

	def print_diagnostics(result: dict[str, int]) -> None:
		table_size = result["table_size"]
		pmax = result["pmax"]
		sigma = result["sigma"]
		rho = result["rho"]
		p = result["P"]
		q = result["Q"]
		anchor = result["anchor"]
		kappa = result["kappa"]

		high = kappa >> 32
		low = kappa & 0xFFFFFFFF

		print(f"table_size = {table_size}")
		print(f"pmax	   = {pmax}")
		print(f"sigma	  = {sigma}")
		print(f"rho		= {rho}")
		print()

		print(f"P		  = 0x{p:X}")
		print(f"Q		  = 0x{q:X}")
		print(f"anchor	 = 0x{anchor:X}")
		print(f"kappa	  = 0x{kappa:X}")
		print()

		print(f"P is prime = {is_prime64(p)}")
		print(f"Q is prime = {is_prime64(q)}")
		print(f"P * Q == kappa = {p * q == kappa}")
		print()

		print(f"P % 300	   = {p % table_size}")
		print(f"Q % 300	   = {q % table_size}")
		print(f"sigma^2 % 300 = {(sigma * sigma) % table_size}")
		print(f"kappa % 300   = {kappa % table_size}")
		print(f"gcd(kappa, 300) = {gcd(kappa, table_size)}")
		print()

		print(f"kappa bit_length = {kappa.bit_length()}")
		print(f"kappa popcount   = {kappa.bit_count()}")
		print(f"kappa max_run	= {max_run_length(kappa, 64)}")
		print(f"kappa byte popcounts = {byte_popcounts(kappa, 8)}")
		print()

		print(f"high32 = 0x{high:08X}")
		print(f"high32 popcount = {high.bit_count()}")
		print(f"high32 max_run  = {max_run_length(high, 32)}")
		print(f"high32 even	 = {(high & 1) == 0}")
		print(f"high32 nibble popcounts = {nibble_popcounts32(high)}")
		print(f"high32 byte popcounts   = {byte_popcounts(high, 4)}")
		print()

		print(f"low32 = 0x{low:08X}")
		print(f"low32 popcount = {low.bit_count()}")
		print(f"low32 max_run  = {max_run_length(low, 32)}")
		print(f"low32 odd	  = {(low & 1) == 1}")
		print(f"low32 nibble popcounts = {nibble_popcounts32(low)}")
		print(f"low32 byte popcounts   = {byte_popcounts(low, 4)}")
		print()

		min_rot_hd_low = min(hamming32(low, rotl32(low, r)) for r in range(1, 32))
		rev_hd_low = hamming32(low, bit_reverse32(low))

		print(f"low32 min rotation HD = {min_rot_hd_low}")
		print(f"low32 reversal HD	 = {rev_hd_low}")
		print()

		print(f"asymmetric_uniform_halves64(kappa) = {asymmetric_uniform_halves64(kappa)}")
		print()

		print(f"P-search steps = {result['P_search_steps']}")
		print(f"Q-search steps = {result['Q_search_steps']}")


	if __name__ == "__main__":
		result = derive_kappa_counter()

		assert result["sigma"] == 29
		assert result["rho"] == 241
		assert result["P"] == 0x1F9289
		assert result["Q"] == 0x658459A0EC1
		assert result["kappa"] == 0xC8522A96E53AF749

		print_diagnostics(result)
	
	*/

	// ---------------------------------------------------------------------
	// Hybrid8 byte substitutions and Shadow carry/borrow operations
	// ---------------------------------------------------------------------
	// H-round uses a 256-bit BigS layer built from alternating byte S-boxes:
	//   SA = BTM -> Borrow -> BTM -> Carry
	//   SB = Carry -> BTM -> Borrow -> BTM
	// S-round uses bounded stage-2 shadow carry/borrow word operations.
	// Both families are table-free in this implementation.
	// ---------------------------------------------------------------------

	namespace
	{
		[[nodiscard]] constexpr std::uint8_t byte8( std::uint64_t value, std::size_t index ) noexcept
		{
			return static_cast<std::uint8_t>( ( value >> ( index * 8U ) ) & 0xFFULL );
		}

		[[nodiscard]] constexpr std::uint64_t with_byte8( std::uint64_t value, std::size_t index, std::uint8_t byte ) noexcept
		{
			const std::uint64_t shift = static_cast<std::uint64_t>( index * 8U );
			const std::uint64_t mask  = 0xFFULL << shift;
			return ( value & ~mask ) | ( static_cast<std::uint64_t>( byte ) << shift );
		}

		[[nodiscard]] constexpr std::uint8_t lifted_carry_add8( std::uint8_t a, std::uint8_t k ) noexcept
		{
			const std::uint8_t p  = static_cast<std::uint8_t>( a ^ k );
			const std::uint8_t g  = static_cast<std::uint8_t>( a & k );
			const std::uint8_t n1 = static_cast<std::uint8_t>( p >> 1 );
			const std::uint8_t n2 = static_cast<std::uint8_t>( ( p >> 2 ) ^ ( p >> 3 ) );

			const std::uint8_t w1 = g;
			const std::uint8_t w2 = static_cast<std::uint8_t>( w1 & n1 );
			const std::uint8_t w4 = static_cast<std::uint8_t>( w2 & n2 );

			return static_cast<std::uint8_t>( p ^ ( w1 << 1 ) ^ ( w2 << 2 ) ^ ( w4 << 4 ) );
		}

		[[nodiscard]] constexpr std::uint8_t lifted_borrow_sub8( std::uint8_t a, std::uint8_t k ) noexcept
		{
			const std::uint8_t p  = static_cast<std::uint8_t>( a ^ k );
			const std::uint8_t h  = static_cast<std::uint8_t>( ( ~a ) & k );
			const std::uint8_t r  = static_cast<std::uint8_t>( ~p );
			const std::uint8_t n1 = static_cast<std::uint8_t>( r >> 1 );
			const std::uint8_t n2 = static_cast<std::uint8_t>( ( r >> 2 ) ^ ( r >> 3 ) );

			const std::uint8_t w1 = h;
			const std::uint8_t w2 = static_cast<std::uint8_t>( w1 & n1 );
			const std::uint8_t w4 = static_cast<std::uint8_t>( w2 & n2 );

			return static_cast<std::uint8_t>( p ^ ( w1 << 1 ) ^ ( w2 << 2 ) ^ ( w4 << 4 ) );
		}

		[[nodiscard]] constexpr std::uint8_t ltam_l8( std::uint8_t a, std::uint8_t k ) noexcept
		{
			return static_cast<std::uint8_t>( a ^ ( ( a << 1 ) & k ) ^ ( ( a << 2 ) & k ) ^ ( ( a << 4 ) & k ) );
		}

		[[nodiscard]] constexpr std::uint8_t ltam_r8( std::uint8_t a, std::uint8_t k ) noexcept
		{
			return static_cast<std::uint8_t>( a ^ ( ( a >> 1 ) & k ) ^ ( ( a >> 2 ) & k ) ^ ( ( a >> 4 ) & k ) );
		}

		[[nodiscard]] constexpr std::uint8_t btm8( std::uint8_t a, std::uint8_t k ) noexcept
		{
			return ltam_r8( ltam_l8( a, k ), k );
		}

		[[nodiscard]] constexpr std::uint8_t hybrid8_sa( std::uint8_t x ) noexcept
		{
			x = btm8( x, 0x2b );
			x = lifted_borrow_sub8( x, 0x3f );
			x = btm8( x, 0x2b );
			x = lifted_carry_add8( x, 0x3f );
			return x;
		}

		[[nodiscard]] constexpr std::uint8_t hybrid8_sb( std::uint8_t x ) noexcept
		{
			x = lifted_carry_add8( x, 0x3f );
			x = btm8( x, 0x2b );
			x = lifted_borrow_sub8( x, 0x3f );
			x = btm8( x, 0x2b );
			return x;
		}

		[[nodiscard]] constexpr std::uint64_t bigs64( std::uint64_t value, std::size_t byte_offset ) noexcept
		{
			std::uint64_t result = 0;

			for ( std::size_t i = 0; i < 8; ++i )
			{
				const std::uint8_t in  = byte8( value, i );
				const std::uint8_t out = ( ( byte_offset + i ) & 1U ) == 0U ? hybrid8_sa( in ) : hybrid8_sb( in );
				result = with_byte8( result, i, out );
			}

			return result;
		}

		[[nodiscard]] constexpr std::uint64_t shadow_carry64( std::uint64_t a, std::uint64_t b ) noexcept
		{
			const std::uint64_t p = a ^ b;

			std::uint64_t c = a & b;
			std::uint64_t q = p;

			c ^= q & ( c << 1 );
			q &= q << 1;
			c ^= q & ( c << 2 );

			return p ^ ( c << 1 ) ^ ( c << 2 );
		}

		[[nodiscard]] constexpr std::uint64_t shadow_borrow64( std::uint64_t a, std::uint64_t b ) noexcept
		{
			const std::uint64_t p = a ^ b;

			std::uint64_t c = ( ~a ) & b;
			std::uint64_t q = ~p;

			c ^= q & ( c << 1 );
			q &= q << 1;
			c ^= q & ( c << 2 );

			return p ^ ( c << 1 ) ^ ( c << 2 );
		}
	} // namespace

	// Core permutation step.
	//
	// External input rebinding:
	// - `number_once` is injected only through XOR / ROTL-based rebinding of the
	//   current state lanes into temporary working words (ww, xx, yy, zz).
	//
	// Constant access:
	// - Four public table indices are derived from `number_once`, `counter`, and
	//   simple combinations of them.
	// - No hidden runtime constants are introduced beyond XCR_ROUND_CONSTANTS[].
	//
	// Hybrid8-Shadow nonlinear replacement:
	// - The previous native modular add/sub step is intentionally removed.
	// - The public counter selects a constant-time public round type:
	//      H-round: counter % 4 == 0
	//          yy = BigS64(yy ^ x,  0)
	//          zz = BigS64(zz ^ y,  8)
	//          ww = BigS64(ww ^ z, 16)
	//          xx = BigS64(xx ^ w, 24)
	//      S-round: otherwise
	//          yy = shadow_carry64(yy, x)
	//          zz = shadow_borrow64(zz, y)
	//          ww = shadow_carry64(ww, z)
	//          xx = shadow_borrow64(xx, w)
	// - H-round has byte-table DDT/LAT oracle semantics.
	// - S-round is intended to be modeled by finite-window DP/LC shadow oracles.
	//
	// Everything after that is XOR / ROTL diffusion.
	// The state is updated in place.

	void XorConstantRotation::PermutationARX( const std::uint64_t number_once )
	{
		// Rebind lanes with number_once injection (XOR/ROTL-only).
		// This keeps the per-call input explicit and modelable.
		std::uint64_t ww = x ^ number_once;
		std::uint64_t xx = y ^ std::rotl( number_once, 9 );
		std::uint64_t yy = z ^ std::rotl( number_once, 27 );
		std::uint64_t zz = w ^ std::rotl( number_once, 43 );

		// Table-driven constants (public indices).
		// Using different index "views" of n to avoid trivial repetition.
		const std::uint64_t RC0 = XCR_ROUND_CONSTANTS[ ( number_once ) % ROUND_CONSTANT_SIZE ];
		const std::uint64_t RC1 = XCR_ROUND_CONSTANTS[ ( counter ) % ROUND_CONSTANT_SIZE ];
		const std::uint64_t RC2 = XCR_ROUND_CONSTANTS[ ( number_once + counter ) % ROUND_CONSTANT_SIZE ];
		const std::uint64_t RC3 = XCR_ROUND_CONSTANTS[ ( ( number_once ^ std::rotl( number_once ^ counter, 3 ) ) ) % ROUND_CONSTANT_SIZE ];

		// Pre-mix (XOR-only) -> feeds the 4 carries below.
		z = xx ^ RC0;
		w = yy ^ RC1;
		x = zz ^ RC2;
		y = ww ^ RC3;

		// --- Periodic Hybrid8-Shadow nonlinear layer ---
		// H-round: exact byte-table oracle path, public period 4.
		// S-round: shadow carry/borrow finite-window oracle path.
		if ( ( counter & 3ULL ) == 0ULL )
		{
			yy = bigs64( yy ^ x, 0 );
			zz = bigs64( zz ^ y, 8 );
			ww = bigs64( ww ^ z, 16 );
			xx = bigs64( xx ^ w, 24 );
		}
		else
		{
			yy = shadow_carry64( yy, x );
			zz = shadow_borrow64( zz, y );
			ww = shadow_carry64( ww, z );
			xx = shadow_borrow64( xx, w );
		}

		// Mix
		// Rotation/XOR-only diffusion layer (no more add/sub).
		x = x ^ std::rotl( xx, 7 ) ^ ( std::rotl( yy, 19 ) ^ zz );
		y = y ^ std::rotl( yy, 11 ) ^ ( std::rotl( zz, 23 ) ^ ww );
		z = z ^ std::rotl( zz, 17 ) ^ ( std::rotl( ww, 29 ) ^ xx );
		w = w ^ std::rotl( ww, 13 ) ^ ( std::rotl( xx, 31 ) ^ yy );
	}

	// ---------------------------------------------------------------------
	// Private helper iteration
	// ---------------------------------------------------------------------
	// Role:
	// - This is an internal helper path used by initialization / warm-up style code.
	// - It accepts the same external per-call input `number_once` as the public
	//   production path, but unlike the public API it also advances the public
	//   schedule variable `counter`.
	//
	// Input separation:
	// - `number_once` is the only explicit per-call external input here.
	// - The seed is NOT directly injected here; seed influence exists only through
	//   the already-initialized internal state (w, x, y, z).
	//
	// Counter semantics:
	// - `counter` is public / trackable state used for round-constant indexing.
	// - This helper advances `counter += COUNTER_STEP` after one permutation.
	// - Because gcd(COUNTER_STEP, ROUND_CONSTANT_SIZE) = 1, the counter walk covers
	//   the constant table in a full-period modular schedule.
	//
	// Output:
	// - Returns a 128-bit view of the updated state as
	//      { x ^ y, z ^ w }.
	//
	// Modeling note:
	// - Native modular add/sub operations are not used inside PermutationARX().
	// - Nonlinearity comes from the public-period Hybrid8 H-round and the
	//   finite-window shadow carry/borrow S-round.
	// ---------------------------------------------------------------------

	XorConstantRotation::GeneratedSubKey128 XorConstantRotation::StateIteration( std::uint64_t number_once )
	{
		static_assert( ( COUNTER_STEP % ROUND_CONSTANT_SIZE ) != 0, "counter step must be nonzero mod ROUND_CONSTANT size" );
		static_assert( std::gcd( COUNTER_STEP, ROUND_CONSTANT_SIZE ) == 1, "counter step must be coprime with ROUND_CONSTANT size" );

		this->PermutationARX( number_once );

		GeneratedSubKey128 out = { x ^ y, z ^ w };

		// Public counter (uniform add; kept for period expansion & external modeling)
		counter += COUNTER_STEP;

		return out;
	}

	XorConstantRotation::GeneratedSubKey128 XorConstantRotation::operator()( std::uint64_t number_once )
	{
		// Public production path now shares the same stepping semantics:
		// one permutation + one explicit counter advance.
		return this->StateIteration( number_once );
	}

	XorConstantRotation::GeneratedSubKey128 XorConstantRotation::GenerateSubKey128( std::uint64_t number_once )
	{
		// Same public semantics as operator().
		return this->StateIteration( number_once );
	}

	// ---------------------------------------------------------------------
	// State initialization / seeded warm-up
	// ---------------------------------------------------------------------
	// Purpose:
	// - Absorb the ctor / Seed() input into the 256-bit internal state.
	// - Avoid trivial early structure such as all-zero side lanes.
	// - Build a reproducible seeded starting state before normal production calls.
	//
	// Seed path:
	// - The incoming seed is first stored in `w`.
	// - x, y, z are reset explicitly.
	// - If the input seed is zero, the code forces `w != 0` in a branch-free way
	//   before continuing, so initialization never starts from the fully-zero root.
	//
	// Warm-up structure:
	// - Initialization uses a short self-contained expansion driven by the internal
	//   helper path StateIteration().
	// - During this phase, the evolving local variable `random` is used as the
	//   `number_once` source, so warm-up does not depend on any external nonce flow.
	// - A small GGM-like two-branch expansion is used to derive two 64-bit leaves,
	//   then those leaves are folded back into the state.
	//
	// Counter handling:
	// - During warm-up, StateIteration() advances `counter`, so the helper path
	//   walks the public round-constant schedule while diffusing the seed.
	// - After warm-up, `counter` is reset to the fixed public start value
	//      counter = COUNTER_STEP;
	//   so the externally visible production phase begins from a clean,
	//   reproducible schedule state.
	//
	// Final state intent:
	// - After initialization, the object is in a seeded, nontrivial, reproducible
	//   state ready for public GenerateSubKey128()/operator() calls.
	// - Subsequent public production calls mutate the internal state AND
	//   explicitly advance `counter` in the current implementation.
	// ---------------------------------------------------------------------
	void XorConstantRotation::StateInitialize()
	{
		// Ensure w != 0 without branch:
		const std::uint64_t nonzero_flag = ( w | ( 0ULL - w ) ) >> 63;
		const std::uint64_t is_zero = nonzero_flag ^ 1ULL;
		w = w + is_zero;

		// The state w is seed
		std::uint64_t random = 0;
		std::uint64_t backup_seed = w;

		auto ggm64_rounds = [ & ]( std::uint64_t seed64 ) -> std::uint64_t {
			constexpr std::uint64_t WARMUP = 0x5741524D5550ULL;	 // "WARMUP"
			std::uint64_t			out64 = seed64;

			// 2 rounds, each round produces 64 bits
			for ( int round = 0; round < 2; ++round )
			{
				std::uint64_t next64 = 0;

				for ( int bit_index = 0; bit_index < 64; ++bit_index )
				{
					const std::uint64_t in = ( WARMUP << 48 ) ^ ( out64 << 32 ) ^ ( out64 << 16 ) ^ ( round << 8 ) ^ bit_index;

					const GeneratedSubKey128 out128 = StateIteration( in );

					const std::uint64_t bit = out128.GetBit( 127 );

					next64 = ( next64 << 1 ) | bit;
				}

				out64 = next64;
			}

			return out64;
		};

		const std::uint64_t left_input = backup_seed ^ XCR_ROUND_CONSTANTS[ ROUND_CONSTANT_SIZE - 1 ];
		const std::uint64_t right_input = backup_seed ^ XCR_ROUND_CONSTANTS[ ROUND_CONSTANT_SIZE - 2 ];
		std::uint64_t lx, rx, ly, ry, lz, rz;

		// LEFT LEAF NODES
		const std::uint64_t left_leaf = ggm64_rounds( left_input );
		// COPY
		lx = x;
		ly = y;
		lz = z;
		
		// MUST RESET TO GGM TREE ROOT!!!
		x = 0;
		y = 0;
		z = 0;
		w = backup_seed;
		// Reset to fixed public start value for production phase
		counter = COUNTER_STEP;

		// RIGHT LEAF NODES
		const std::uint64_t right_leaf = ggm64_rounds( right_input );
		// COPY
		rx = x;
		ry = y;
		rz = z;
		
		// MUST RESET TO GGM TREE ROOT!!!
		x = 0;
		y = 0;
		z = 0;
		w = backup_seed;
		// Reset to fixed public start value for production phase
		counter = COUNTER_STEP;

		// Set Random Node
		x = lx ^ rx;
		y = ly ^ ry;
		z = lz ^ rz;
		random = left_leaf ^ right_leaf;

		// Minimal fold-back (key whitening)
		w = backup_seed ^ random;
	}
}  // namespace TwilightDreamOfMagical::CustomSecurity::CSPRNG