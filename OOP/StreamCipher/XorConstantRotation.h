#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <bit>	  // std::rotl

namespace TwilightDreamOfMagical::CustomSecurity::CSPRNG
{
	// -------------------------------------------------------------------------
	// XCR (Xor-Constant-Rotation) - Balanced / analysis-friendly experimental CSPRNG-ish core
	//
	// Goals (explicit):
	// - Experimental: NOT a proven CSPRNG. Intended for iterative hardening + analysis.
	// - ARX automation-friendly: keep carry events small and countable.
	// - Engineering-friendly: integer-only, no branches, no heavy math at runtime.
	// - Constants MUST come only from ROUND_CONSTANT[] table (no "classic constants" injected).
	//
	// State:
	// - 256-bit internal state: (w, x, y, z), each uint64_t.
	//
	// Inputs:
	// - key/seed: provided ONLY through Seed()/ctor and affects ONLY StateInitialize().
	// - number_once (nonce-like, per-call input): provided ONLY to StateIteration().
	//
	// Iteration constraint:
	// - Exactly 4 modular add/sub operations on 64-bit lanes:
	//	 w += yy;  x -= zz;  y += ww;  z -= xx;
	//   Everything else is XOR / ROTL / table lookup.
	// Design rule: the key/seed is consumed ONLY by StateInitialize().
	// StateIteration() must never directly mix the key/seed; it only takes `number_once`.
	// -------------------------------------------------------------------------

	class XorConstantRotation
	{
	public:
		using result_type = std::uint64_t;

		XorConstantRotation();
		explicit XorConstantRotation(std::uint64_t seed);

		void Seed(std::uint64_t seed);

		// White-box API: caller provides number_once per output.
		result_type operator()(std::size_t number_once);

		struct GeneratedSubKey128
		{
			uint64_t a,b;
		}
		
	private:
		void StateInitialize();
		result_type StateIteration(std::size_t number_once);

		// 256-bit state
		std::uint64_t w = 0;
		std::uint64_t x = 0;
		std::uint64_t y = 0;
		std::uint64_t z = 0;
		
		// public counter 
		std::uint64_t counter = 0;

		static const std::array<std::uint64_t, 300> ROUND_CONSTANT;
	};
} // namespace TwilightDreamOfMagical::CustomSecurity::CSPRNG
