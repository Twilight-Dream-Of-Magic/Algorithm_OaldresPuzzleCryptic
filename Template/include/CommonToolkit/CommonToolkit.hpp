/*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * 本文件是 TDOM-EncryptOrDecryptFile-Reborn 的一部分。
 *
 * TDOM-EncryptOrDecryptFile-Reborn 是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是（按你的决定）任何以后版都可以。
 *
 * 发布 TDOM-EncryptOrDecryptFile-Reborn 是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的复本。如果没有，请看 <https://www.gnu.org/licenses/>。
 */

 /*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * This file is part of TDOM-EncryptOrDecryptFile-Reborn.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "./CPP2020_Concept.hpp"

#ifndef COMMON_TOOLKIT_HPP
#define COMMON_TOOLKIT_HPP

#if __cplusplus >= 202002L

namespace CommonToolkit
{
	using namespace EODF_Reborn_CommonToolkit::CPP2020_Concepts;

	namespace MakeArrayImplement
	{
		template<typename Type, std::size_t N, std::size_t... I>
		constexpr auto make_array(std::index_sequence<I...>)
		{
			return std::array<Type, N>{ {I...} };
		}

		template<typename Type, typename FunctionType, std::size_t... Is>
		requires std::invocable<FunctionType>
		constexpr auto generate_array(FunctionType& function, std::index_sequence<Is...>) -> std::array<Type, sizeof...(Is)>
		{
			return {{ function(std::integral_constant<std::size_t, Is>{})... }};
		}
	}

	template<typename Type, std::size_t N>
	constexpr auto make_array()
	{
		static_assert(N >= Type{}, "no negative sizes");
		return MakeArrayImplement::make_array<Type, N>(std::make_index_sequence<N>{});
	}

	template<typename Type, std::size_t N, typename FunctionType>
	requires std::invocable<FunctionType>
	constexpr auto generate_array(FunctionType function)
	{
		return MakeArrayImplement::generate_array<Type>(function, std::make_index_sequence<N>{});
	}

	namespace MakeVectorImplement
	{
		template <typename Type, Type... VALUES>
		constexpr std::vector<Type> make_vector()
		{
			return std::vector<Type> { VALUES... };
		}
	}

	template <typename Type, Type... VALUES>
	constexpr std::vector<Type> make_vector( std::integer_sequence<Type, VALUES...> )
	{
		return MakeVectorImplement::make_vector<Type, VALUES...>();
	}

	//https://vladris.com/blog/2018/10/13/arithmetic-overflow-and-underflow.html
	//https://zh.cppreference.com/w/cpp/algorithm/iota
	template<bool is_increment_or_decrement, std::input_or_output_iterator IteratorType, typename IteratorSentinelType, typename NumericalType>
	requires std::sentinel_for<IteratorSentinelType, IteratorType>
	&& std::signed_integral<NumericalType>
	|| std::unsigned_integral<NumericalType>
	void numbers_sequence_generator(IteratorType first, IteratorSentinelType last, NumericalType value)
	{
		while (first != last)
		{
			*first++ = value;

			if constexpr(is_increment_or_decrement)
			{
				if(value + 1 == std::numeric_limits<NumericalType>::min())
					break;
				++value;
			}
			else if constexpr(is_increment_or_decrement)
			{
				if(value - 1 == std::numeric_limits<NumericalType>::max())
					break;
				--value;
			}
		}
	}

	template<bool is_increment_or_decrement, std::bidirectional_iterator IteratorType, typename IteratorSentinelType, typename NumericalType>
	requires std::integral<NumericalType>
	&& std::sentinel_for<IteratorSentinelType, IteratorType>
	void numbers_sequence_generator(IteratorType first, IteratorSentinelType last, NumericalType value, NumericalType other_value)
	{
		std::iter_difference_t<IteratorType> ranges_size = std::ranges::distance(first, last);

		if(ranges_size > 0)
		{
			while (first != last)
			{
				/*
					Equivalence Code:

					*first = value;
					first++;

				*/
				*first++ = value;

				if constexpr(is_increment_or_decrement)
				{
					//AdditionOverflows
					if( (other_value >= 0) && (value > std::numeric_limits<NumericalType>::max() - other_value) )
						break;
					//AdditionUnderflows
					else if( (other_value < 0) && (value < std::numeric_limits<NumericalType>::min() - other_value) )
						break;
					value += other_value;
				}
				else if constexpr(!is_increment_or_decrement)
				{
					//SubtractionOverflows
					if( (other_value < 0) && (value > std::numeric_limits<NumericalType>::max() + other_value) )
						break;
					//SubtractionOverflows
					else if( (other_value >= 0) && (value < std::numeric_limits<NumericalType>::min() + other_value) )
						break;
					value -= other_value;
				}
			}
		}
		else if (ranges_size < 0)
		{
			while (last != first)
			{
				/*
					Equivalence Code:

					*first = value;
					first--;

				*/
				*first-- = value;

				if constexpr(is_increment_or_decrement)
				{
					//AdditionOverflows
					if( (other_value >= 0) && (value > std::numeric_limits<NumericalType>::max() - other_value) )
						break;
					//AdditionUnderflows
					else if( (other_value < 0) && (value < std::numeric_limits<NumericalType>::min() - other_value) )
						break;
					value += other_value;
				}
				else if constexpr(!is_increment_or_decrement)
				{
					//SubtractionOverflows
					if( (other_value < 0) && (value > std::numeric_limits<NumericalType>::max() + other_value) )
						break;
					//SubtractionOverflows
					else if( (other_value >= 0) && (value < std::numeric_limits<NumericalType>::min() + other_value) )
						break;
					value -= other_value;
				}
			}
		}
		else
		{
			return;
		}
	}

}  // namespace CommonToolkit

#endif	// __cplusplus

#endif	// !COMMON_TOOLKIT_HPP
