/*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * 本文件是 Algorithm_OaldresPuzzleCryptic 的一部分。
 *
 * Algorithm_OaldresPuzzleCryptic 是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是（按你的决定）任何以后版都可以。
 *
 * 发布 Algorithm_OaldresPuzzleCryptic 是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的复本。如果没有，请看 <https://www.gnu.org/licenses/>。
 */
 
 /*
 * Copyright (C) 2021-2022 Twilight-Dream
 *
 * This file is part of Algorithm_OaldresPuzzleCryptic.
 *
 * Algorithm_OaldresPuzzleCryptic is free software: you may redistribute it and/or modify it under the GNU General Public License as published by the Free Software Foundation, either under the Version 3 license, or (at your discretion) any later version.
 *
 * TDOM-EncryptOrDecryptFile-Reborn is released in the hope that it will be useful, but there are no guarantees; not even that it will be marketable and fit a particular purpose. Please see the GNU General Public License for details.
 * You should get a copy of the GNU General Public License with your program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_PBKDF2_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_PBKDF2_HPP

#include "../SecureHashProvider/HMAC_Worker.hpp"

namespace TwilightDreamOfMagical::CommonSecurity
{	namespace KeyDerivationFunction
	{
		struct PBKDF2
		{
			std::vector<std::uint8_t> WithSHA2_512
			(
				std::span<std::uint8_t> secret_passsword_or_key_byte,
				std::span<std::uint8_t> salt_data,
				const std::size_t round_count,
				std::uint64_t result_byte_size
			);
		};
	}
}

#endif	//ALGORITHM_OALDRESPUZZLECRYPTIC_PBKDF2_HPP
