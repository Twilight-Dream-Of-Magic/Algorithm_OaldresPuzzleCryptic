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

#ifndef ALGORITHM_OALDRESPUZZLECRYPTIC_HMAC_WORKER_HPP
#define ALGORITHM_OALDRESPUZZLECRYPTIC_HMAC_WORKER_HPP

#include "../../CommonSecurity.hpp"
#include "SHA2_512.hpp"

namespace TwilightDreamOfMagical::CommonSecurity
{	namespace DataHashingWrapper
	{
		/**
		*	https://zh.wikipedia.org/wiki/HMAC
		*	密钥散列消息认证码（英语：Keyed-hash message authentication code），又称散列消息认证码（Hash-based message authentication code，缩写为HMAC）
		*	是一种通过特别计算方式之后产生的消息认证码（MAC），使用密码散列函数，同时结合一个加密密钥。
		*	它可以用来保证资料的完整性，同时可以用来作某个消息的身份验证。
		*	https://en.wikipedia.org/wiki/HMAC
		*	In cryptography, an HMAC (sometimes expanded as either keyed-hash message authentication code or hash-based message authentication code)
		*	is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key.
		*	As with any MAC, it may be used to simultaneously verify both the data integrity and authenticity of a message.
		*	HMAC can provide authentication using a shared secret instead of using digital signatures with asymmetric cryptography.
		*	It trades off the need for a complex public key infrastructure by delegating the key exchange to the communicating parties, who are responsible for establishing and using a trusted channel to agree on the key prior to communication.
		*/
		class HMAC_Worker
		{

		public:
			// Outer padded key
			static constexpr char OuterPaddingKey = 0x5c;
			// Inner padded key
			static constexpr char InnerPaddingKey = 0x36;

			explicit HMAC_Worker(SHA::SHA2_512& HashFunctionInstance)
				: SHA2_512_Pointer(std::addressof(HashFunctionInstance))
			{

			}

			~HMAC_Worker()
			{
				if(SHA2_512_Pointer != nullptr)
					SHA2_512_Pointer.reset();
			}

			void GivenKeyWith_SHA2_512(const std::string& Key)
			{
				static constexpr std::size_t BLOCK_SIZE = 64;

				//Key after hashing and padding
				std::string KeyPaddings( BLOCK_SIZE, 0x00 );

				//Keys are processed according to the block size of the hash function
				if(Key.size() > BLOCK_SIZE)
				{
					// Keys longer than blockSize are shortened by hashing them
					// 长于blockSize的密钥通过散列来缩短其长度

					SHA2_512_Pointer->Hash(Key, KeyPaddings);
				}
				else if(Key.size() < BLOCK_SIZE)
				{
					// Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
					// 短于blockSize的键被填充到blockSize，在右边用0填充。

					KeyPaddings = Key;

					for ( std::size_t index = 0; index < BLOCK_SIZE; ++index )
					{
						// Pad key with zeros to make it blockSize bytes long
						if ( index < BLOCK_SIZE - Key.size() )
						{
							KeyPaddings[ index ] = 0x00;
						}
						else
						{
							KeyPaddings[ index ] = Key[ index - ( BLOCK_SIZE - Key.size() ) ];
						}
					}
				}
				else
				{
					// If the key is exactly equal to the block size, use it directly
					KeyPaddings = Key;
				}

				OuterPaddedKeys.resize( BLOCK_SIZE, 0x5C );
				InnerPaddedKeys.resize( BLOCK_SIZE, 0x36 );

				for ( std::size_t index = 0; index < BLOCK_SIZE; ++index )
				{
					OuterPaddedKeys[ index ] ^= KeyPaddings[ index ];
					InnerPaddedKeys[ index ] ^= KeyPaddings[ index ];
				}
			}

			void With_SHA2_512
			(
				const std::string& Message,
				std::string& Digest
			);

		private:
			std::unique_ptr<SHA::SHA2_512> SHA2_512_Pointer = nullptr;
			std::string OuterPaddedKeys; // inner padding key
			std::string InnerPaddedKeys; // Outer padding key
		};
	}
}

#endif	//ALGORITHM_OALDRESPUZZLECRYPTIC_HMAC_WORKER_HPP
