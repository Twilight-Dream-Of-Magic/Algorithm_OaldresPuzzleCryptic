#include "HMAC_Worker.hpp"

namespace TwilightDreamOfMagical::CommonSecurity
{	namespace DataHashingWrapper
	{
		void HMAC_Worker::With_SHA2_512
		(
			const std::string& Message,
			std::string& Digest
		)
		{
			my_cpp2020_assert(SHA2_512_Pointer != nullptr, "Oops, HMAC doesn't have a SHA2 512-bit instance right now.",std::source_location::current());

			static constexpr std::size_t BLOCK_SIZE = 64;

			std::string FirstData = InnerPaddedKeys + Message;
			std::string FirstHashedData( BLOCK_SIZE, 0x00 );
			SHA2_512_Pointer->Hash( FirstData, FirstHashedData);

			std::string LastData = OuterPaddedKeys + FirstHashedData;
			std::string LastHashedData( BLOCK_SIZE, 0x00 );
			SHA2_512_Pointer->Hash( LastData, LastHashedData);

			FirstData.clear();
			FirstHashedData.clear();
			LastData.clear();

			Digest = LastHashedData;
		}
	}
}