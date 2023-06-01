#include "Test_OaldresPuzzle_Cryptic.h"

namespace TwilightDreamOfMagical
{
	namespace Test_OaldresPuzzle_Cryptic
	{

		/*
			Autocorrelation is a method that can be used to analyze the randomness of a sequence of numbers or bytes.
			It measures how similar a sequence is to a delayed version of itself, and can be used to identify patterns or repeating structures in the data.
		*/
		double ByteDataAutoCorrelation( const std::vector<std::uint8_t>& data, std::size_t round )
		{
			std::vector<double> auto_correlation_datas( round + 1, 0.0 );

			// Compute the mean of the data
			double mean = 0.0;
			for ( std::uint8_t x : data )
			{
				mean += static_cast<double>( x );
			}
			mean /= static_cast<double>( data.size() );

			// Compute the variance of the data
			double var = 0.0;
			for ( std::uint8_t x : data )
			{
				var += ( static_cast<double>( x ) - mean ) * ( static_cast<double>( x ) - mean );
			}
			var /= static_cast<double>( data.size() );

			// Compute the autocorrelation for each lag value
			for ( std::size_t lag = 0; lag <= round; lag++ )
			{
				double sum = 0.0;
				for ( std::size_t i = 0; i < data.size() - lag - 1; i++ )
				{
					sum += ( static_cast<double>( data[ i ] ) - mean ) * ( static_cast<double>( data[ i + lag ] ) - mean );
				}
				auto_correlation_datas[ lag ] = sum / ( ( data.size() - lag - 1 ) * var );
			}

			// Compute the average autocorrelation
			double average = 0.0;
			for ( double value : auto_correlation_datas )
			{
				average += value;
			}
			average /= static_cast<double>( auto_correlation_datas.size() );

			return average;
		}

		/*
			This function takes a ciphertext as input and returns a dictionary containing the frequency of each byte in the ciphertext, expressed as a percentage of the total number of bytes.
			You can use this function to compare the frequency distribution of the ciphertext to the expected distribution for random data.
			If the distribution of the ciphertext is significantly different from the expected distribution, this may indicate that the ciphertext is not sufficiently random.
		*/
		void ByteFrequencyAnalysis( std::span<std::uint8_t> data )
		{
			// Initialize an array to count the frequency of each byte
			std::array<std::uint32_t, 256> freq = { 0 };

			// Count the frequency of each byte in the input data
			for ( size_t i = 0; i < data.size(); i++ )
			{
				freq[ data[ i ] ]++;
			}

			// Print the frequency of each byte in the input data
			for ( std::size_t i = 0; i < 256; i++ )
			{
				if ( freq[ i ] > 0 )
				{
					std::cout << "Byte 0x" << std::hex << i << ": " << freq[ i ] << std::endl;
				}
			}
		}

		double ShannonInformationEntropy( std::vector<std::uint8_t>& data )
		{
			double					   entropy { 0.0 };
			std::size_t				   frequencies_count { 0 };
			std::map<int, std::size_t> map;

			for ( const auto& item : data )
			{
				map[ item ]++;
			}

			std::size_t size = data.size();

			for ( auto iterator = map.cbegin(); iterator != map.cend(); ++iterator )
			{
				double probability_x = static_cast<double>( iterator->second ) / static_cast<double>( size );
				entropy -= probability_x * std::log2( probability_x );
				++frequencies_count;
			}

			if ( frequencies_count > 256 )
			{
				return -1.0;
			}

			return entropy < 0.0 ? -entropy : entropy;
		}

		void UsedAlgorithmByteDataDifferences( std::string AlgorithmName, std::span<const std::uint8_t> BeforeByteData, std::span<const std::uint8_t> AfterByteData )
		{
			std::size_t DifferentByteCounter = 0;

			std::size_t CountBitOneA = 0;
			std::size_t CountBitOneB = 0;

			for ( auto IteratorBegin = ( BeforeByteData ).begin(), IteratorEnd = ( BeforeByteData ).end(), IteratorBegin2 = ( AfterByteData ).begin(), IteratorEnd2 = ( AfterByteData ).end(); IteratorBegin != IteratorEnd && IteratorBegin2 != IteratorEnd2; ++IteratorBegin, ++IteratorBegin2 )
			{
				if ( *IteratorBegin != *IteratorBegin2 )
					++DifferentByteCounter;

				CountBitOneA += std::popcount( static_cast<std::uint8_t>( *IteratorBegin ) );
				CountBitOneB += std::popcount( static_cast<std::uint8_t>( *IteratorBegin2 ) );
			}

			std::cout << "Applying this symmetric encryption and decryption algorithm "
					  << "[" << AlgorithmName << "]" << std::endl;
			std::cout << "The result is that a difference of (" << DifferentByteCounter << ") bytes happened !" << std::endl;
			std::cout << "Difference ratio is: " << static_cast<double>( DifferentByteCounter * 100.0 ) / static_cast<double>( BeforeByteData.size() ) << "%" << std::endl;

			std::cout << "The result is that a hamming distance difference of (" << ( CountBitOneA > CountBitOneB ? "+" : "-" ) << ( CountBitOneA > CountBitOneB ? CountBitOneA - CountBitOneB : CountBitOneB - CountBitOneA ) << ") bits happened !" << std::endl;
			std::cout << "Difference ratio is: " << static_cast<double>( CountBitOneA * 100.0 ) / static_cast<double>( CountBitOneB ) << "%" << std::endl;
		}

		void RunUnit( const std::vector<std::uint8_t>& PlainData, const std::vector<std::uint8_t>& Keys, const std::vector<std::uint8_t>& InitialVector, std::uint64_t LFSR_Seed, std::uint64_t NLFSR_Seed, std::uint64_t SDP_Seed ) 
		{
			using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::OaldresPuzzle_Cryptic;
			using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::OPC_MainAlgorithm_Worker;
			using TwilightDreamOfMagical::CustomSecurity::SED::BlockCipher::ImplementationDetails::CommonStateData;

			std::chrono::duration<double> TimeSpent;

			std::unique_ptr<CommonStateData>		  CommonStateDataUniquePointer = std::make_unique<CommonStateData>( 16, 32, InitialVector, LFSR_Seed, NLFSR_Seed, SDP_Seed );
			std::unique_ptr<OaldresPuzzle_Cryptic>	  AlgorithmCorePointer = std::make_unique<OaldresPuzzle_Cryptic>( *CommonStateDataUniquePointer );
			std::unique_ptr<OPC_MainAlgorithm_Worker> OPC_Worker_Pointer = std::make_unique<OPC_MainAlgorithm_Worker>( *AlgorithmCorePointer );

			//10485760 10MB
			//209715200 200MB

			//RandomGeneraterByReallyTime = std::mt19937_64(123456);

			std::chrono::time_point<std::chrono::system_clock> generateEncryptionStartTime = std::chrono::system_clock::now();

			std::vector<std::uint8_t> CipherData;
			if ( PlainData.size() % 16 != 0 )
				CipherData = OPC_Worker_Pointer->EncrypterMain( PlainData, Keys );
			else
				CipherData = OPC_Worker_Pointer->EncrypterMainWithoutPadding( PlainData, Keys );

			std::chrono::time_point<std::chrono::system_clock> generateEncryptionEndTime = std::chrono::system_clock::now();
			TimeSpent = generateEncryptionEndTime - generateEncryptionStartTime;
			std::cout << "The time spent encrypting the data: " << TimeSpent.count() << "s" << std::endl;

			/*
				Reset cipher state
			*/
			OPC_Worker_Pointer.reset();
			AlgorithmCorePointer.reset();
			CommonStateDataUniquePointer.reset();

			CommonStateDataUniquePointer = std::make_unique<CommonStateData>( 16, 32, InitialVector, LFSR_Seed, NLFSR_Seed, SDP_Seed );
			AlgorithmCorePointer = std::make_unique<OaldresPuzzle_Cryptic>( *CommonStateDataUniquePointer );
			OPC_Worker_Pointer = std::make_unique<OPC_MainAlgorithm_Worker>( *AlgorithmCorePointer );

			std::chrono::time_point<std::chrono::system_clock> generateDecryptionStartTime = std::chrono::system_clock::now();

			std::vector<std::uint8_t> ProcessData;
			if ( PlainData.size() % 16 != 0 )
				ProcessData = OPC_Worker_Pointer->DecrypterMain( CipherData, Keys );
			else
				ProcessData = OPC_Worker_Pointer->DecrypterMainWithoutUnpadding( CipherData, Keys );

			std::chrono::time_point<std::chrono::system_clock> generateDecryptionEndTime = std::chrono::system_clock::now();
			TimeSpent = generateDecryptionEndTime - generateDecryptionStartTime;
			std::cout << "The time spent decrypting the data: " << TimeSpent.count() << "s" << std::endl;

			OPC_Worker_Pointer.reset();

			volatile bool IsSameData = true;

			for ( volatile std::size_t DataIndex = 0; DataIndex < ProcessData.size(); ++DataIndex )
			{
				if ( PlainData[ DataIndex ] != ProcessData[ DataIndex ] )
				{
					IsSameData = false;
					break;
				}
			}

			if ( IsSameData )
			{
				std::cout << "The data after this operation is correct!" << std::endl;
				std::cout << "Yeah! \nThe module is normal work!" << std::endl;

				UsedAlgorithmByteDataDifferences( "CustomBlockCryptograph - OaldresPuzzle_Cryptic By Twilight-Dream", PlainData, CipherData );

				auto ShannonInformationEntropyValue0 = ShannonInformationEntropy( CipherData );
				std::cout << "Encrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue0 << std::endl;
				auto ShannonInformationEntropyValue1 = ShannonInformationEntropy( ProcessData );
				std::cout << "Decrypted Data, Shannon information entropy is :" << ShannonInformationEntropyValue1 << std::endl;

				if ( ShannonInformationEntropyValue0 > ShannonInformationEntropyValue1 )
					std::cout << "Difference of entropy degree of sequential data :" << ShannonInformationEntropyValue0 - ShannonInformationEntropyValue1 << std::endl;

				auto AutoCorrelationValue = ByteDataAutoCorrelation( CipherData, 64 );
				std::cout << "The rate of 64 rounds of autocorrelated data :" << ShannonInformationEntropyValue1 << std::endl;
			}
			else
			{
				std::cout << "The data after this operation is incorrect!" << std::endl;
				std::cout << "Oh, no!\nThe module is not processing the correct data." << std::endl;
			}

			CipherData.clear();
			ProcessData.clear();

			CipherData.shrink_to_fit();
			ProcessData.shrink_to_fit();
		}
	}  // namespace Test_OaldresPuzzle_Cryptic
}