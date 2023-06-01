#### NIST 800-22 Rev1 - Randomness Test (Evaluate Type 1 Algorithm)
#### NIST 800-22 Rev1 - 随机性测试（评估 Type 1 算法）

***Chacha20 vs XorConstantRotation with use NIST RNG(Data Visualization)***   
***Chacha20与使用NIST RNG的XorConstantRotation的比较(数据可视化)***   

Use the console to run `pip install nistrng` to prepare for the NIST 800-22 Rev1 - Randomness Test   

使用控制台运行 `pip install nistrng` 准备做 NIST 800-22 Rev1 - 随机性测试   

Github: [NistRng](https://github.com/InsaneMonster/NistRng)   


`CSPRNG_XorConstantRotation.h`
```c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

//ROUND_CONSTANT length is 300
static uint64_t XCR_ROUND_CONSTANT[] = {
	//Concatenation of Fibonacci numbers., π, φ, e
	0x01B70C8E97AD5F98,0x243F6A8885A308D3,0x9E3779B97F4A7C15,0xB7E151628AED2A6A,
	
	//#x ∈ [1, 138] 
	//f(x) = (e^x - cos(πx)) * (φx^2 - φx - 1) * (x√2 - floor(x√2)) * (x√3 - floor(x√3)) * ln(1+x) * (xδ - floor(xδ)) * (xρ - floor(xρ))
	0x6a433d2ae48d4c90,0x9e2b6e6880ad26da,0x5380e7890f281d86,0x47ea9e01d8ef7c3c,
	0xb7cfc42c4640a591,0x8ba869f86f575f77,0x66ff83fd9954772c,0x0552755b7ef8c3f6,
	0xe4931d40d079c5cb,0xd6065bf025a81d13,0x586ceb7761d284af,0x5407a44155b8e341,
	0x7810f48181dff9e2,0x0f44524582d1d6cf,0x919ad67c2cd7118c,0x926d94a3923cb938,
	0xc3f400bd67479e59,0x83cb03ba7366b70e,0x629043e6e5712e5c,0x69589ff399736efb,
	0x834d96f80eea56d7,0x02992cb1835476aa,0x78502c2a1b947013,0xbca81dad05eac8c7,
	0x43216fe770f57c2d,0x604a5ccfe888eef1,0xfcf5bdd0ea8a112c,0xeb13dc4ba7327617,
	0xf8587cc0dd587813,0x092b98e058140b26,0x1e044153ec902650,0xd13ef3afb71efc3e,
	0x55af3f5bca28309e,0xcf478054be1173c8,0x99bb2b591f35ac72,0xd3f5e092a0c7c2bb,
	0xdc120bced1935766,0xbb2525cf28193ea8,0x6a06eb360550e537,0x4501817d5023f9bb,
	0x6c9e6ef207e06420,0xa12e023656301669,0x2692fa5ed25b6a2b,0xeb48ef08fd6fbdb7,
	0xfe8db57151c600fb,0x51197bfba60c36ff,0xe95328ef18701542,0x0663e86118debfdd,
	0xee0b0fcbaf12d0d0,0xc92c72f7a14c35ea,0x21ca0bd30529c74c,0x70243d7854330319,
	0x193b70b72995d737,0xa936acbbbe88f426,0x61da22530a461898,0x49afa0f477bda24c,
	0x795bbbc0bf0cdc23,0x3b5f4cf676e0fc41,0xdeec67413dc24105,0x1af46f766498679d,
	0xa9f37172c15f8e20,0x292b237adf6467a9,0x09538ddc3733c79e,0xde5c2f22b2c1aa42,
	0x6204c7ebee5a90d8,0x4359ac75de286849,0x7e616650ab318ae8,0xd7552e509ab0d5a6,
	0xffaf2a408f8cfa95,0x4289e66a0b74427e,0xc5e9869af1856c6d,0x336aa2e2b3dbfeda,
	0x9835ff10bf4b7e3c,0xc0c5d995789a9c04,0x09dce0a22fccbe60,0x7cc16b5458b38ec9,
	0x880d6019ab1aa3fa,0xb9ac43e6d90c89dc,0xe0c876bea28b38be,0xafca75b1c80bc8fa,
	0xf4e5b08059acb0bd,0x643587ac551f3aa0,0x83fa523817844ac9,0x3e97eca86cc41268,
	0xd53517b095a47a79,0x418aaab53810d432,0xde9ad8739ba769b7,0x6f53b6fb08b9809c,
	0xe5d41d82eb6a0d63,0x42137200d3b75b64,0x9ee670cd25143c29,0xdc2b3edf3617c034,
	0xf5d6d70093472506,0xeaca4e8f7eaa4b68,0x0e7b78a6eca0e67e,0x67db9133f144d92d,
	0xa2f043bdf0bfc70d,0x679513157c68480e,0xc7359f77d43ecedb,0xa73610dd579db5e8,
	0xd33f00a73c40b3f4,0x1f6693cdc79f41cf,0x402aba3326ff09e4,0xc2f06d96a33ed417,
	0x16882cd0ac38796e,0xde2342960e538c6e,0xee16a05c0f946350,0xb76895e14d9f81b0,
	0x8d8e566bbc5b2b65,0x1b1881ca8831ba3c,0x0fb99dab44900c06,0x51701c39eabb7550,
	0x98c5cadd4f0446cd,0x12cd6ac42824463f,0x815f799d0d2b6b8d,0xd34bed6a3284fb8f,
	0x1f4f71425e521345,0x5ec3427cc37ef4b7,0x41ca4c3fbb4ae014,0x4d4a5a8399958a44,
	0x6f21b526d0c7ee3c,0xe85d52cfba2818c0,0x09d0b2cc4deccc35,0x1b13c064ccec4d2e,
	0x92b538d3b747c6ac,0x58719d59011b3fae,0xedde21671368f97e,0xfc4dbeff22c77aab,
	0x66997342600d0997,0x6a173e62da2821d7,0xe657b797f1f23506,0x7052226e4dde4ce0,
	0xcec9d219091d3713,0x46b20fcd9abd9b13,0x0a8bbb7b077261a8,0x8cf03c3c366533db,
	0x9d167cec4a7f4953,0xed8bbf927c48dbf9,0x21e8d4a1dd84e782,0x4ac104ee6fa65e69,
	0x5cb955963da25bee,0xa0f791f755ed9ead,0x1125fa77491b7c6a,0x3c0560dc8d08a6b6,
	0x20cb39c7b8690d0c,0x29a3a26ccc8540de,0x3ba44a4cbb906982,0xddf9454bc0acb110,
	0xa989a47d915cc360,0xb90af4a05b78e702,0x7f20b78fb8d8eae8,0xedb6cb8180b81603,
	0xdfe86decf8f940b5,0x4c6baf1de449fc4d,0x165f86d08961df51,0x4c038e6a96040825,
	0xf4f2cb95b6276944,0xe7f98f0aae90ff54,0xd90fc39cae09f82e,0x45ef9b03350e102c,
	0xba319140b8a35152,0xa1c8bf3071254d17,0x6d942b49712b2ff0,0x687ab4e1a35f3a7f,
	0x8fa2a50edfdfce2d,0x1b123d5c5ba08e5b,0x287209f7e4ad4cd4,0xaae61796f1414dd9,
	0xabd88a4167ec1728,0x584654213d59d9ac,0x1010e8491f4e2d7d,0x01b6087b68d105e5,
	0xd478306668f2aed3,0x35b78cf5c30272db,0x4e9b1bd35706711d,0xfbee714f84a270e5,
	0x8855b3fe8d108055,0x1829c0415ef92080,0x2a6238b05b1e17f1,0x270e32a624ce5105,
	0x03a089b9cf427251,0x468ff8821f5007cd,0xf3f13de46ea0de52,0x2353e2eb32dd119c,
	0x5deef337d58f8050,0x4627b46ab323ee76,0x6bc50f6c85bf5ee4,0x4e85d72c7ad96e41,
	0xb3a3842fd79e9b66,0xc1b355c2514cc12b,0x4d8d8e57e20a533f,0x9a230f94a80cc9cc,
	0x20287e80ba5f6a99,0xbf798e5356d5544d,0xa4b98b8f7cf5d947,0x5dfec4b0cf53d480,
	0xaff6108433392823,0xc77e7eafb9c35034,0x627f1e008407d3a4,0xd8187da069398c24,
	0x5b82e2951399fb6b,0x8f4165a5b13ef5e5,0xccc6836e6da90f20,0x5bc18466d41ea4b4,
	0xae57d5f0e7469301,0x382ec77f6dda7973,0x3334a04bfaf89130,0x560ae692d459495d,
	0xad396981b2cc54c6,0x721ee73a08477f9d,0xac3af4d5f2b948ae,0x8f027b0998907e6a,
	0xa2aa2576933135d2,0xf977e97a32d0ff40,0xc9ec4b2937331421,0x0a60651dd255075e,
	0xbc57a87285ad8ce8,0x05f745bb0f2f26c5,0xdbcb6ea37829349e,0xac85ec736c6c05f0,
	0xa0b8478607780956,0xe1a6cfc18a52c5cf,0xfdc0c9870db192cb,0x6fef6fa94de1275f,
	0xe7095cf3a87858df,0xa9382116dc12addf,0xfe43770e8ee1fdd0,0x12b5911c68f5a4fa,
	0xf674859107a9946e,0xbcbcec98535a2e90,0x487bbba9ec45c860,0xa6690ca5bfae55ef,
	0x2e90b70e4a6edd45,0xf75f315df85c92de,0x73c4b5d3f00c8ff6,0x16e7c2df5e0cc2fd,
	0x4d3450b5d1238d73,0x3be2360b8e8b5abf,0xaa9f15256af3545e,0x0b78b50380d558f5,
	0x35b1cd715c1a79c2,0xa5fd04e9b573386e,0xe8287684ad00498d,0x3af5a5175be12d85,
	0x00bad43e22f3efd0,0x2424d7c00ce3eea8,0x43be6edf2c578cf0,0x4640b84a827945fc,
	0x7e85782d5ed0fb6d,0xffde4449d800463d,0x5505de67825caf7c,0x958bad14a0d2bebd,
	0x19031376b81730d2,0xffe7c1cfd5aaf333,0x4a7cd21c4d61a00c,0xd955c74fee9622b4,
	0xdb600428f8ec65bd,0x412e30c19e4e9b47,0x1b39e37cd46c51fc,0x0b328354c1031b99,
	0x71eb9da5c27e6be7,0x56dd31a71467973d,0x9cefe510b69e8058,0x516e50ccb614f4a3,
	0x2feb109a1269f007,0x5bed5039f264362c,0x5a35a81fc188b664,0x86da46de6967b611,
	0x21cbe3aa2bf1e587,0x814748b95e35060d,0x4532a469e90aafc3,0xe7cdfd61261c5f5f,
	0x5f9ed3b7b2f0e4c7,0x8633484a1fe91578,0x07982616ddb26917,0x0a4a8fa267fd8e35,
	0x0169aa3ddb17bbe0,0x7ad23781004a8abb,0x8a99977154276184,0xf5aa49eb805db993,
	0xa91402c443f56747,0x3a158fd200401788,0x90d1286159a88e33,0x225ba3c00271a613,
	0xee87820cfe2bc5c1,0xf9cdfc0003d47859,0x58c3aeb0ed7bd81b,0x9dd2e17302417c1c,
	0x83236763812fd272,0x66337800026dd3d8,0x67926c64cdb2e951,0x28cd00001a9deeb6,
	0x7f5198092527e597,0x87de18001de39c2a,0x2389f07669962eee,0x4f2800002f2e26ac
};

#define ROUND_CONSTANT_SIZE (sizeof(XCR_ROUND_CONSTANT) / sizeof(uint64_t))

uint64_t left_rotate64(uint64_t n, uint64_t bits){
	uint64_t left = n << bits;
	uint64_t right = n >> (64 - bits);
	return (left | right) & 0xFFFFFFFFFFFFFFFF;
}

uint64_t right_rotate64(uint64_t n, uint64_t bits){
	uint64_t left = n >> bits;
	uint64_t right = n << (64 - bits);
	return (left | right) & 0xFFFFFFFFFFFFFFFF;
}

typedef struct {
	uint64_t x;
	uint64_t y;
	uint64_t state;
} XorConstantRotation;

void XorConstantRotation_initial(XorConstantRotation* instance, uint64_t seed) {
	instance->x = 0;
	instance->y = 0;
	instance->state = seed;
	return instance;
}

uint64_t XorConstantRotation_round(XorConstantRotation *instance, uint64_t round) {
	instance->y = (instance->x ^ left_rotate64(instance->state, 32)) ^ left_rotate64(instance->state, 19);
	if(instance->x == 0){
		instance->x = XCR_ROUND_CONSTANT[round % ROUND_CONSTANT_SIZE];
	}else{
		instance->x = instance->x + (left_rotate64(instance->x, 7) ^ XCR_ROUND_CONSTANT[round % ROUND_CONSTANT_SIZE]);
	}
	instance->state = (instance->state + (instance->x ^ instance->y));
	return instance->y;
}

```

`chacha20.h`
```c

typedef struct {
	uint32_t state[16];
} ChaCha20;

void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
	*a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
	*c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
	*a += *b; *d ^= *a; *d = (*d <<  8) | (*d >> 24);
	*c += *d; *b ^= *c; *b = (*b <<  7) | (*b >> 25);
}

void chacha20_block(ChaCha20 *instance) {
	uint32_t *state = instance->state;
	uint32_t x[16];
	memcpy(x, state, sizeof(uint32_t) * 16);

	for (int i = 0; i < 10; i++) {
		quarter_round(&x[0], &x[4], &x[8],  &x[12]);
		quarter_round(&x[1], &x[5], &x[9],  &x[13]);
		quarter_round(&x[2], &x[6], &x[10], &x[14]);
		quarter_round(&x[3], &x[7], &x[11], &x[15]);
		quarter_round(&x[0], &x[5], &x[10], &x[15]);
		quarter_round(&x[1], &x[6], &x[11], &x[12]);
		quarter_round(&x[2], &x[7], &x[8],  &x[13]);
		quarter_round(&x[3], &x[4], &x[9],  &x[14]);
	}

	for (int i = 0; i < 16; i++) {
		state[i] += x[i];
	}
}

void chacha20_encrypt(ChaCha20 *instance, const uint8_t *input, uint8_t *output, size_t size) {
	size_t remaining = size;

	while (remaining >= 64) {
		chacha20_block(instance);
		for (int i = 0; i < 64; i++) {
			output[i] = input[i] ^ ((uint8_t *)instance->state)[i];
		}
		input += 64;
		remaining -= 64;
		output += 64;
	}

	if (remaining > 0) {
		chacha20_block(instance);
		for (int i = 0; i < remaining; i++) {
			output[i] = input[i] ^ ((uint8_t *)instance->state)[i];
		}
	}
}

void chacha20_key_setup(ChaCha20 *instance, const uint8_t *key, const uint8_t *nonce, uint32_t counter) {
	instance->state[0] = 0x61707865; // "expa"
	instance->state[1] = 0x3320646e; // "nd 3"
	instance->state[2] = 0x79622d32; // "2-by"
	instance->state[3] = 0x6b206574; // "te k"

	instance->state[4] = ((uint32_t *)key)[0];
	instance->state[5] = ((uint32_t *)key)[1];
	instance->state[6] = ((uint32_t *)key)[2];
	instance->state[7] = ((uint32_t *)key)[3];

	instance->state[8] = ((uint32_t *)key)[4];
	instance->state[9] = ((uint32_t *)key)[5];
	instance->state[10] = ((uint32_t *)key)[6];
	instance->state[11] = ((uint32_t *)key)[7];

	instance->state[12] = counter;

	instance->state[13] = ((uint32_t *)nonce)[0];
	instance->state[14] = ((uint32_t *)nonce)[1];
	instance->state[15] = ((uint32_t *)nonce)[2];
}
```

`snow5.h`
```c
#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

///////////////////////////////

uint8_t RijndaelSubstitutionBox[256] =
{
	0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
	0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
	0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
	0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
	0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
	0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
	0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
	0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
	0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
	0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
	0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
	0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
	0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
	0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
	0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
	0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

#define MAKEU32(a, b) (((uint32_t)(a) << 16) | ((uint32_t)(b) ))
#define MAKEU16(a, b) (((uint16_t)(a) << 8) | ((uint16_t)(b) ))

typedef struct {
	uint16_t A[16], B[16]; //LFSR
	uint32_t R1[4], R2[4], R3[4]; // FSM

	uint32_t RijndaelKey1[4];
	uint32_t RijndaelKey2[4];
	uint8_t Sigma[16]; //Rijndael state index
} SNOW5;

void SNOW5_initialize_zero_key(SNOW5* instance)
{
	for (uint32_t i = 0; i < 4; i++)
		instance->RijndaelKey1[i] = instance->RijndaelKey2[i] = 0x00000000;

	uint8_t Sigma[16] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
	memcpy(&(instance->Sigma), &Sigma, 16);

	for (uint32_t i = 0; i < 4; i++)
		instance->R1[i] = instance->R2[i] = instance->R3[i] = 0x00000000;
}

void SNOW5_initialize(SNOW5* instance, uint32_t RijndaelKey1[4], uint32_t RijndaelKey2[4])
{
	memcpy(&(instance->RijndaelKey1), RijndaelKey1, 4 * sizeof(uint32_t));
	memcpy(&(instance->RijndaelKey2), RijndaelKey2, 4 * sizeof(uint32_t));

	uint8_t Sigma[16] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
	memcpy(&(instance->Sigma), &Sigma, 16);

	for (uint32_t i = 0; i < 4; i++)
		instance->R1[i] = instance->R2[i] = instance->R3[i] = 0x00000000;
}

void SNOW5_rijndael_encryption_round_step(SNOW5* instance, const uint32_t state_index, const uint8_t* substituted_bytes, uint32_t *result, const uint32_t *round_key)
{
	uint32_t Word32Bit = 0, TransformedWord32Bit = 0;

	//Rijndael: Shift row (16 bytes concatenated into four 32Bits)
	Word32Bit = ((uint32_t)(substituted_bytes[(state_index * 4 + 0) % 16])) << (3 * 8)
	| ((uint32_t)(substituted_bytes[(state_index * 4 + 5) % 16])) << (0 * 8)
	| ((uint32_t)(substituted_bytes[(state_index * 4 + 10) % 16])) << (1 * 8)
	| ((uint32_t)(substituted_bytes[(state_index * 4 + 15) % 16])) << (2 * 8);

	//Rijndael: Mix column
	TransformedWord32Bit = ((Word32Bit << 16) | (Word32Bit >> (32 - 16)))
		^ ((Word32Bit << 1) & 0xfefefefeUL) ^ (((Word32Bit >> 7) & 0x01010101UL) * 0x1b);

	//Rijndael: Use round key
	result[state_index] = round_key[state_index]
		^ Word32Bit
		^ TransformedWord32Bit ^ ((TransformedWord32Bit << 16) | (TransformedWord32Bit >> (32 - 8)));
}

void SNOW5_rijndael_encryption_round(SNOW5* instance, uint32_t *result, const uint32_t *state, const uint32_t *round_key)
{
	uint8_t substituted_bytes[16] = {0x00};

	//Rijndael Substitute bytes (Four 32Bits split into 16 bytes)
	for (uint32_t i = 0; i < 4; i++)
		for (uint32_t j = 0; j < 4; j++)
			substituted_bytes[i * 4 + j] = RijndaelSubstitutionBox[(state[i] >> (j * 8)) & 0xff];
	
	SNOW5_rijndael_encryption_round_step(instance, 0, substituted_bytes, result, round_key);
	SNOW5_rijndael_encryption_round_step(instance, 1, substituted_bytes, result, round_key);
	SNOW5_rijndael_encryption_round_step(instance, 2, substituted_bytes, result, round_key);
	SNOW5_rijndael_encryption_round_step(instance, 3, substituted_bytes, result, round_key);
}

void SNOW5_permute_sigma(SNOW5* instance, uint32_t *state)
{
	uint8_t transformed_sigma[16];
	for (uint32_t i = 0; i < 16; i++)
		transformed_sigma[i] = (uint8_t)(state[instance->Sigma[i] >> 2] >> ((instance->Sigma[i] & 3) << 3));
	for (uint32_t i = 0; i < 4; i++)
		state[i] = MAKEU32(MAKEU16(transformed_sigma[4 * i + 3], transformed_sigma[4 * i + 2]), MAKEU16(transformed_sigma[4 * i + 1], transformed_sigma[4 * i]));
}

void SNOW5_FSM_update(SNOW5* instance)
{
	uint32_t R1_Copy[4];
	memcpy(R1_Copy, instance->R1, sizeof(instance->R1));

	for (int i = 0; i < 4; i++)
	{
		uint32_t T2 = MAKEU32(instance->A[2 * i + 1], instance->A[2 * i]);
		instance->R1[i] = (T2 ^ instance->R3[i]) + instance->R2[i];
	}
	SNOW5_permute_sigma(instance, instance->R1);
	SNOW5_rijndael_encryption_round(instance, instance->R3, instance->R2, instance->RijndaelKey2);
	SNOW5_rijndael_encryption_round(instance, instance->R2, R1_Copy, instance->RijndaelKey1);
}

uint16_t LFSR_16_Multiply_X(uint16_t v, uint16_t c)
{
	if (v & 0x8000)
		return (v << 1) ^ c;
	else
		return (v << 1);
}

uint16_t LFSR_16_MultiplyInverse_X(uint16_t v, uint16_t d)
{
	if (v & 0x0001)
		return(v >> 1) ^ d;
	else
		return (v >> 1);
}


void SNOW5_LFSR_update(SNOW5* instance)
{
	for (int i = 0; i < 8; i++)
	{
		uint16_t u = LFSR_16_Multiply_X(instance->A[0], 0x990f) ^ instance->A[1] ^ LFSR_16_MultiplyInverse_X(instance->A[8], 0xcc87) ^ instance->B[0];
		uint16_t v = LFSR_16_Multiply_X(instance->B[0], 0xc963) ^ instance->B[3] ^ LFSR_16_MultiplyInverse_X(instance->B[8], 0xe4b1) ^ instance->A[0];
		for (int j = 0; j < 15; j++)
		{ 
			instance->A[j] = instance->A[j + 1];
			instance->B[j] = instance->B[j + 1];
		}
		instance->A[15] = u;
		instance->B[15] = v;
	}
}

void SNOW5_keystream(SNOW5* instance, uint8_t *keystream_data)
{
	for (int i = 0; i < 4; i++)
	{
		uint32_t T1 = MAKEU32(instance->B[2 * i + 9], instance->B[2 * i + 8]);
		uint32_t v = (T1 + instance->R1[i]) ^ instance->R2[i];
		keystream_data[i * 4 + 0] = (v >> 0) & 0xff;
		keystream_data[i * 4 + 1] = (v >> 8) & 0xff;
		keystream_data[i * 4 + 2] = (v >> 16) & 0xff;
		keystream_data[i * 4 + 3] = (v >> 24) & 0xff;
	}

	SNOW5_FSM_update(instance);
	SNOW5_LFSR_update(instance);
}

void SNOW5_keyiv_setup(SNOW5* instance, uint8_t *key, uint8_t *initial_vector, int is_aead_mode)
{
	for (int i = 0; i < 8; i++)
	{
		instance->A[i] = MAKEU16(initial_vector[2 * i + 1], initial_vector[2 * i]);
		instance->A[i + 8] = MAKEU16(key[2 * i + 1], key[2 * i]);
		instance->B[i] = 0x0000;
		instance->B[i + 8] = MAKEU16(key[2 * i + 17], key[2 * i + 16]);
	}

	if(is_aead_mode == 1)
	{
		instance->B[0] = 0x6C41;
		instance->B[1] = 0x7865;
		instance->B[2] = 0x6B45;
		instance->B[3] = 0x2064;
		instance->B[4] = 0x694A;
		instance->B[5] = 0x676E;
		instance->B[6] = 0x6854;
		instance->B[7] = 0x6D6F;
	}

	for (int i = 0; i < 16; i++)
	{
		uint8_t keystream_data[16];
		SNOW5_keystream(instance, keystream_data);

		for (uint32_t j = 0; j < 8; j++)
			instance->A[j + 8] ^= MAKEU16(keystream_data[2 * j + 1], keystream_data[2 * j]);
		
		if (i == 14)
			for (uint32_t j = 0; j < 4; j++)
				instance->R1[j] ^= MAKEU32(MAKEU16(key[4 * j + 3], key[4 * j + 2]), MAKEU16(key[4 * j + 1], key[4 * j + 0]));
		
		if (i == 15)
			for (uint32_t j = 0; j < 4; j++)
				instance->R1[j] ^= MAKEU32(MAKEU16(key[4 * j + 19], key[4 * j + 18]), MAKEU16(key[4 * j + 17], key[4 * j + 16]));
	}
}

#undef MAKEU32
#undef MAKEU16
```

`mt19937_64bit.h`
```c
#define NN 312
#define MM 156
#define MATRIX_A 0xB5026F5AA96619E9ULL
#define UM 0xFFFFFFFF80000000ULL /* Most significant 33 bits */
#define LM 0x7FFFFFFFULL /* Least significant 31 bits */

typedef struct {
	unsigned long long mt[NN];
	int mti;
} MT19937_64;

void MT19937_64_initial(MT19937_64* mt19937, unsigned long long seed) {
	mt19937->mt[0] = seed;
	for (mt19937->mti=1; mt19937->mti<NN; mt19937->mti++)
		mt19937->mt[mt19937->mti] =  (6364136223846793005ULL * (mt19937->mt[mt19937->mti-1] ^ (mt19937->mt[mt19937->mti-1] >> 62)) + mt19937->mti);
}

unsigned long long MT19937_64_generate(MT19937_64* mt19937) {
	int i;
	unsigned long long x;
	static unsigned long long mag01[2]={0ULL, MATRIX_A};

	if (mt19937->mti >= NN) {

		if (mt19937->mti == NN+1)
			MT19937_64_initial(mt19937, 5489ULL);

		for (i=0;i<NN-MM;i++) {
			x = (mt19937->mt[i]&UM)|(mt19937->mt[i+1]&LM);
			mt19937->mt[i] = mt19937->mt[i+MM] ^ (x>>1) ^ mag01[(int)(x&1ULL)];
		}
		for (;i<NN-1;i++) {
			x = (mt19937->mt[i]&UM)|(mt19937->mt[i+1]&LM);
			mt19937->mt[i] = mt19937->mt[i+(MM-NN)] ^ (x>>1) ^ mag01[(int)(x&1ULL)];
		}
		x = (mt19937->mt[NN-1]&UM)|(mt19937->mt[0]&LM);
		mt19937->mt[NN-1] = mt19937->mt[MM-1] ^ (x>>1) ^ mag01[(int)(x&1ULL)];

		mt19937->mti = 0;
	}

	x = mt19937->mt[mt19937->mti++];

	x ^= (x >> 29) & 0x5555555555555555ULL;
	x ^= (x << 17) & 0x71D67FFFEDA60000ULL;
	x ^= (x << 37) & 0xFFF7EEE000000000ULL;
	x ^= (x >> 43);

	return x;
}

#undef NN
#undef MM
#undef MATRIX_A
#undef UM
#undef LM
```

`main.c`
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG Seed 1
	XCR CSPRNG Round counting from 0, accumulating 1 each time (0,1,2,3,4,5 .......) 
	CHACHA20 Key bytes all 0, Nonce bytes all 0, Counter 0

	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {
	XorConstantRotation XCR_Instance;

	XorConstantRotation_initial(&XCR_Instance, 1);
	uint64_t* buffer = (uint64_t*)malloc(125 * 1024); // 125 KB of uint64_t data
	if(buffer == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	for(uint64_t i = 0; i < 125 * 1024 / sizeof(uint64_t); ++i)
	{
		buffer[i] = XorConstantRotation_round(&XCR_Instance, i);
		
		//XOR Is not reset inner state (One-way-function mode)
	}

	FILE* file_XorConstantRotation = fopen("125KB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL)
	{
		printf("Could not open file_XorConstantRotation for writing.\n");
		free(buffer);
		return -2;
	}
	fwrite((uint8_t*)buffer, 125 * 1024, 1, file_XorConstantRotation);

	fclose(file_XorConstantRotation);
	free(buffer);

	uint8_t key[32] = { 0x00 };
	uint8_t nonce[12] = { 0x00 };
	uint32_t counter = 0;
	uint8_t* buffer2 = (uint8_t*)malloc(125 * 1024); // 125KB of uint8_t data
	if(buffer2 == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	ChaCha20 ChaCha20_Instance;

	chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);

	chacha20_encrypt(&ChaCha20_Instance, buffer2, buffer2, 125 * 1024);

	FILE *file_ChaCha20 = fopen("125KB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL)
	{
		printf("Could not open file_ChaCha20 for writing.\n");
		free(buffer2);
		return -2;
	}

	fwrite(buffer2, 125 * 1024, 1, file_ChaCha20);

	fclose(file_ChaCha20);
	free(buffer2);

	return 0;
}
```

`CSPRNG A vs B.py`
```python
import numpy as np
from nistrng import *
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

########################################

if __name__ == "__main__":

	#open and close form(xor csprng / chacha20) generated binary file with use c language
	xor_constant_rotation_file = open("125KB_XorConstantRotation_RandomBinaryFile.bin", "rb")
	chacha20_file = open("125KB_ChaCha20_RandomBinaryFile.bin", "rb")
	
	#Read the binary files as uint64 arrays
	xor_constant_rotation_samples = np.fromfile(xor_constant_rotation_file, dtype=np.uint64)
	chacha20_samples = np.fromfile(chacha20_file, dtype=np.uint64)

	#Close the files
	xor_constant_rotation_file.close()
	chacha20_file.close()

	# Convert samples to binary
	print("Packed as a binary array - Start")
	xor_constant_rotation_samples_binary = pack_sequence(np.array(xor_constant_rotation_samples, dtype=np.uint64))
	chacha20_samples_binary = pack_sequence(np.array(chacha20_samples, dtype=np.uint64))
	print("Packed as a binary array - End")

	# Check the eligibility of the test and generate an eligible battery from the default NIST-sp800-22r1a battery
	print("Check if the test conditions for the NIST random number test are met - Start")
	xor_eligible_battery = check_eligibility_all_battery(xor_constant_rotation_samples_binary, SP800_22R1A_BATTERY)
	chacha20_eligible_battery = check_eligibility_all_battery(chacha20_samples_binary, SP800_22R1A_BATTERY)
	print("Check if the test conditions for the NIST random number test are met - End")

	# Test the sequences on the eligible tests
	print("Testing begins.")
	xor_results = run_all_battery(xor_constant_rotation_samples_binary, xor_eligible_battery, False)
	chacha20_results = run_all_battery(chacha20_samples_binary, chacha20_eligible_battery, False)
	print("Testing ends.")

	print("Collect the data after the test and prepare the output graph.")
	
	# Get test names and scores
	test_names = [result.name for result, _ in xor_results]
	xor_scores = [result.score for result, _ in xor_results]
	chacha20_scores = [result.score for result, _ in chacha20_results]
	
	# Plot results
	fig, ax = plt.subplots(figsize=(12, 12))  # Define the figure and axes here

	x = np.arange(len(test_names))
	width = 0.35

	ax.set_title('NIST Test Scores')

	ax.set_ylabel('Score')
	# Set precision of Y-axis tick interval
	y_ticks = np.arange(0, max(max(xor_scores), max(chacha20_scores)) + 0.05, 0.05)
	ax.set_yticks(y_ticks)
	
	ax.set_xticks(x)
	ax.set_xticklabels([''] * len(test_names))

	colors = plt.cm.get_cmap('hsv', len(test_names))
	for i in x:
		ax.plot([i - width/2, i + width/2], [-0.05, -0.05], color=colors(i), marker='o', markersize=10, transform=ax.get_xaxis_transform(), clip_on=False)

	legend_elements_tests = [Line2D([0], [0], marker='o', color='w', markerfacecolor=colors(i), markersize=10, label=name) for i, name in enumerate(test_names)]
	legend2 = plt.legend(handles=legend_elements_tests, loc='lower left', bbox_to_anchor=(0, -0.7))
	ax.add_artist(legend2)

	#You can change label name
	legend_elements_algorithms = [Line2D([0], [0], color='blue', lw=4, label='XorConstantRotation (1000000 bits)'),
								  Line2D([0], [0], color='orange', lw=4, label='ChaCha20 (1000000 bits)')]
	ax.legend(handles=legend_elements_algorithms, loc='lower right', bbox_to_anchor=(1, -0.3))

	ax.bar(x - width/2, xor_scores, width, label='XorConstantRotation')
	ax.bar(x + width/2, chacha20_scores, width, label='ChaCha20')

	fig.tight_layout()
	plt.subplots_adjust(bottom=0.4)  # Adjust the bottom margin as per your requirement
	plt.show()

```

**NIST 800-22 Rev1 Test Results Data Figure 0 (Use the above code to generate)**
**NIST 800-22 Rev1 测试结果数据图表 0 (使用以上代码生成)**

![NIST Randomness Result (Binary Data 125KB).png](%5B%23XCR%20CSPRNG%20Seed%201%20%23CHACHA20%20Key%20all%200%2C%20Nonce%20all%200%2C%20Counter%200%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20125KB).png)

---

`main.c`
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG Seed is 1
	XCR CSPRNG Round counting from 0, accumulating 1 each time (0,1,2,3,4,5 .......) 
	CHACHA20 Key bytes all 0, Nonce bytes all 0, When each 1KB subkey is used, the count from zero accumulates 1 each time.

	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {
	XorConstantRotation XCR_Instance;

	XorConstantRotation_initial(&XCR_Instance, 1);
	uint64_t* buffer = (uint64_t*)malloc(125 * 1024); // 125 KB of uint64_t data
	if(buffer == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	for(uint64_t i = 0; i < 125 * 1024 / sizeof(uint64_t); ++i)
	{
		buffer[i] = XorConstantRotation_round(&XCR_Instance, i);
		
		//XOR Is not reset inner state (One-way-function mode)
	}

	FILE* file_XorConstantRotation = fopen("125KB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL)
	{
		printf("Could not open file_XorConstantRotation for writing.\n");
		free(buffer);
		return -2;
	}
	fwrite((uint8_t*)buffer, (size_t)125 * 1024, 1, file_XorConstantRotation);

	fclose(file_XorConstantRotation);
	free(buffer);

	uint8_t key[32] = { 0x00 };
	memset(&key, 0x00, 32);
	uint8_t nonce[12] = { 0x00 };
	memset(&nonce, 0x00, 12);
	uint32_t counter = 0;
	uint8_t *buffer2 = malloc(125 * 1024); // 1KB of uint8_t data
	if(buffer2 == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	ChaCha20 ChaCha20_Instance;
	uint8_t* buffer2_pointer = buffer2;
	for (size_t i = 0; i < 125; i++)
	{
		chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);
		chacha20_encrypt(&ChaCha20_Instance, buffer2_pointer, buffer2_pointer, 1024);
		counter++;
		buffer2_pointer += 1024;
	}

	FILE *file_ChaCha20 = fopen("125KB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL)
	{
		printf("Could not open file_ChaCha20 for writing.\n");
		free(buffer2);
		return -2;
	}

	fwrite((uint8_t*)buffer2, (size_t)125 * 1024, 1, file_ChaCha20);

	fclose(file_ChaCha20);
	free(buffer2);

	return 0;
}
```

`CSPRNG A vs B.py`
```python
import numpy as np
from nistrng import *
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

########################################

if __name__ == "__main__":

	#open and close form(xor csprng / chacha20) generated binary file with use c language
	xor_constant_rotation_file = open("125KB_XorConstantRotation_RandomBinaryFile.bin", "rb")
	chacha20_file = open("125KB_ChaCha20_RandomBinaryFile.bin", "rb")
	
	#Read the binary files as uint64 arrays
	xor_constant_rotation_samples = np.fromfile(xor_constant_rotation_file, dtype=np.uint64)
	chacha20_samples = np.fromfile(chacha20_file, dtype=np.uint64)

	#Close the files
	xor_constant_rotation_file.close()
	chacha20_file.close()

	#..... Same code as before

```

**NIST 800-22 Rev1 Test Results Data Figure 1 (Use the above code to generate)**
**NIST 800-22 Rev1 测试结果数据图表 1 (使用以上代码生成)**

![NIST Randomness Result (Binary Data 125KB).png](%5B%23XCR%20CSPRNG%20Seed%201%20%23CHACHA20%20Key%20all%200%2C%20Nonce%20all%200%2C%20Counter%20%2B%2B%20with%201KB%20subkey%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20125KB).png)

---

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG Seed is 1
	XCR CSPRNG Round counting from 0, accumulating 1 each time (0,1,2,3,4,5 .......) 
	CHACHA20 Key bytes all 1, Nonce bytes all 1, When each 1KB subkey is used, the count from zero accumulates 1 each time.

	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {
	XorConstantRotation XCR_Instance;

	XorConstantRotation_initial(&XCR_Instance, 1);
	uint64_t* buffer = (uint64_t*)malloc(125 * 1024); // 125 KB of uint64_t data
	if(buffer == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	for(uint64_t i = 0; i < 125 * 1024 / sizeof(uint64_t); ++i)
	{
		buffer[i] = XorConstantRotation_round(&XCR_Instance, i);
		
		//XOR Is not reset inner state (One-way-function mode)
	}

	FILE* file_XorConstantRotation = fopen("125KB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL)
	{
		printf("Could not open file_XorConstantRotation for writing.\n");
		free(buffer);
		return -2;
	}
	fwrite((uint8_t*)buffer, (size_t)125 * 1024, 1, file_XorConstantRotation);

	fclose(file_XorConstantRotation);
	free(buffer);

	uint8_t key[32] = { 0x00 };
	memset(&key, 0x01, 32);
	uint8_t nonce[12] = { 0x00 };
	memset(&nonce, 0x01, 12);
	uint32_t counter = 0;
	uint8_t *buffer2 = malloc(125 * 1024); // 1KB of uint8_t data
	if(buffer2 == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	ChaCha20 ChaCha20_Instance;
	uint8_t* buffer2_pointer = buffer2;
	for (size_t i = 0; i < 125; i++)
	{
		chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);
		chacha20_encrypt(&ChaCha20_Instance, buffer2_pointer, buffer2_pointer, 1024);
		counter++;
		buffer2_pointer += 1024;
	}

	FILE *file_ChaCha20 = fopen("125KB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL)
	{
		printf("Could not open file_ChaCha20 for writing.\n");
		free(buffer2);
		return -2;
	}

	fwrite((uint8_t*)buffer2, (size_t)125 * 1024, 1, file_ChaCha20);

	fclose(file_ChaCha20);
	free(buffer2);

	return 0;
}
```

Same `CSPRNG A vs B.py` before :

**NIST 800-22 Rev1 Test Results Data Figure 2 (Use the above code to generate)**
**NIST 800-22 Rev1测试结果数据图表 2 (使用以上代码生成)**

![NIST Randomness Result (Binary Data 125KB).png](%5B%23XCR%20CSPRNG%20Seed%201%20%23CHACHA20%20Key%20all%201%2C%20Nonce%20all%201%2C%20Counter%20%2B%2B%20with%201KB%20subkey%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20125KB).png)

---

`main.c`
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG Seed is 123456789
	XCR CSPRNG Round counting from 0, accumulating 1 each time (0,1,2,3,4,5 .......) 
	CHACHA20 Key bytes all 1, Nonce bytes all 1, When each 1KB subkey is used, the count from zero accumulates 1 each time.

	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {
	XorConstantRotation XCR_Instance;

	XorConstantRotation_initial(&XCR_Instance, 123456789);
	uint64_t* buffer = (uint64_t*)malloc(125 * 1024); // 125 KB of uint64_t data
	if(buffer == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	for(uint64_t i = 0; i < 125 * 1024 / sizeof(uint64_t); ++i)
	{
		buffer[i] = XorConstantRotation_round(&XCR_Instance, i);
		
		//XOR Is not reset inner state (One-way-function mode)
	}

	FILE* file_XorConstantRotation = fopen("125KB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL)
	{
		printf("Could not open file_XorConstantRotation for writing.\n");
		free(buffer);
		return -2;
	}
	fwrite((uint8_t*)buffer, (size_t)125 * 1024, 1, file_XorConstantRotation);

	fclose(file_XorConstantRotation);
	free(buffer);

	uint8_t key[32] = { 0x00 };
	memset(&key, 0x01, 32);
	uint8_t nonce[12] = { 0x00 };
	memset(&nonce, 0x01, 12);
	uint32_t counter = 0;
	uint8_t *buffer2 = malloc(125 * 1024); // 1KB of uint8_t data
	if(buffer2 == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	ChaCha20 ChaCha20_Instance;
	uint8_t* buffer2_pointer = buffer2;
	for (size_t i = 0; i < 125; i++)
	{
		chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);
		chacha20_encrypt(&ChaCha20_Instance, buffer2_pointer, buffer2_pointer, 1024);
		counter++;
		buffer2_pointer += 1024;
	}

	FILE *file_ChaCha20 = fopen("125KB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL)
	{
		printf("Could not open file_ChaCha20 for writing.\n");
		free(buffer2);
		return -2;
	}

	fwrite((uint8_t*)buffer2, (size_t)125 * 1024, 1, file_ChaCha20);

	fclose(file_ChaCha20);
	free(buffer2);

	return 0;
}
```

Same `CSPRNG A vs B.py` before :

**NIST 800-22 Rev1 Test Results Data Figure 3 (Use the above code to generate)**
**NIST 800-22 Rev1测试结果数据图表 3 (使用以上代码生成)**

![NIST Randomness Result (Binary Data 125KB).png](%5B%23XCR%20CSPRNG%20Seed%20123456789%20%23CHACHA20%20Key%20all%201%2C%20Nonce%20all%201%2C%20Counter%20%2B%2B%20with%201KB%20subkey%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20125KB).png)

---

`main.c`
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"
#include "mt19937_64bit.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG seed is 123456789
	XCR CSPRNG The value of round comes from the iteration using MT19937-64 PRNG(Seed 1)
	CHACHA20 Key bytes all 1, Nonce bytes all 1, When each 1KB subkey is used, the count from zero accumulates 1 each time.

	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {

	uint64_t* buffer = (uint64_t*)malloc(125 * 1024); // 125 KB of uint64_t data
	if(buffer == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	MT19937_64 MT19937_64_Instance;
	MT19937_64_initial(&MT19937_64_Instance, 1);
	XorConstantRotation XCR_Instance;
	XorConstantRotation_initial(&XCR_Instance, 123456789);

	for(uint64_t i = 0; i < 125 * 1024 / sizeof(uint64_t); ++i)
	{
		buffer[i] = XorConstantRotation_round(&XCR_Instance, MT19937_64_generate(&MT19937_64_Instance));
	}

	FILE* file_XorConstantRotation = fopen("125KB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL)
	{
		printf("Could not open file_XorConstantRotation for writing.\n");
		free(buffer);
		return -2;
	}

	fwrite((uint8_t*)buffer, (size_t)125 * 1024, 1, file_XorConstantRotation);

	fclose(file_XorConstantRotation);
	free(buffer);

	uint8_t key[32] = { 0x00 };
	memset(&key, 0x01, 32);
	uint8_t nonce[12] = { 0x00 };
	memset(&nonce, 0x01, 12);
	uint32_t counter = 0;
	uint8_t *buffer2 = malloc(125 * 1024); // 1KB of uint8_t data
	if(buffer2 == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	ChaCha20 ChaCha20_Instance;
	uint8_t* buffer2_pointer = buffer2;
	for (size_t i = 0; i < 125; i++)
	{
		chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);
		chacha20_encrypt(&ChaCha20_Instance, buffer2_pointer, buffer2_pointer, 1024);
		counter++;
		buffer2_pointer += 1024;
	}

	FILE *file_ChaCha20 = fopen("125KB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL)
	{
		printf("Could not open file_ChaCha20 for writing.\n");
		free(buffer2);
		return -2;
	}

	fwrite((uint8_t*)buffer2, (size_t)125 * 1024, 1, file_ChaCha20);

	fclose(file_ChaCha20);
	free(buffer2);

	return 0;
}
```

Same `CSPRNG A vs B.py` before:

**NIST 800-22 Rev1 Test Results Data Figure 4 (Use the above code to generate)**
**NIST 800-22 Rev1测试结果数据图表 4 (使用以上代码生成)**

![NIST Randomness Result (Binary Data 125KB).png](%5B%23XCR%20CSPRNG%20Seed%20123456789%2C%20iteration%20MT19937%2064Bit(Seed%201)%20%23CHACHA20%20Key%20all%201%2C%20Nonce%20all%201%2C%20Counter%20%2B%2B%20with%201KB%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20125KB).png)

---

`main.c`
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG Seed is 19734862582791643
	XCR CSPRNG Round counting from 0, accumulating 1 each time (0,1,2,3,4,5 .......) 
	CHACHA20 Key bytes all 1, Nonce bytes all 1, When each 1KB subkey is used, the count from zero accumulates 1 each time.

	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {
	XorConstantRotation XCR_Instance;

	XorConstantRotation_initial(&XCR_Instance, 19734862582791643);
	uint64_t* buffer = (uint64_t*)malloc(125 * 1024); // 125 KB of uint64_t data
	if(buffer == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	for(uint64_t i = 0; i < 125 * 1024 / sizeof(uint64_t); ++i)
	{
		buffer[i] = XorConstantRotation_round(&XCR_Instance, i);
		
		//XOR Is not reset inner state (One-way-function mode)
	}

	FILE* file_XorConstantRotation = fopen("125KB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL)
	{
		printf("Could not open file_XorConstantRotation for writing.\n");
		free(buffer);
		return -2;
	}
	fwrite((uint8_t*)buffer, (size_t)125 * 1024, 1, file_XorConstantRotation);

	fclose(file_XorConstantRotation);
	free(buffer);

	uint8_t key[32] = { 0x00 };
	memset(&key, 0x01, 32);
	uint8_t nonce[12] = { 0x00 };
	memset(&nonce, 0x01, 12);
	uint32_t counter = 0;
	uint8_t *buffer2 = malloc(125 * 1024); // 1KB of uint8_t data
	if(buffer2 == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	ChaCha20 ChaCha20_Instance;
	uint8_t* buffer2_pointer = buffer2;
	for (size_t i = 0; i < 125; i++)
	{
		chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);
		chacha20_encrypt(&ChaCha20_Instance, buffer2_pointer, buffer2_pointer, 1024);
		counter++;
		buffer2_pointer += 1024;
	}

	FILE *file_ChaCha20 = fopen("125KB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL)
	{
		printf("Could not open file_ChaCha20 for writing.\n");
		free(buffer2);
		return -2;
	}

	fwrite((uint8_t*)buffer2, (size_t)125 * 1024, 1, file_ChaCha20);

	fclose(file_ChaCha20);
	free(buffer2);

	return 0;
}
```

Same `CSPRNG A vs B.py` before :

**NIST 800-22 Rev1 Test Results Data Figure 5 (Use the above code to generate)**
**NIST 800-22 Rev1测试结果数据图表 5 (使用以上代码生成)**

![NIST Randomness Result (Binary Data 125KB).png](%5B%23XCR%20CSPRNG%20Seed%2019734862582791643%20%23CHACHA20%20Key%20all%201%2C%20Nonce%20all%201%2C%20Counter%20%2B%2B%20with%201KB%20subkey%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20125KB).png)

---

`main.c`
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"
#include "mt19937_64bit.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG Seed is 19734862582791643 (01000110000111001100000011000001111100000011110111011011) Hamming Weights is 26
	XCR CSPRNG discard 128 round(counting from 0, accumulating 1 each time (0,1,2,3,4,5 .......)) with value itetation
	XCR CSPRNG The value of round comes from the iteration using MT19937-64 PRNG(Seed 1) and use mix hash
	CHACHA20 Key bytes all 1, Nonce bytes all 1, When each 1KB subkey is used, the count from zero accumulates 1 each time.
	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {

	MT19937_64 MT19937_64_Instance;
	XorConstantRotation XCR_Instance;

	MT19937_64_initial(&MT19937_64_Instance, 1); // Recommend to use uint16_t seed (seed > (2 power 16) -1)
	
	XorConstantRotation_initial(&XCR_Instance, 19734862582791643); // Must be use uint64_t seed (seed > (2 power 32) -1)
	
	uint64_t value = MT19937_64_generate(&MT19937_64_Instance);
	for (size_t i = 0; i < 128; i++)
	{
		//discard 128 round with value iteration
		value = XorConstantRotation_round(&XCR_Instance, value);
	}

	uint64_t* buffer = (uint64_t*)malloc(125 * 1024); // 125 KB of uint64_t data
	if(buffer == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	uint64_t a = MT19937_64_generate(&MT19937_64_Instance);
	uint64_t b = MT19937_64_generate(&MT19937_64_Instance);
	for(uint64_t i = 0; i < 125 * 1024 / sizeof(uint64_t); ++i)
	{
		//Mix
		a ^= XorConstantRotation_round(&XCR_Instance, b);
		b += XorConstantRotation_round(&XCR_Instance, a);

		//Mix hash
		a ^= b;
		a = right_rotate(a, 43);
		a += b;
		b = right_rotate(b, 32);
		b ^= a;

		a = right_rotate(a, 48);
		a += b;
		b = right_rotate(b, 51);
		b ^= a;

		buffer[i] = b;
	}

	FILE* file_XorConstantRotation = fopen("125KB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL)
	{
		printf("Could not open file_XorConstantRotation for writing.\n");
		free(buffer);
		return -2;
	}
	fwrite((uint8_t*)buffer, (size_t)125 * 1024, 1, file_XorConstantRotation);

	fclose(file_XorConstantRotation);
	free(buffer);

	uint8_t key[32] = { 0x00 };
	memset(&key, 0x01, 32);
	uint8_t nonce[12] = { 0x00 };
	memset(&nonce, 0x01, 12);
	uint32_t counter = 0;
	uint8_t *buffer2 = malloc(125 * 1024); // 1KB of uint8_t data
	if(buffer2 == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	ChaCha20 ChaCha20_Instance;
	uint8_t* buffer2_pointer = buffer2;
	for (size_t i = 0; i < 125; i++)
	{
		chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);
		chacha20_encrypt(&ChaCha20_Instance, buffer2_pointer, buffer2_pointer, 1024);
		counter++;
		buffer2_pointer += 1024;
	}

	FILE *file_ChaCha20 = fopen("125KB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL)
	{
		printf("Could not open file_ChaCha20 for writing.\n");
		free(buffer2);
		return -2;
	}

	fwrite((uint8_t*)buffer2, (size_t)125 * 1024, 1, file_ChaCha20);

	fclose(file_ChaCha20);
	free(buffer2);

	return 0;
}
```

Same `CSPRNG A vs B.py` before:

**NIST 800-22 Rev1 Test Results Data Figure 6 (Use the above code to generate)**
**NIST 800-22 Rev1测试结果数据图表 6 (使用以上代码生成)**

![NIST Randomness Result (Binary Data 125KB).png](%5B%23XCR%20CSPRNG%20Seed%2019734862582791643%20discard%20128%20and%20mix%20hashed%20%23CHACHA20%20Key%20all%201%2C%20Nonce%20all%201%2C%20Counter%20%2B%2B%20with%201KB%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20125KB).png)

---

`main.c`
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"
#include "mt19937_64bit.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG A seed is 19734862582791643
	XCR CSPRNG B seed is generate by XCR CSPRNG A (round is 1)
	XCR CSPRNG A re-seed generate by XCR CSPRNG B (round is 1)
	XCR CSPRNG A,B round counting from 0, accumulating 1 each time

	CHACHA20 Key bytes all 1, Nonce bytes all 1, Counter accumulate 1 with use 1KB subkey

	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {

	uint64_t* buffer = (uint64_t*)malloc(125 * 1024); // 125 KB of uint64_t data
	if(buffer == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	XorConstantRotation XCR_Instance;
	XorConstantRotation XCR_Instance2;
	XorConstantRotation_initial(&XCR_Instance, 19734862582791643);
	XorConstantRotation_initial(&XCR_Instance2, XorConstantRotation_round(&XCR_Instance, 1));
	XorConstantRotation_initial(&XCR_Instance, XorConstantRotation_round(&XCR_Instance2, 1));

	uint64_t a = 0;
	uint64_t b = 0;
	for(uint64_t i = 0; i < 125 * 1024 / sizeof(uint64_t); ++i)
	{
		a = XorConstantRotation_round(&XCR_Instance2, XorConstantRotation_round(&XCR_Instance, i));
		b = XorConstantRotation_round(&XCR_Instance, XorConstantRotation_round(&XCR_Instance2, i));

		b ^= XorConstantRotation_round(&XCR_Instance, XorConstantRotation_round(&XCR_Instance2, a));
		a ^= XorConstantRotation_round(&XCR_Instance2, XorConstantRotation_round(&XCR_Instance, b));

		buffer[i] = b;
	}

	FILE* file_XorConstantRotation = fopen("125KB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL)
	{
		printf("Could not open file_XorConstantRotation for writing.\n");
		free(buffer);
		return -2;
	}

	fwrite((uint8_t*)buffer, (size_t)125 * 1024, 1, file_XorConstantRotation);

	fclose(file_XorConstantRotation);
	free(buffer);

	uint8_t key[32] = { 0x00 };
	memset(&key, 0x01, 32);
	uint8_t nonce[12] = { 0x00 };
	memset(&nonce, 0x01, 12);
	uint32_t counter = 0;
	uint8_t *buffer2 = malloc(125 * 1024); // 1KB of uint8_t data
	if(buffer2 == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	ChaCha20 ChaCha20_Instance;
	uint8_t* buffer2_pointer = buffer2;
	for (size_t i = 0; i < 125; i++)
	{
		chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);
		chacha20_encrypt(&ChaCha20_Instance, buffer2_pointer, buffer2_pointer, 1024);
		counter++;
		buffer2_pointer += 1024;
	}

	FILE *file_ChaCha20 = fopen("125KB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL)
	{
		printf("Could not open file_ChaCha20 for writing.\n");
		free(buffer2);
		return -2;
	}

	fwrite((uint8_t*)buffer2, (size_t)125 * 1024, 1, file_ChaCha20);

	fclose(file_ChaCha20);
	free(buffer2);

	return 0;
}
```
Same `CSPRNG A vs B.py` before:

**NIST 800-22 Rev1 Test Results Data Figure 7 (Use the above code to generate)**
**NIST 800-22 Rev1测试结果数据图表 7 (使用以上代码生成)**

![NIST Randomness Result (Binary Data 125KB).png](%5B%23XCR%20CSPRNG%20Seed%2019734862582791643%2C%20use%20double%20instance%20%2C%20%23CHACHA20%20Key%20all%201%2C%20Nonce%20all%201%2C%20Counter%20%2B%2B%20with%201KB%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20125KB).png)

---

`main.c`
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"
#include "snow5.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG Seed is 0x5555555555555555 (0101010101010101010101010101010101010101010101010101010101010101) Hamming Weights is 32
	XCR CSPRNG round value comes from Use SNOW-V 32 bit(Key bytes all 0x00, Initial Vector bytes all 0x00) for each time
	CHACHA20 Key bytes all 1, Nonce bytes all 1, When each 1KB subkey is used, the count from zero accumulates 1 each time.

	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {

	SNOW5 SNOW5_Instance;

	SNOW5_initialize_zero_key(&SNOW5_Instance);

	uint8_t snow5_key[32] = { 0x00 };
	memset(&snow5_key, 0x01, 32);
	uint8_t snow5_initial_vector[16] = { 0x00 };
	memset(&snow5_initial_vector, 0x01, 16);
	SNOW5_keyiv_setup(&SNOW5_Instance, snow5_key, snow5_initial_vector, 0);

	XorConstantRotation XCR_Instance;

	XorConstantRotation_initial(&XCR_Instance, 0x5555555555555555);
	uint64_t* buffer = (uint64_t*)malloc(125 * 1024); // 125 KB of uint64_t data
	if(buffer == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	uint8_t snow5_keystream_data[16] = {0x00};
	uint64_t round = 0;
	for(uint64_t i = 0; i < 125 * 1024 / sizeof(uint64_t); ++i)
	{
		buffer[i] = XorConstantRotation_round(&XCR_Instance, round);
		SNOW5_keystream(&SNOW5_Instance, snow5_keystream_data);
		memcpy(&round, &snow5_keystream_data, sizeof(uint64_t));
		
		//XOR Is not reset inner state (One-way-function mode)
	}

	FILE* file_XorConstantRotation = fopen("125KB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL)
	{
		printf("Could not open file_XorConstantRotation for writing.\n");
		free(buffer);
		return -2;
	}
	fwrite((uint8_t*)buffer, (size_t)125 * 1024, 1, file_XorConstantRotation);

	fclose(file_XorConstantRotation);
	free(buffer);

	uint8_t key[32] = { 0x00 };
	memset(&key, 0x01, 32);
	uint8_t nonce[12] = { 0x00 };
	memset(&nonce, 0x01, 12);
	uint32_t counter = 0;
	uint8_t *buffer2 = malloc(125 * 1024); // 1KB of uint8_t data
	if(buffer2 == NULL)
	{
		printf("Memory allocation failed!\n");
		return -1;
	}

	ChaCha20 ChaCha20_Instance;
	uint8_t* buffer2_pointer = buffer2;
	for (size_t i = 0; i < 125; i++)
	{
		chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);
		chacha20_encrypt(&ChaCha20_Instance, buffer2_pointer, buffer2_pointer, 1024);
		counter++;
		buffer2_pointer += 1024;
	}

	FILE *file_ChaCha20 = fopen("125KB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL)
	{
		printf("Could not open file_ChaCha20 for writing.\n");
		free(buffer2);
		return -2;
	}

	fwrite((uint8_t*)buffer2, (size_t)125 * 1024, 1, file_ChaCha20);

	fclose(file_ChaCha20);
	free(buffer2);

	return 0;
}
```

Same `CSPRNG A vs B.py` before :

**NIST 800-22 Rev1 Test Results Data Figure 8 (Use the above code to generate)**
**NIST 800-22 Rev1测试结果数据图表 8 (使用以上代码生成)**

![NIST Randomness Result (Binary Data 125KB).png](%5B%23XCR%20CSPRNG%20Seed%200x5555555555555555%20Round%20value%20use%20SNOW-V%2C%20%23CHACHA20%20Key%20all%201%2C%20Nonce%20all%201%2C%20Counter%20%2B%2B%20with%201KB%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20125KB).png)

---

`main.c`
```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CSPRNG_XorConstantRotation.h"
#include "chacha20.h"

/*
	CSPRNGs operating parameters:
	CSPRNGs 运行参数:

	XCR CSPRNG Seed 1
	XCR CSPRNG round counting from 0, accumulating 1 each time 
	CHACHA20 Key bytes all 0, Nonce bytes all 0, When each 64KB subkey is used, the count from zero accumulates 1 each time.
	Generate XorConstantRotation CPSRNG and Chacha20 binary files
	产生XorConstantRotation CPSRNG和Chacha20二进制文件
*/
int main() {
	FILE* file_XorConstantRotation = fopen("128MB_XorConstantRotation_RandomBinaryFile.bin", "wb+");
	if(file_XorConstantRotation == NULL){
		printf("Could not open file_XorConstantRotation for writing.\n");
		return 1;
	}

	XorConstantRotation XCR_Instance;
	XorConstantRotation_initial(&XCR_Instance, 1);
	//128MB is 1073741824 bits
	uint64_t iterations = 1073741824 / 64; // 128 MB of uint64_t data

	for(uint64_t integer = 0; integer < iterations; ++integer){
		uint64_t random = XorConstantRotation_round(&XCR_Instance, integer);
		fwrite(&random, sizeof(random), 1, file_XorConstantRotation);
	}

	fclose(file_XorConstantRotation);

	FILE *file_ChaCha20 = fopen("128MB_ChaCha20_RandomBinaryFile.bin", "wb+");
	if (file_ChaCha20 == NULL) {
		printf("Could not open file_ChaCha20 for writing.\n");
		return 1;
	}

	uint8_t key[32] = { 0x00 };
	memset(&key, 0x00, 32);
	uint8_t nonce[12] = { 0x00 };
	memset(&nonce, 0x00, 12);
	uint32_t counter = 0;
	uint8_t *buffer = malloc(64 * 1024); // 64KB of uint8_t data
	ChaCha20 ChaCha20_Instance;

	chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);

	//128MB is 134217728 bytes
	for (size_t i = 0; i < 134217728 / (64 * 1024); i++) {
		chacha20_encrypt(&ChaCha20_Instance, buffer, buffer, (64 * 1024));
		fwrite(buffer, 1, (64 * 1024), file_ChaCha20);
		counter++;
		chacha20_key_setup(&ChaCha20_Instance, key, nonce, counter);
	}

	fclose(file_ChaCha20);
	free(buffer);
	return 0;
}
```

#### 128MB binary file test takes about 12 hours to run!!!
#### 128MB 二进制文件测试 运行需要12小时左右！！！
`CSPRNG A vs B.py`
```python
import numpy as np
from nistrng import *
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

########################################

if __name__ == "__main__":

	#open and close form(xor csprng / chacha20) generated binary file with use c language
	xor_constant_rotation_file = open("128MB_XorConstantRotation_RandomBinaryFile.bin", "rb")
	chacha20_file = open("128MB_ChaCha20_RandomBinaryFile.bin", "rb")
	
	#Read the binary files as uint64 arrays
	xor_constant_rotation_samples = np.fromfile(xor_constant_rotation_file, dtype=np.uint64)
	chacha20_samples = np.fromfile(chacha20_file, dtype=np.uint64)

	#Close the files
	xor_constant_rotation_file.close()
	chacha20_file.close()

	#..... Same code as before

```

**NIST 800-22 Rev1 Extended Test Results Data Figure (Use the above code to generate)**
**NIST 800-22 Rev1 扩展测试结果数据图表 (使用以上代码生成)**

![NIST NIST 800-22 Rev1 Randomness Result (Binary Data 128MB).png](%5B%23XCR%20CSPRNG%20Seed%201%20%23CHACHA20%20Key%20all%200%2C%20Nonce%20all%200%2C%20Counter%20%2B%2B%20with%2064KB%20subkey%5D%20NIST%20Randomness%20Result%20(Binary%20Data%20128MB).png)

---