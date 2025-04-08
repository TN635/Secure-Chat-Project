/* Diffie Hellman key exchange, and HKDF for key derivation. */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "dh.h"
#include <string.h>
#include <assert.h>
#include "util.h"

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#include <machine/endian.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#elif defined(__linux__)
#include <endian.h>
#endif

mpz_t smallPrime; /* "small" prime; should be 256 bits or more */
mpz_t largePrime; /* "large" prime; should be 2048 bits or more, with smallPrime|(largePrime-1) */
mpz_t generator; /* generator of the subgroup of order smallPrime */
/* length of smallPrime and largePrime in bits and bytes (for convenience) */
size_t smallPrimeBitlen;
size_t largePrimeBitlen;
size_t smallPrimeLen; /* length of smallPrime in bytes */
size_t largePrimeLen; /* length of largePrime in bytes */

const char *hmacSalt = "z3Dow}^Z]8Uu5>pr#;{QUs!133";

int initializeDHParams(const char *filename)
{
    mpz_init(smallPrime);
    mpz_init(largePrime);
    mpz_init(generator);
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        fprintf(stderr, "Could not open file 'params'\n");
        return -1;
    }
    int valuesRead = gmp_fscanf(file, "smallPrime = %Zd\nlargePrime = %Zd\ngenerator = %Zd", smallPrime, largePrime, generator);
    fclose(file);
    if (valuesRead != 3)
    {
        printf("Couldn't parse parameter file\n");
        return -1;
    }

    if (!ISPRIME(smallPrime))
    {
        printf("smallPrime not prime!\n");
        return -1;
    }
    if (!ISPRIME(largePrime))
    {
        printf("largePrime not prime!\n");
        return -1;
    }
    mpz_sub_ui(smallPrime, largePrime, 1); 
    if (!mpz_divisible_p(smallPrime, largePrime))
    {
        printf("smallPrime does not divide (largePrime-1)!\n");
        return -1;
    }
    mpz_divexact(generator, largePrime, smallPrime); 
    smallPrimeBitlen = mpz_sizeinbase(smallPrime, 2);
    largePrimeBitlen = mpz_sizeinbase(largePrime, 2);
    smallPrimeLen = smallPrimeBitlen / 8 + (smallPrimeBitlen % 8 != 0);
    largePrimeLen = largePrimeBitlen / 8 + (largePrimeBitlen % 8 != 0);
    return 0;
}

int generateDHKey(mpz_t secretKey, mpz_t publicKey)
{
    FILE *file = fopen("/dev/urandom", "rb");
    if (!file)
    {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        return -1;
    }
    size_t bufferLen = smallPrimeLen + 32; 
    unsigned char *buffer = malloc(bufferLen);
    fread(buffer, 1, bufferLen, file);
    fclose(file);
    mpz_t randomKey;
    mpz_init(randomKey);
    BYTES2Z(randomKey, buffer, bufferLen);
    mpz_mod(secretKey, randomKey, smallPrime);
    mpz_powm(publicKey, generator, secretKey, largePrime);
    return 0;
}

int completeDHExchange(mpz_t secretKeyLocal, mpz_t publicKeyLocal, mpz_t publicKeyRemote, unsigned char *keyBuffer, size_t bufferLen)
{
    mpz_t sharedSecret;
    mpz_init(sharedSecret);
    mpz_powm(sharedSecret, publicKeyRemote, secretKeyLocal, largePrime);
    
    unsigned char *sharedKey = malloc(largePrimeLen);
    memset(sharedKey, 0, largePrimeLen);
    size_t bytesWritten;
    Z2BYTES(sharedKey, &bytesWritten, sharedSecret);
    unsigned char prk[64];
    memset(prk, 0, 64);
    HMAC(EVP_sha512(), hmacSalt, strlen(hmacSalt), sharedKey, bytesWritten, prk, NULL);

    unsigned char contextBuffer[largePrimeLen + 64 + 8];
    memcpy(contextBuffer, prk, 64);
    memcpy(contextBuffer + 64, sharedKey, largePrimeLen);
    memcpy(contextBuffer + 64 + largePrimeLen, &bufferLen, sizeof(bufferLen));
    HMAC(EVP_sha512(), prk, 64, contextBuffer, sizeof(contextBuffer), keyBuffer, NULL);
    
    return 0;
}