#include "util.h"
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#else
#include <endian.h>
#endif

#define MPZ_MAX_LEN 1024

void readFully(int fd, void *buf, size_t numBytes)
{
    do
    {
        ssize_t n = read(fd, buf, numBytes);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && errno == EWOULDBLOCK)
            continue;
        if (n < 0)
            perror("read"), abort();
        buf = (char *)buf + n;
        numBytes -= n;
    } while (numBytes);
}

void writeFully(int fd, const void *buf, size_t numBytes)
{
    do
    {
        ssize_t n = write(fd, buf, numBytes);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && errno == EWOULDBLOCK)
            continue;
        if (n < 0)
            perror("write"), abort();
        buf = (const char *)buf + n;
        numBytes -= n;
    } while (numBytes);
}

size_t serializeLargeInt(int fd, mpz_t x)
{
    size_t numBytes;
    unsigned char *buffer = Z2BYTES(NULL, &numBytes, x);
    if (!buffer)
    {
        numBytes = 1;
        buffer = malloc(1);
        *buffer = 0;
    }
    LE(numBytes);
    writeFully(fd, &numBytes_le, 4);
    writeFully(fd, buffer, numBytes);
    free(buffer);
    return numBytes + 4;
}

int deserializeLargeInt(mpz_t x, int fd)
{
    uint32_t numBytes_le;
    readFully(fd, &numBytes_le, 4);
    size_t numBytes = le32toh(numBytes_le);
    if (numBytes > MPZ_MAX_LEN)
        return -1;
    unsigned char *buffer = malloc(numBytes);
    readFully(fd, buffer, numBytes);
    BYTES2Z(x, buffer, numBytes);
    free(buffer);
    return 0;
}

void generateRSAKeyPair(const char *privateKeyFilename, const char *publicKeyFilename)
{
    RSA *rsa = NULL;
    BIGNUM *bignum = BN_new();
    BN_set_word(bignum, RSA_F4);
    rsa = RSA_new();
    RSA_generate_key_ex(rsa, 4096, bignum, NULL);

    FILE *privateKeyFile = fopen(privateKeyFilename, "wb");
    if (!privateKeyFile)
    {
        perror("Unable to open file for writing private key");
        RSA_free(rsa);
        BN_free(bignum);
        return;
    }
    PEM_write_RSAPrivateKey(privateKeyFile, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(privateKeyFile);

    FILE *publicKeyFile = fopen(publicKeyFilename, "wb");
    if (!publicKeyFile)
    {
        perror("Unable to open file for writing public key");
        RSA_free(rsa);
        BN_free(bignum);
        return;
    }
    PEM_write_RSA_PUBKEY(publicKeyFile, rsa);
    fclose(publicKeyFile);

    RSA_free(rsa);
    BN_free(bignum);
}