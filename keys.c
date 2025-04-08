#include "keys.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "util.h"
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <gmp.h>

int initializeKey(dhKey *key)
{
    assert(key);
    mpz_init(key->PK);
    mpz_init(key->SK);
    strncpy(key->name, "default", MAX_NAME);
    return 0;
}

int destroyKey(dhKey *key)
{
    assert(key);
    size_t limbs = mpz_size(key->SK);
    memset(mpz_limbs_write(key->SK, limbs), 0, limbs * sizeof(mp_limb_t));
    mpz_clear(key->SK);
    limbs = mpz_size(key->PK);
    memset(mpz_limbs_write(key->PK, limbs), 0, limbs * sizeof(mp_limb_t));
    mpz_clear(key->PK);
    memset(key->name, 0, MAX_NAME);
    return 0;
}

int saveDHKey(char *filename, dhKey *key)
{
    assert(key);
    if (strnlen(filename, PATH_MAX) > PATH_MAX - 4)
    {
        fprintf(stderr, "Filename too long for saving public/private keys.\n");
        return -2;
    }

    char publicKeyFilename[PATH_MAX + 1];
    strncpy(publicKeyFilename, filename, PATH_MAX);
    strncat(publicKeyFilename, ".pub", PATH_MAX);

    int fd;
    FILE *file;
    if (mpz_cmp_ui(key->SK, 0))
    {
        fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0600);
        file = fdopen(fd, "wb");
        if (!file)
            return -1;
        fprintf(file, "name:%s\n", key->name);
        gmp_fprintf(file, "PK:%Zd\n", key->PK);
        gmp_fprintf(file, "SK:%Zd\n", key->SK);
        fclose(file);
    }

    file = fopen(publicKeyFilename, "wb");
    if (!file)
        return -1;
    fprintf(file, "name:%s\n", key->name);
    gmp_fprintf(file, "PK:%Zd\n", key->PK);
    fprintf(file, "SK:0\n");
    fclose(file);
    return 0;
}

int loadDHKey(char *filename, dhKey *key)
{
    assert(key);
    initializeKey(key);
    FILE *file = fopen(filename, "rb");
    if (!file)
        return -1;
    int result = 0;
    char *name;
    if (fscanf(file, "name:%ms\n", &name) != 1)
    {
        result = -2;
        goto end;
    }
    strncpy(key->name, name, MAX_NAME);
    key->name[MAX_NAME] = 0;
    free(name);

    if (gmp_fscanf(file, "PK:%Zd\n", key->PK) != 1)
    {
        result = -2;
        goto end;
    }
    if (gmp_fscanf(file, "SK:%Zd\n", key->SK) != 1)
    {
        result = -2;
        goto end;
    }
end:
    fclose(file);
    return result;
}

char *computePKHash(dhKey *key, char *hash)
{
    assert(key);
    const size_t hashLength = 32;
    unsigned char hashed[hashLength];
    size_t bufferLength;
    unsigned char *buffer = Z2BYTES(NULL, &bufferLength, key->PK);
    SHA256(buffer, bufferLength, hashed);
    if (!hash)
        hash = malloc(2 * hashLength);
    for (size_t i = 0; i < 2 * hashLength; i++)
    {
        hash[i] = "0123456789abcdef"[(hashed[i / 2] << 4 * (i % 2)) & 0xf0 >> 4];
    }
    return hash;
}

// RSA Key loading
RSA *loadRSAPrivateKey(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        fprintf(stderr, "Failed to open private key file: %s\n", filename);
        return NULL;
    }
    RSA *rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    return rsa;
}

RSA *loadRSAPublicKey(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        fprintf(stderr, "Failed to open public key file: %s\n", filename);
        return NULL;
    }
    RSA *rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    return rsa;
}
