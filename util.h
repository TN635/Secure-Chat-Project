#pragma once
#include <gmp.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#else
// For non-macOS platforms (Linux), include the appropriate header
#include <endian.h>
#endif

// util.h
#ifdef __APPLE__
#define LE(x) uint32_t x##_le = htole32((uint32_t)x);
#else
#define LE(x) uint32_t x##_le = htole32((uint32_t)x);
#endif

/* convenience macros */
#define ISPRIME(x) mpz_probab_prime_p(x, 10)
#define NEWZ(x) \
    mpz_t x;    \
    mpz_init(x)
/* these will read/write integers from byte arrays where the
 * least significant byte is first (little endian bytewise). */
#define BYTES2Z(x, buf, len) mpz_import(x, len, -1, 1, 0, 0, buf)
#define Z2BYTES(buf, len, x) mpz_export(buf, len, -1, 1, 0, 0, x)
#define LE(x) uint32_t x##_le = htole32((uint32_t)x);

/* utility functions */

/** write an mpz_t as an unambiguous sequence of bytes.
 * @param fd is the file descriptor to write to.  Must be opened for writing.
 * @param x is the integer to serialize and write.
 * @return total number of bytes written, or 0 to indicate failure.
 * */
size_t serialize_mpz(int fd, mpz_t x);

/** inverse operation of serialize_mpz
 * @param x will be set to the integer serialized into buf.  NOTE: x must
 * already be initialized (with mpz_init(...) / NEWZ(...)
 * @param fd is the file descriptor from which to read serialized x
 * @return 0 for success */
int deserialize_mpz(mpz_t x, int fd);

/** Like read(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xread(int fd, void *buf, size_t nBytes);

/** Like write(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xwrite(int fd, const void *buf, size_t nBytes);

void generate_rsa_keys(const char *private_filename, const char *public_filename);