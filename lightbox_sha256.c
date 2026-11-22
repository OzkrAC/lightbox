#include "lightbox.h"

/*
 * SHA-256, as FIPS 180-4 has it (ROADMAP I.1). A blob of an image is named
 * by its digest, and a blob is held to that name before it is used.
 *
 * The input comes in pieces of any length: a layer is hashed while it is
 * written or read, and is never in memory whole.
 */

/* the first 32 bits of the fractional parts of the cube roots of the first
 * 64 primes (FIPS 180-4, 4.2.2) */
static const uint32_t ROUND[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

/* one block of 64 bytes into the state (FIPS 180-4, 6.2.2) */
static void sha256_block(uint32_t state[8], const uint8_t block[SHA256_BLOCK]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)block[4 * i] << 24 | (uint32_t)block[4 * i + 1] << 16 |
               (uint32_t)block[4 * i + 2] << 8 | (uint32_t)block[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + ROUND[i] + w[i];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_init(sha256_ctx *ctx) {
    /* the first 32 bits of the fractional parts of the square roots of the
     * first 8 primes (FIPS 180-4, 5.3.3) */
    static const uint32_t start[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    lc_bytes_copy(ctx->state, start, sizeof(start));
    ctx->length = 0;
}

void sha256_update(sha256_ctx *ctx, const void *data, size_t len) {
    const uint8_t *in = data;
    size_t held = (size_t)(ctx->length % SHA256_BLOCK);
    ctx->length += len;

    /* fill the block that was begun, then whole blocks straight from the
     * input, and keep what is left for the next call */
    if (held) {
        size_t room = SHA256_BLOCK - held;
        size_t take = len < room ? len : room;
        lc_bytes_copy(ctx->block + held, in, take);
        in += take;
        len -= take;
        if (held + take < SHA256_BLOCK)
            return;
        sha256_block(ctx->state, ctx->block);
    }
    for (; len >= SHA256_BLOCK; in += SHA256_BLOCK, len -= SHA256_BLOCK)
        sha256_block(ctx->state, in);
    if (len)
        lc_bytes_copy(ctx->block, in, len);
}

void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_BYTES]) {
    /* a 1 bit, zeros up to 8 bytes before a block's end, and the length of
     * the message in bits, big-endian (FIPS 180-4, 5.1.1) */
    uint64_t bits = ctx->length * 8;
    size_t held = (size_t)(ctx->length % SHA256_BLOCK);
    ctx->block[held++] = 0x80;
    if (held > SHA256_BLOCK - 8) {
        lc_bytes_fill(ctx->block + held, 0, SHA256_BLOCK - held);
        sha256_block(ctx->state, ctx->block);
        held = 0;
    }
    lc_bytes_fill(ctx->block + held, 0, SHA256_BLOCK - 8 - held);
    for (int i = 0; i < 8; i++)
        ctx->block[SHA256_BLOCK - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha256_block(ctx->state, ctx->block);

    for (int i = 0; i < 8; i++) {
        digest[4 * i] = (uint8_t)(ctx->state[i] >> 24);
        digest[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[4 * i + 3] = (uint8_t)ctx->state[i];
    }
    /* spent: a second final would give another digest, not this one again */
    lc_bytes_fill(ctx, 0, sizeof(*ctx));
}

void sha256_hex(const uint8_t digest[SHA256_BYTES], char out[SHA256_HEX + 1]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < SHA256_BYTES; i++) {
        out[2 * i] = hex[digest[i] >> 4];
        out[2 * i + 1] = hex[digest[i] & 0xf];
    }
    out[SHA256_HEX] = '\0';
}

bool sha256_hex_ok(const char *text) {
    size_t len = lc_string_length(text);
    if (len != SHA256_HEX)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}
