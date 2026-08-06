#ifndef MIEL_NATIVE_SHA256_H
#define MIEL_NATIVE_SHA256_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct MielSha256Context {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char block[64];
    size_t block_used;
} MielSha256Context;

static uint32_t miel_sha256_rotate_right(uint32_t value, uint32_t count)
{
    return (value >> count) | (value << (32u - count));
}

static uint32_t miel_sha256_load_be32(const unsigned char *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void miel_sha256_store_be32(unsigned char *bytes, uint32_t value)
{
    bytes[0] = (unsigned char)(value >> 24);
    bytes[1] = (unsigned char)(value >> 16);
    bytes[2] = (unsigned char)(value >> 8);
    bytes[3] = (unsigned char)value;
}

static void miel_sha256_transform(
    MielSha256Context *context, const unsigned char block[64]
)
{
    static const uint32_t constants[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h, index;
    for (index = 0u; index < 16u; ++index)
        words[index] = miel_sha256_load_be32(block + index * 4u);
    for (index = 16u; index < 64u; ++index) {
        uint32_t s0 = miel_sha256_rotate_right(words[index - 15u], 7u) ^
                      miel_sha256_rotate_right(words[index - 15u], 18u) ^
                      (words[index - 15u] >> 3);
        uint32_t s1 = miel_sha256_rotate_right(words[index - 2u], 17u) ^
                      miel_sha256_rotate_right(words[index - 2u], 19u) ^
                      (words[index - 2u] >> 10);
        words[index] = words[index - 16u] + s0 + words[index - 7u] + s1;
    }
    a = context->state[0]; b = context->state[1];
    c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5];
    g = context->state[6]; h = context->state[7];
    for (index = 0u; index < 64u; ++index) {
        uint32_t sum1 = miel_sha256_rotate_right(e, 6u) ^
                        miel_sha256_rotate_right(e, 11u) ^
                        miel_sha256_rotate_right(e, 25u);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + sum1 + choice + constants[index] + words[index];
        uint32_t sum0 = miel_sha256_rotate_right(a, 2u) ^
                        miel_sha256_rotate_right(a, 13u) ^
                        miel_sha256_rotate_right(a, 22u);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = sum0 + majority;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
}

static void miel_sha256_init(MielSha256Context *context)
{
    static const uint32_t initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };
    memcpy(context->state, initial, sizeof(initial));
    context->bit_count = 0u;
    context->block_used = 0u;
}

static void miel_sha256_update(
    MielSha256Context *context, const unsigned char *bytes, size_t size
)
{
    context->bit_count += (uint64_t)size * 8u;
    while (size != 0u) {
        size_t available = 64u - context->block_used;
        size_t take = size < available ? size : available;
        memcpy(context->block + context->block_used, bytes, take);
        context->block_used += take;
        bytes += take;
        size -= take;
        if (context->block_used == 64u) {
            miel_sha256_transform(context, context->block);
            context->block_used = 0u;
        }
    }
}

static void miel_sha256_final(
    MielSha256Context *context, unsigned char digest[32]
)
{
    unsigned char padding[72] = {0x80};
    unsigned char length_bytes[8];
    uint64_t bits = context->bit_count;
    size_t pad_size = context->block_used < 56u ?
        56u - context->block_used : 120u - context->block_used;
    uint32_t index;
    for (index = 0u; index < 8u; ++index)
        length_bytes[7u - index] = (unsigned char)(bits >> (index * 8u));
    miel_sha256_update(context, padding, pad_size);
    miel_sha256_update(context, length_bytes, sizeof(length_bytes));
    for (index = 0u; index < 8u; ++index)
        miel_sha256_store_be32(digest + index * 4u, context->state[index]);
}

static int miel_sha256_file(const char *path, char output[65])
{
    static const char digits[] = "0123456789abcdef";
    unsigned char buffer[16384], digest[32];
    MielSha256Context context;
    FILE *stream = fopen(path, "rb");
    size_t count;
    uint32_t index;
    if (stream == NULL) return 0;
    miel_sha256_init(&context);
    while ((count = fread(buffer, 1u, sizeof(buffer), stream)) != 0u)
        miel_sha256_update(&context, buffer, count);
    if (ferror(stream) || fclose(stream) != 0) return 0;
    miel_sha256_final(&context, digest);
    for (index = 0u; index < 32u; ++index) {
        output[index * 2u] = digits[digest[index] >> 4];
        output[index * 2u + 1u] = digits[digest[index] & 15u];
    }
    output[64] = '\0';
    return 1;
}

#endif
