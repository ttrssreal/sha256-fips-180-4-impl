/*
SHA-256 from the Secure Hash Standard implemented in c.
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "main.h"

// Sec. 3.1 specifies big-endian
// and my CPU is little endian
#define SWAP_BYTE_ORDER_64(x)                                                                      \
    (x & 0xFF00000000000000) >> 8 * 7 | (x & 0x00FF000000000000) >> 8 * 5 |                        \
        (x & 0x0000FF0000000000) >> 8 * 3 | (x & 0x000000FF00000000) >> 8 * 1 |                    \
        (x & 0x00000000FF000000) << 8 * 1 | (x & 0x0000000000FF0000) << 8 * 3 |                    \
        (x & 0x000000000000FF00) << 8 * 5 | (x & 0x00000000000000FF) << 8 * 7

#define SWAP_BYTE_ORDER_32(x)                                                                      \
    (x & 0x00FF0000) >> 8 * 1 | (x & 0xFF000000) >> 8 * 3 | (x & 0x0000FF00) << 8 * 1 |            \
        (x & 0x000000FF) << 8 * 3

// Sec. 4.2.4
/*
The SHA256 constants are made up of 64, 32-bit words.
For good randomness they are calculated by using "the first thirty-two bits of the fractional
parts of the cube roots of the first sixty-four prime numbers" damm. NSA backdoor?? :)
*/
const uint32_t sha256constants[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    // Open the file in binary mode
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        printf("Error opening the file.\n");
        return 1;
    }

    //Gets the file size by seeking to the end of the file and then rewinding
    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    rewind(file);

    uint8_t* buffer = malloc(fileSize);
    fread(buffer, fileSize, 1, file);
    fclose(file);

    print_digest(sha256hash(buffer, fileSize));
}

uint32_t* sha256hash(uint8_t* rawM, uint64_t size) {
    // Sec. 5.1.1
    // Pad message to a multiple of 512 bits
    uint64_t l = size * 8;

    int k = ((448 - 1 - l) % 512 + 512) % 512;

    uint64_t N = (l + 1 + k + 64) / 512;
    uint8_t* M = malloc((l + 1 + k + 64) / 8);

    memcpy(M, rawM, size);
    *(M + l / 8) = 0x1 << 0x7;

    // 10101010 1'0000000' = 7, '000...' = k-7
    memset(M + l / 8 + 1, 0, (k - 7) / 8);
    *((uint64_t*)(M + l / 8 + 1 + (k - 7) / 8)) = SWAP_BYTE_ORDER_64(l);

    uint32_t* H = (uint32_t*)malloc(8 * 4);
    uint32_t* W = (uint32_t*)malloc(64 * 4);

    // Sec. 6.2 working variables
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;

    // Sec. 5.3.3/6.2.1 Set initial 256 bit hash value H0
    H[0] = 0x6a09e667;
    H[1] = 0xbb67ae85;
    H[2] = 0x3c6ef372;
    H[3] = 0xa54ff53a;
    H[4] = 0x510e527f;
    H[5] = 0x9b05688c;
    H[6] = 0x1f83d9ab;
    H[7] = 0x5be0cd19;

    const uint32_t* K = sha256constants;

    for (int i = 1; i <= N; i++) {
        // Sec. 6.2.2
        // Step 1. Prepare the message schedule
        for (int t = 0; t <= 64; t++) {
            if (t < 16) {
                W[t] = SWAP_BYTE_ORDER_32( ( (uint32_t*)(M + (i-1) * 64) )[t] );
            } else {
                W[t] = sigma1(W[t - 2]) + W[t - 7] +
                       sigma0(W[t - 15]) + W[t - 16];
            }
        }

        // Step 2.
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        // Step 3.
        for (int t = 0; t < 64; t++)
        {
            T1 = h + cap_sigma1(e) + Ch(e, f, g) + K[t] + W[t];
            T2 = cap_sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Step 4.
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    free(M);
    free(W);

    return H;
}

void usage(char* run) {
    printf("Usage:\n");
    printf("%s <file>\n", run);
    return;
}

void print_digest(uint32_t* digest) {
    // Swap endian for display
    for (int i = 0; i < 8; i++) {
            digest[i] = SWAP_BYTE_ORDER_32(digest[i]);
    }
    for (int i = 0; i < 32; i++) {
        printf("%02x", ((unsigned char*)digest)[i]);
    }
    printf("\n");
    return;
}

// Sec. 3.2 "This operation is used only in the SHA-1 algorithm." in reference to ROTL
static inline uint32_t ROTR(uint32_t x, int n) { return (x >> n) ^ (x << (32 - n)); }

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t cap_sigma0(uint32_t x) { return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22); }
static inline uint32_t cap_sigma1(uint32_t x) { return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25); }
static inline uint32_t sigma0(uint32_t x) { return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3); }
static inline uint32_t sigma1(uint32_t x) { return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10); }
