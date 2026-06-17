/*
 * Fast Kuznyechik (GOST R 34.12-2015) - correct implementation
 * Byte ordering: x[0] is the leftmost (most significant) byte, matching the GOST spec.
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static const uint8_t PI[256] = {
    252,238,221, 17,207,110, 49, 22,251,196,250,218, 35,197,  4, 77,
    233,119,240,219,147, 46,153,186, 23, 54,241,187, 20,205, 95,193,
    249, 24,101, 90,226, 92,239, 33,129, 28, 60, 66,139,  1,142, 79,
      5,132,  2,174,227,106,143,160,  6, 11,237,152,127,212,211, 31,
    235, 52, 44, 81,234,200, 72,171,242, 42,104,162,253, 58,206,204,
    181,112, 14, 86,  8, 12,118, 18,191,114, 19, 71,156,183, 93,135,
     21,161,150, 41, 16,123,154,199,243,145,120,111,157,158,178,177,
     50,117, 25, 61,255, 53,138,126,109, 84,198,128,195,189, 13, 87,
    223,245, 36,169, 62,168, 67,201,215,121,214,246,124, 34,185,  3,
    224, 15,236,222,122,148,176,188,220,232, 40, 80, 78, 51, 10, 74,
    167,151, 96,115, 30,  0, 98, 68, 26,184, 56,130,100,159, 38, 65,
    173, 69, 70,146, 39, 94, 85, 47,140,163,165,125,105,213,149, 59,
      7, 88,179, 64,134,172, 29,247, 48, 55,107,228,136,217,231,137,
    225, 27,131, 73, 76, 63,248,254,141, 83,170,144,202,216,133, 97,
     32,113,103,164, 45, 43,  9, 91,203,155, 37,208,190,229,108, 82,
     89,166,116,210,230,244,180,192,209,102,175,194, 57, 75, 99,182
};

static const uint8_t PI_INV[256] = {
    165, 45, 50,143, 14, 48, 56,192, 84,230,158, 57, 85,126, 82,145,
    100,  3, 87, 90, 28, 96,  7, 24, 33,114,168,209, 41,198,164, 63,
    224, 39,141, 12,130,234,174,180,154, 99, 73,229, 66,228, 21,183,
    200,  6,112,157, 65,117, 25,201,170,252, 77,191, 42,115,132,213,
    195,175, 43,134,167,177,178, 91, 70,211,159,253,212, 15,156, 47,
    155, 67,239,217,121,182, 83,127,193,240, 35,231, 37, 94,181, 30,
    162,223,166,254,172, 34,249,226, 74,188, 53,202,238,120,  5,107,
     81,225, 89,163,242,113, 86, 17,106,137,148,101,140,187,119, 60,
    123, 40,171,210, 49,222,196, 95,204,207,118, 44,184,216, 46, 54,
    219,105,179, 20,149,190, 98,161, 59, 22,102,233, 92,108,109,173,
     55, 97, 75,185,227,186,241,160,133,131,218, 71,197,176, 51,250,
    150,111,110,194,246, 80,255, 93,169,142, 23, 27,151,125,236, 88,
    247, 31,251,124,  9, 13,122,103, 69,135,220,232, 79, 29, 78,  4,
    235,248,243, 62, 61,189,138,136,221,205, 11, 19,152,  2,147,128,
    144,208, 36, 52,203,237,244,206,153, 16, 68, 64,146, 58,  1, 38,
     18, 26, 72,104,245,129,139,199,214, 32, 10,  8,  0, 76,215,116
};

/* GF(2^8) multiply mod p(x) = x^8 + x^7 + x^6 + x + 1 = 0x1C3.
 * The R/L transforms call this in the innermost loop, so the public cipher
 * path uses a 64 KiB lookup table initialized once at library load time.
 */
static uint8_t GF_MUL_TABLE[256][256];
static int GF_MUL_TABLE_READY = 0;

static uint8_t gf_mul_slow(uint8_t a, uint8_t b) {
    uint8_t c = 0;
    while (b) {
        if (b & 1) c ^= a;
        /* multiply a by x; reduce if degree 8 bit set */
        a = (a & 0x80) ? (uint8_t)((a << 1) ^ 0xC3) : (uint8_t)(a << 1);
        b >>= 1;
    }
    return c;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((constructor))
#endif
static void init_gf_mul_table(void) {
    if (GF_MUL_TABLE_READY) return;
    for (int a = 0; a < 256; a++)
        for (int b = 0; b < 256; b++)
            GF_MUL_TABLE[a][b] = gf_mul_slow((uint8_t)a, (uint8_t)b);
    GF_MUL_TABLE_READY = 1;
}

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    return GF_MUL_TABLE[a][b];
}

/* L-step linear coefficients (applied to bytes x[0]..x[15]) */
static const uint8_t L_COEFF[16] = {
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
};

/*
 * R transformation (spec Section 2.1.1):
 *   l = nabla(a[0],...,a[15]) = XOR of L_COEFF[i]*a[i]
 *   R(a) = l || a[0] || ... || a[14]
 * i.e. feedback goes to position 0 (leftmost), shift right by one byte.
 */
static void R(uint8_t x[16]) {
    /* compute LFSR feedback from all 16 bytes */
    uint8_t l = 0;
    for (int i = 0; i < 16; i++)
        l ^= gf_mul(x[i], L_COEFF[i]);
    /* shift right: x[1..15] -> x[0..14] ... wait, spec says shift LFSR:
       new_x[0] = l, new_x[i] = x[i-1] for i=1..15
       That's a LEFT rotation of the array positions with l inserted at [0]. */
    memmove(x + 1, x, 15);
    x[0] = l;
}

static void R_inv(uint8_t x[16]) {
    /* Given b = R(a) = (nabla(a), a[0], ..., a[14]), recover:
     *   a[0..14] = b[1..15]
     *   a[15]    = b[0] XOR sum_{i=0}^{14} L_COEFF[i] * a[i]
     * because L_COEFF[15] == 1.
     */
    uint8_t t = x[0];
    memmove(x, x + 1, 15);

    uint8_t fb = 0;
    for (int i = 0; i < 15; i++)
        fb ^= gf_mul(x[i], L_COEFF[i]);
    x[15] = t ^ fb;
}

static void L_slow(uint8_t x[16]) {
    for (int i = 0; i < 16; i++) R(x);
}

static void L_inv_slow(uint8_t x[16]) {
    for (int i = 0; i < 16; i++) R_inv(x);
}

/* L and L^-1 are linear over GF(2^8)^16, so each output can be built as the
 * XOR of 16 precomputed single-byte contributions.  Tables are 2 * 16 * 256 *
 * 16 = 128 KiB, trading a large number of GF multiplies per block for simple
 * table lookups and XORs.
 */
static uint8_t L_TABLE[16][256][16];
static uint8_t L_INV_TABLE[16][256][16];
static int L_TABLES_READY = 0;

#if defined(__GNUC__) || defined(__clang__)
__attribute__((constructor))
#endif
static void init_l_tables(void) {
    if (L_TABLES_READY) return;
    init_gf_mul_table();

    for (int pos = 0; pos < 16; pos++) {
        for (int val = 0; val < 256; val++) {
            uint8_t x[16] = {0};
            x[pos] = (uint8_t)val;
            L_slow(x);
            memcpy(L_TABLE[pos][val], x, 16);

            memset(x, 0, 16);
            x[pos] = (uint8_t)val;
            L_inv_slow(x);
            memcpy(L_INV_TABLE[pos][val], x, 16);
        }
    }
    L_TABLES_READY = 1;
}

static void L(uint8_t x[16]) {
    uint8_t y[16] = {0};
    for (int pos = 0; pos < 16; pos++) {
        const uint8_t *t = L_TABLE[pos][x[pos]];
        for (int j = 0; j < 16; j++) y[j] ^= t[j];
    }
    memcpy(x, y, 16);
}

static void L_inv(uint8_t x[16]) {
    uint8_t y[16] = {0};
    for (int pos = 0; pos < 16; pos++) {
        const uint8_t *t = L_INV_TABLE[pos][x[pos]];
        for (int j = 0; j < 16; j++) y[j] ^= t[j];
    }
    memcpy(x, y, 16);
}

static inline void S(uint8_t x[16]) {
    for (int i = 0; i < 16; i++) x[i] = PI[x[i]];
}
static inline void S_inv(uint8_t x[16]) {
    for (int i = 0; i < 16; i++) x[i] = PI_INV[x[i]];
}
static inline void XOR16(uint8_t dst[16], const uint8_t a[16], const uint8_t b[16]) {
    for (int i = 0; i < 16; i++) dst[i] = a[i] ^ b[i];
}

/* Key schedule */
typedef struct { uint8_t rk[10][16]; } KuzKey;

/* Round constant C_i: x[0..14]=0, x[15]=i, then L() */
static void round_const(int i, uint8_t c[16]) {
    memset(c, 0, 16);
    c[15] = (uint8_t)i;
    L(c);
}

static void F(const uint8_t c[16], uint8_t k1[16], uint8_t k2[16]) {
    uint8_t tmp[16], new_k1[16];
    XOR16(tmp, c, k1);
    S(tmp);
    L(tmp);
    XOR16(new_k1, tmp, k2);
    memcpy(k2, k1, 16);
    memcpy(k1, new_k1, 16);
}

KuzKey* kuz_key_schedule_native(const uint8_t key32[32]) {
    KuzKey *ks = malloc(sizeof(KuzKey));
    uint8_t k1[16], k2[16];
    memcpy(k1, key32,      16);
    memcpy(k2, key32 + 16, 16);
    memcpy(ks->rk[0], k1, 16);
    memcpy(ks->rk[1], k2, 16);

    int idx = 2;
    for (int i = 1; i <= 32; i++) {
        uint8_t c[16];
        round_const(i, c);
        F(c, k1, k2);
        if (i % 8 == 0) {
            memcpy(ks->rk[idx++], k1, 16);
            memcpy(ks->rk[idx++], k2, 16);
        }
    }
    return ks;
}

void kuz_encrypt_native(const uint8_t in[16], const KuzKey *ks, uint8_t out[16]) {
    uint8_t x[16];
    memcpy(x, in, 16);
#define KUZ_ENC_ROUND(i) do { XOR16(x, x, ks->rk[(i)]); S(x); L(x); } while (0)
    KUZ_ENC_ROUND(0);
    KUZ_ENC_ROUND(1);
    KUZ_ENC_ROUND(2);
    KUZ_ENC_ROUND(3);
    KUZ_ENC_ROUND(4);
    KUZ_ENC_ROUND(5);
    KUZ_ENC_ROUND(6);
    KUZ_ENC_ROUND(7);
    KUZ_ENC_ROUND(8);
#undef KUZ_ENC_ROUND
    XOR16(out, x, ks->rk[9]);
}

void kuz_decrypt_native(const uint8_t in[16], const KuzKey *ks, uint8_t out[16]) {
    uint8_t x[16];
    XOR16(x, in, ks->rk[9]);
#define KUZ_DEC_ROUND(i) do { L_inv(x); S_inv(x); XOR16(x, x, ks->rk[(i)]); } while (0)
    KUZ_DEC_ROUND(8);
    KUZ_DEC_ROUND(7);
    KUZ_DEC_ROUND(6);
    KUZ_DEC_ROUND(5);
    KUZ_DEC_ROUND(4);
    KUZ_DEC_ROUND(3);
    KUZ_DEC_ROUND(2);
    KUZ_DEC_ROUND(1);
    KUZ_DEC_ROUND(0);
#undef KUZ_DEC_ROUND
    memcpy(out, x, 16);
}

/* ---- Public ctypes API ---- */

#ifdef _WIN32
#  define KUZ_API __declspec(dllexport)
#else
#  define KUZ_API
#endif

KUZ_API void* kuz_key_schedule(const uint8_t *key32) {
    init_l_tables();
    return kuz_key_schedule_native(key32);
}

KUZ_API void kuz_free_key_arr(void *ks) { free(ks); }

KUZ_API void kuz_encrypt_block(const uint8_t *in16, void *ks, uint8_t *out16) {
    kuz_encrypt_native(in16, (KuzKey*)ks, out16);
}

KUZ_API void kuz_decrypt_block(const uint8_t *in16, void *ks, uint8_t *out16) {
    kuz_decrypt_native(in16, (KuzKey*)ks, out16);
}

KUZ_API void kuz_ctr_crypt(
    const uint8_t *in, uint8_t *out, size_t length,
    void *ks, const uint8_t *iv_be
) {
    uint8_t ctr_buf[16], ks_buf[16];
    memcpy(ctr_buf, iv_be, 16);

    size_t offset = 0;
    while (offset < length) {
        kuz_encrypt_native(ctr_buf, (KuzKey*)ks, ks_buf);
        size_t blk = length - offset; if (blk > 16) blk = 16;
        for (size_t j = 0; j < blk; j++) out[offset+j] = in[offset+j] ^ ks_buf[j];
        offset += blk;

        /* Increment the 128-bit big-endian counter in-place. */
        for (int i = 15; i >= 0; i--) {
            ctr_buf[i]++;
            if (ctr_buf[i] != 0) break;
        }
    }
}