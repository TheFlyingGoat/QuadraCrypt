/* Serpent_Fast.c
 *
 * Standalone, fast Serpent-128/192/256 implementation.  Derived from
 * the reference code shipped with libgcrypt (cipher/serpent.c) and
 * rewritten to build as a small shared library with NO libgcrypt
 * infrastructure.  The public C ABI mirrors the Kuznechik_Fast.c
 * wrapper used elsewhere in this project.
 *
 * All 16-byte blocks crossing the API boundary are interpreted as
 * BIG-ENDIAN (i.e. the same byte order the Python code uses with
 * `int.to_bytes(16, "big")`), so it can be dropped in transparently
 * in place of pyserpent.
 *
 * Build:
 *   Windows / MSVC : cl /LD /O2 Serpent_Fast.c /Fe:Serpent_Fast.dll
 *   Windows / MinGW: gcc -O2 -shared -o Serpent_Fast.dll Serpent_Fast.c
 *   Linux          : gcc -O2 -fPIC -shared -o libSerpent_Fast.so Serpent_Fast.c
 *
 *   #pragma comment(lib, "advapi32")  -- not needed, we use only libc
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t u32;
typedef uint8_t  byte;

#if defined(_WIN32) || defined(_WIN64)
  #define SERPENT_API __declspec(dllexport)
#else
  #define SERPENT_API __attribute__((visibility("default")))
#endif

/* ------------------------------------------------------------------ */
/* Small helpers                                                        */
/* ------------------------------------------------------------------ */
static inline u32 rol_u32(u32 x, unsigned int n) {
    return (x << n) | (x >> (32 - n));
}
static inline u32 ror_u32(u32 x, unsigned int n) {
    return (x >> n) | (x << (32 - n));
}

static inline u32 load_be32(const byte *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
           ((u32)p[2] <<  8) | ((u32)p[3]);
}
static inline void store_be32(byte *p, u32 v) {
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >>  8);
    p[3] = (byte)(v);
}

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */
#define ROUNDS 32
#define PHI    0x9E3779B9U

/* 33 subkeys x 128 bits, stored as 4 x u32 (big-endian on the wire). */
typedef u32 serpent_subkeys_t[ROUNDS + 1][4];

typedef struct serpent_ctx {
    serpent_subkeys_t keys;
} serpent_ctx;

/* ------------------------------------------------------------------ */
/* S-Boxes (forward and inverse) - all 8 of them                       */
/* ------------------------------------------------------------------ */
#define SBOX0(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t05, t06, t07, t08, t09; \
    u32 t11, t12, t13, t14, t15, t17, t01; \
    t01 = b   ^ c  ; \
    t02 = a   | d  ; \
    t03 = a   ^ b  ; \
    z   = t02 ^ t01; \
    t05 = c   | z  ; \
    t06 = a   ^ d  ; \
    t07 = b   | c  ; \
    t08 = d   & t05; \
    t09 = t03 & t07; \
    y   = t09 ^ t08; \
    t11 = t09 & y  ; \
    t12 = c   ^ d  ; \
    t13 = t07 ^ t11; \
    t14 = b   & t06; \
    t15 = t06 ^ t13; \
    w   =     ~ t15; \
    t17 = w   ^ t14; \
    x   = t12 ^ t17; \
  }

#define SBOX0_INVERSE(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t06, t08, t09, t10; \
    u32 t12, t13, t14, t15, t17, t18, t01; \
    t01 = c   ^ d  ; \
    t02 = a   | b  ; \
    t03 = b   | c  ; \
    t04 = c   & t01; \
    t05 = t02 ^ t01; \
    t06 = a   | t04; \
    y   =     ~ t05; \
    t08 = b   ^ d  ; \
    t09 = t03 & t08; \
    t10 = d   | y  ; \
    x   = t09 ^ t06; \
    t12 = a   | t05; \
    t13 = x   ^ t12; \
    t14 = t03 ^ t10; \
    t15 = a   ^ c  ; \
    z   = t14 ^ t13; \
    t17 = t05 & t13; \
    t18 = t14 | t17; \
    w   = t15 ^ t18; \
  }

#define SBOX1(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t06, t07, t08; \
    u32 t10, t11, t12, t13, t16, t17, t01; \
    t01 = a   | d  ; \
    t02 = c   ^ d  ; \
    t03 =     ~ b  ; \
    t04 = a   ^ c  ; \
    t05 = a   | t03; \
    t06 = d   & t04; \
    t07 = t01 & t02; \
    t08 = b   | t06; \
    y   = t02 ^ t05; \
    t10 = t07 ^ t08; \
    t11 = t01 ^ t10; \
    t12 = y   ^ t11; \
    t13 = b   & d  ; \
    z   =     ~ t10; \
    x   = t13 ^ t12; \
    t16 = t10 | x  ; \
    t17 = t05 & t16; \
    w   = c   ^ t17; \
  }

#define SBOX1_INVERSE(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t06, t07, t08; \
    u32 t09, t10, t11, t14, t15, t17, t01; \
    t01 = a   ^ b  ; \
    t02 = b   | d  ; \
    t03 = a   & c  ; \
    t04 = c   ^ t02; \
    t05 = a   | t04; \
    t06 = t01 & t05; \
    t07 = d   | t03; \
    t08 = b   ^ t06; \
    t09 = t07 ^ t06; \
    t10 = t04 | t03; \
    t11 = d   & t08; \
    y   =     ~ t09; \
    x   = t10 ^ t11; \
    t14 = a   | y  ; \
    t15 = t06 ^ x  ; \
    z   = t01 ^ t04; \
    t17 = c   ^ t15; \
    w   = t14 ^ t17; \
  }

#define SBOX2(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t05, t06, t07, t08; \
    u32 t09, t10, t12, t13, t14, t01; \
    t01 = a   | c  ; \
    t02 = a   ^ b  ; \
    t03 = d   ^ t01; \
    w   = t02 ^ t03; \
    t05 = c   ^ w  ; \
    t06 = b   ^ t05; \
    t07 = b   | t05; \
    t08 = t01 & t06; \
    t09 = t03 ^ t07; \
    t10 = t02 | t09; \
    x   = t10 ^ t08; \
    t12 = a   | d  ; \
    t13 = t09 ^ x  ; \
    t14 = b   ^ t13; \
    z   =     ~ t09; \
    y   = t12 ^ t14; \
  }

#define SBOX2_INVERSE(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t06, t07, t08, t09; \
    u32 t10, t11, t12, t15, t16, t17, t01; \
    t01 = a   ^ d  ; \
    t02 = c   ^ d  ; \
    t03 = a   & c  ; \
    t04 = b   | t02; \
    w   = t01 ^ t04; \
    t06 = a   | c  ; \
    t07 = d   | w  ; \
    t08 =     ~ d  ; \
    t09 = b   & t06; \
    t10 = t08 | t03; \
    t11 = b   & t07; \
    t12 = t06 & t02; \
    z   = t09 ^ t10; \
    x   = t12 ^ t11; \
    t15 = c   & z  ; \
    t16 = w   ^ x  ; \
    t17 = t10 ^ t15; \
    y   = t16 ^ t17; \
  }

#define SBOX3(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t06, t07, t08; \
    u32 t09, t10, t11, t13, t14, t15, t01; \
    t01 = a   ^ c  ; \
    t02 = a   | d  ; \
    t03 = a   & d  ; \
    t04 = t01 & t02; \
    t05 = b   | t03; \
    t06 = a   & b  ; \
    t07 = d   ^ t04; \
    t08 = c   | t06; \
    t09 = b   ^ t07; \
    t10 = d   & t05; \
    t11 = t02 ^ t10; \
    z   = t08 ^ t09; \
    t13 = d   | z  ; \
    t14 = a   | t07; \
    t15 = b   & t13; \
    y   = t08 ^ t11; \
    w   = t14 ^ t15; \
    x   = t05 ^ t04; \
  }

#define SBOX3_INVERSE(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t06, t07, t09; \
    u32 t11, t12, t13, t14, t16, t01; \
    t01 = c   | d  ; \
    t02 = a   | d  ; \
    t03 = c   ^ t02; \
    t04 = b   ^ t02; \
    t05 = a   ^ d  ; \
    t06 = t04 & t03; \
    t07 = b   & t01; \
    y   = t05 ^ t06; \
    t09 = a   ^ t03; \
    w   = t07 ^ t03; \
    t11 = w   | t05; \
    t12 = t09 & t11; \
    t13 = a   & y  ; \
    t14 = t01 ^ t05; \
    x   = b   ^ t12; \
    t16 = b   | t13; \
    z   = t14 ^ t16; \
  }

#define SBOX4(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t06, t08, t09; \
    u32 t10, t11, t12, t13, t14, t15, t16, t01; \
    t01 = a   | b  ; \
    t02 = b   | c  ; \
    t03 = a   ^ t02; \
    t04 = b   ^ d  ; \
    t05 = d   | t03; \
    t06 = d   & t01; \
    z   = t03 ^ t06; \
    t08 = z   & t04; \
    t09 = t04 & t05; \
    t10 = c   ^ t06; \
    t11 = b   & c  ; \
    t12 = t04 ^ t08; \
    t13 = t11 | t03; \
    t14 = t10 ^ t09; \
    t15 = a   & t05; \
    t16 = t11 | t12; \
    y   = t13 ^ t08; \
    x   = t15 ^ t16; \
    w   =     ~ t14; \
  }

#define SBOX4_INVERSE(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t06, t07, t09; \
    u32 t10, t11, t12, t13, t15, t01; \
    t01 = b   | d  ; \
    t02 = c   | d  ; \
    t03 = a   & t01; \
    t04 = b   ^ t02; \
    t05 = c   ^ d  ; \
    t06 =     ~ t03; \
    t07 = a   & t04; \
    x   = t05 ^ t07; \
    t09 = x   | t06; \
    t10 = a   ^ t07; \
    t11 = t01 ^ t09; \
    t12 = d   ^ t04; \
    t13 = c   | t10; \
    z   = t03 ^ t12; \
    t15 = a   ^ t04; \
    y   = t11 ^ t13; \
    w   = t15 ^ t09; \
  }

#define SBOX5(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t07, t08, t09; \
    u32 t10, t11, t12, t13, t14, t01; \
    t01 = b   ^ d  ; \
    t02 = b   | d  ; \
    t03 = a   & t01; \
    t04 = c   ^ t02; \
    t05 = t03 ^ t04; \
    w   =     ~ t05; \
    t07 = a   ^ t01; \
    t08 = d   | w  ; \
    t09 = b   | t05; \
    t10 = d   ^ t08; \
    t11 = b   | t07; \
    t12 = t03 | w  ; \
    t13 = t07 | t10; \
    t14 = t01 ^ t11; \
    y   = t09 ^ t13; \
    x   = t07 ^ t08; \
    z   = t12 ^ t14; \
  }

#define SBOX5_INVERSE(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t07, t08, t09; \
    u32 t10, t12, t13, t15, t16, t01; \
    t01 = a   & d  ; \
    t02 = c   ^ t01; \
    t03 = a   ^ d  ; \
    t04 = b   & t02; \
    t05 = a   & c  ; \
    w   = t03 ^ t04; \
    t07 = a   & w  ; \
    t08 = t01 ^ w  ; \
    t09 = b   | t05; \
    t10 =     ~ b  ; \
    x   = t08 ^ t09; \
    t12 = t10 | t07; \
    t13 = w   | x  ; \
    z   = t02 ^ t12; \
    t15 = t02 ^ t13; \
    t16 = b   ^ d  ; \
    y   = t16 ^ t15; \
  }

#define SBOX6(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t07, t08, t09, t10; \
    u32 t11, t12, t13, t15, t17, t18, t01; \
    t01 = a   & d  ; \
    t02 = b   ^ c  ; \
    t03 = a   ^ d  ; \
    t04 = t01 ^ t02; \
    t05 = b   | c  ; \
    x   =     ~ t04; \
    t07 = t03 & t05; \
    t08 = b   & x  ; \
    t09 = a   | c  ; \
    t10 = t07 ^ t08; \
    t11 = b   | d  ; \
    t12 = c   ^ t11; \
    t13 = t09 ^ t10; \
    y   =     ~ t13; \
    t15 = x   & t03; \
    z   = t12 ^ t07; \
    t17 = a   ^ b  ; \
    t18 = y   ^ t15; \
    w   = t17 ^ t18; \
  }

#define SBOX6_INVERSE(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t06, t07, t08, t09; \
    u32 t12, t13, t14, t15, t16, t17, t01; \
    t01 = a   ^ c  ; \
    t02 =     ~ c  ; \
    t03 = b   & t01; \
    t04 = b   | t02; \
    t05 = d   | t03; \
    t06 = b   ^ d  ; \
    t07 = a   & t04; \
    t08 = a   | t02; \
    t09 = t07 ^ t05; \
    x   = t06 ^ t08; \
    w   =     ~ t09; \
    t12 = b   & w  ; \
    t13 = t01 & t05; \
    t14 = t01 ^ t12; \
    t15 = t07 ^ t13; \
    t16 = d   | t02; \
    t17 = a   ^ x  ; \
    z   = t17 ^ t15; \
    y   = t16 ^ t14; \
  }

#define SBOX7(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t05, t06, t08, t09, t10; \
    u32 t11, t13, t14, t15, t16, t17, t01; \
    t01 = a   & c  ; \
    t02 =     ~ d  ; \
    t03 = a   & t02; \
    t04 = b   | t01; \
    t05 = a   & b  ; \
    t06 = c   ^ t04; \
    z   = t03 ^ t06; \
    t08 = c   | z  ; \
    t09 = d   | t05; \
    t10 = a   ^ t08; \
    t11 = t04 & z  ; \
    x   = t09 ^ t10; \
    t13 = b   ^ x  ; \
    t14 = t01 ^ x  ; \
    t15 = c   ^ t05; \
    t16 = t11 | t13; \
    t17 = t02 | t14; \
    w   = t15 ^ t17; \
    y   = a   ^ t16; \
  }

#define SBOX7_INVERSE(a, b, c, d, w, x, y, z) \
  { \
    u32 t02, t03, t04, t06, t07, t08, t09; \
    u32 t10, t11, t13, t14, t15, t16, t01; \
    t01 = a   & b  ; \
    t02 = a   | b  ; \
    t03 = c   | t01; \
    t04 = d   & t02; \
    z   = t03 ^ t04; \
    t06 = b   ^ t04; \
    t07 = d   ^ z  ; \
    t08 =     ~ t07; \
    t09 = t06 | t08; \
    t10 = b   ^ d  ; \
    t11 = a   | d  ; \
    x   = a   ^ t09; \
    t13 = c   ^ t06; \
    t14 = c   & t11; \
    t15 = d   | x  ; \
    t16 = t01 | t10; \
    w   = t13 ^ t15; \
    y   = t14 ^ t16; \
  }

/* ------------------------------------------------------------------ */
/* Block xor / copy / SBOX dispatch                                     */
/* ------------------------------------------------------------------ */
#define BLOCK_XOR(block0, block1) \
  {                               \
    block0[0] ^= block1[0];       \
    block0[1] ^= block1[1];       \
    block0[2] ^= block1[2];       \
    block0[3] ^= block1[3];       \
  }

#define BLOCK_COPY(block_dst, block_src) \
  {                                      \
    block_dst[0] = block_src[0];         \
    block_dst[1] = block_src[1];         \
    block_dst[2] = block_src[2];         \
    block_dst[3] = block_src[3];         \
  }

#define SBOX(which, array0, array1, index)            \
  SBOX##which (array0[index + 0], array0[index + 1],  \
               array0[index + 2], array0[index + 3],  \
               array1[index + 0], array1[index + 1],  \
               array1[index + 2], array1[index + 3]);

#define SBOX_INVERSE(which, array0, array1, index)              \
  SBOX##which##_INVERSE (array0[index + 0], array0[index + 1],  \
                         array0[index + 2], array0[index + 3],  \
                         array1[index + 0], array1[index + 1],  \
                         array1[index + 2], array1[index + 3]);

/* ------------------------------------------------------------------ */
/* Linear transformation                                                */
/* ------------------------------------------------------------------ */
#define LINEAR_TRANSFORMATION(block)                  \
  {                                                   \
    block[0] = rol_u32 (block[0], 13);                \
    block[2] = rol_u32 (block[2], 3);                 \
    block[1] = block[1] ^ block[0] ^ block[2];        \
    block[3] = block[3] ^ block[2] ^ (block[0] << 3); \
    block[1] = rol_u32 (block[1], 1);                 \
    block[3] = rol_u32 (block[3], 7);                 \
    block[0] = block[0] ^ block[1] ^ block[3];        \
    block[2] = block[2] ^ block[3] ^ (block[1] << 7); \
    block[0] = rol_u32 (block[0], 5);                 \
    block[2] = rol_u32 (block[2], 22);                \
  }

#define LINEAR_TRANSFORMATION_INVERSE(block)          \
  {                                                   \
    block[2] = ror_u32 (block[2], 22);                \
    block[0] = ror_u32 (block[0] , 5);                \
    block[2] = block[2] ^ block[3] ^ (block[1] << 7); \
    block[0] = block[0] ^ block[1] ^ block[3];        \
    block[3] = ror_u32 (block[3], 7);                 \
    block[1] = ror_u32 (block[1], 1);                 \
    block[3] = block[3] ^ block[2] ^ (block[0] << 3); \
    block[1] = block[1] ^ block[0] ^ block[2];        \
    block[2] = ror_u32 (block[2], 3);                 \
    block[0] = ror_u32 (block[0], 13);                \
  }

/* ------------------------------------------------------------------ */
/* Round macros                                                        */
/* ------------------------------------------------------------------ */
#define ROUND(which, subkeys, block, block_tmp) \
  {                                             \
    BLOCK_XOR (block, subkeys[round]);          \
    round++;                                    \
    SBOX (which, block, block_tmp, 0);          \
    LINEAR_TRANSFORMATION (block_tmp);          \
    BLOCK_COPY (block, block_tmp);              \
  }

#define ROUND_LAST(which, subkeys, block, block_tmp) \
  {                                                  \
    BLOCK_XOR (block, subkeys[round]);               \
    round++;                                         \
    SBOX (which, block, block_tmp, 0);               \
    BLOCK_XOR (block_tmp, subkeys[round]);           \
    round++;                                         \
  }

#define ROUND_INVERSE(which, subkey, block, block_tmp) \
  {                                                    \
    LINEAR_TRANSFORMATION_INVERSE (block);             \
    SBOX_INVERSE (which, block, block_tmp, 0);         \
    BLOCK_XOR (block_tmp, subkey[round]);              \
    round--;                                           \
    BLOCK_COPY (block, block_tmp);                     \
  }

#define ROUND_FIRST_INVERSE(which, subkeys, block, block_tmp) \
  {                                                           \
    BLOCK_XOR (block, subkeys[round]);                        \
    round--;                                                  \
    SBOX_INVERSE (which, block, block_tmp, 0);                \
    BLOCK_XOR (block_tmp, subkeys[round]);                    \
    round--;                                                  \
  }

/* ------------------------------------------------------------------ */
/* Key preparation / subkey generation                                 */
/* ------------------------------------------------------------------ */
static void
serpent_key_prepare (const byte *key, unsigned int key_length,
                     u32 key_prepared[8])
{
  unsigned int i;

  for (i = 0; i < key_length / 4; i++)
    key_prepared[i] = load_be32 (key + 4 * i);

  if (i < 8)
    {
      /* Pad with 0x00000001 followed by zeros, per the Serpent spec. */
      key_prepared[i] = 0x00000001U;
      for (i++; i < 8; i++)
        key_prepared[i] = 0;
    }
}

static void
serpent_subkeys_generate (const u32 key[8], serpent_subkeys_t subkeys)
{
  u32 w_real[140];
  u32 k[132];
  u32 *w = &w_real[8];
  int i, j;

  /* Initialise with key values (8 words = 256-bit). */
  for (i = 0; i < 8; i++)
    w[i - 8] = key[i];

  /* Expand to intermediate key using the affine recurrence. */
  for (i = 0; i < 132; i++)
    w[i] = rol_u32 (w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ (u32)i, 11);

  /* Calculate subkeys via S-Boxes, in bitslice mode. */
  SBOX (3, w, k,   0);
  SBOX (2, w, k,   4);
  SBOX (1, w, k,   8);
  SBOX (0, w, k,  12);
  SBOX (7, w, k,  16);
  SBOX (6, w, k,  20);
  SBOX (5, w, k,  24);
  SBOX (4, w, k,  28);
  SBOX (3, w, k,  32);
  SBOX (2, w, k,  36);
  SBOX (1, w, k,  40);
  SBOX (0, w, k,  44);
  SBOX (7, w, k,  48);
  SBOX (6, w, k,  52);
  SBOX (5, w, k,  56);
  SBOX (4, w, k,  60);
  SBOX (3, w, k,  64);
  SBOX (2, w, k,  68);
  SBOX (1, w, k,  72);
  SBOX (0, w, k,  76);
  SBOX (7, w, k,  80);
  SBOX (6, w, k,  84);
  SBOX (5, w, k,  88);
  SBOX (4, w, k,  92);
  SBOX (3, w, k,  96);
  SBOX (2, w, k, 100);
  SBOX (1, w, k, 104);
  SBOX (0, w, k, 108);
  SBOX (7, w, k, 112);
  SBOX (6, w, k, 116);
  SBOX (5, w, k, 120);
  SBOX (4, w, k, 124);
  SBOX (3, w, k, 128);

  /* Renumber subkeys. */
  for (i = 0; i < ROUNDS + 1; i++)
    for (j = 0; j < 4; j++)
      subkeys[i][j] = k[4 * i + j];
}

/* ------------------------------------------------------------------ */
/* Block encrypt / decrypt                                              */
/* ------------------------------------------------------------------ */
static void
serpent_encrypt_block_internal (const serpent_subkeys_t keys,
                                const byte in[16], byte out[16])
{
  u32 b[4], b_next[4];
  int round = 0;
  int i;

  for (i = 0; i < 4; i++)
    b[i] = load_be32 (in + 4 * i);

  ROUND (0, keys, b, b_next);
  ROUND (1, keys, b, b_next);
  ROUND (2, keys, b, b_next);
  ROUND (3, keys, b, b_next);
  ROUND (4, keys, b, b_next);
  ROUND (5, keys, b, b_next);
  ROUND (6, keys, b, b_next);
  ROUND (7, keys, b, b_next);
  ROUND (0, keys, b, b_next);
  ROUND (1, keys, b, b_next);
  ROUND (2, keys, b, b_next);
  ROUND (3, keys, b, b_next);
  ROUND (4, keys, b, b_next);
  ROUND (5, keys, b, b_next);
  ROUND (6, keys, b, b_next);
  ROUND (7, keys, b, b_next);
  ROUND (0, keys, b, b_next);
  ROUND (1, keys, b, b_next);
  ROUND (2, keys, b, b_next);
  ROUND (3, keys, b, b_next);
  ROUND (4, keys, b, b_next);
  ROUND (5, keys, b, b_next);
  ROUND (6, keys, b, b_next);
  ROUND (7, keys, b, b_next);
  ROUND (0, keys, b, b_next);
  ROUND (1, keys, b, b_next);
  ROUND (2, keys, b, b_next);
  ROUND (3, keys, b, b_next);
  ROUND (4, keys, b, b_next);
  ROUND (5, keys, b, b_next);
  ROUND (6, keys, b, b_next);

  ROUND_LAST (7, keys, b, b_next);

  for (i = 0; i < 4; i++)
    store_be32 (out + 4 * i, b_next[i]);
}

static void
serpent_decrypt_block_internal (const serpent_subkeys_t keys,
                                const byte in[16], byte out[16])
{
  u32 b[4], b_next[4];
  int round = ROUNDS;
  int i;

  for (i = 0; i < 4; i++)
    b_next[i] = load_be32 (in + 4 * i);

  ROUND_FIRST_INVERSE (7, keys, b_next, b);

  ROUND_INVERSE (6, keys, b, b_next);
  ROUND_INVERSE (5, keys, b, b_next);
  ROUND_INVERSE (4, keys, b, b_next);
  ROUND_INVERSE (3, keys, b, b_next);
  ROUND_INVERSE (2, keys, b, b_next);
  ROUND_INVERSE (1, keys, b, b_next);
  ROUND_INVERSE (0, keys, b, b_next);
  ROUND_INVERSE (7, keys, b, b_next);
  ROUND_INVERSE (6, keys, b, b_next);
  ROUND_INVERSE (5, keys, b, b_next);
  ROUND_INVERSE (4, keys, b, b_next);
  ROUND_INVERSE (3, keys, b, b_next);
  ROUND_INVERSE (2, keys, b, b_next);
  ROUND_INVERSE (1, keys, b, b_next);
  ROUND_INVERSE (0, keys, b, b_next);
  ROUND_INVERSE (7, keys, b, b_next);
  ROUND_INVERSE (6, keys, b, b_next);
  ROUND_INVERSE (5, keys, b, b_next);
  ROUND_INVERSE (4, keys, b, b_next);
  ROUND_INVERSE (3, keys, b, b_next);
  ROUND_INVERSE (2, keys, b, b_next);
  ROUND_INVERSE (1, keys, b, b_next);
  ROUND_INVERSE (0, keys, b, b_next);
  ROUND_INVERSE (7, keys, b, b_next);
  ROUND_INVERSE (6, keys, b, b_next);
  ROUND_INVERSE (5, keys, b, b_next);
  ROUND_INVERSE (4, keys, b, b_next);
  ROUND_INVERSE (3, keys, b, b_next);
  ROUND_INVERSE (2, keys, b, b_next);
  ROUND_INVERSE (1, keys, b, b_next);
  ROUND_INVERSE (0, keys, b, b_next);

  for (i = 0; i < 4; i++)
    store_be32 (out + 4 * i, b_next[i]);
}

/* ------------------------------------------------------------------ */
/* Exported API (mirrors Kuznechik_Fast.c)                              */
/* ------------------------------------------------------------------ */

/* Allocate a context and pre-compute subkeys from a 32-byte key.
 * Returns an opaque pointer (NULL on failure). */
SERPENT_API void *
serpent_key_schedule (const byte *key)
{
  serpent_ctx *ctx;
  u32 key_words[8];

  if (!key)
    return NULL;

  ctx = (serpent_ctx *) malloc (sizeof (serpent_ctx));
  if (!ctx)
    return NULL;

  serpent_key_prepare (key, 32, key_words);
  serpent_subkeys_generate (key_words, ctx->keys);
  return ctx;
}

/* Wipe and free a context.  Safe to call with NULL. */
SERPENT_API void
serpent_free_key_arr (void *ctx_ptr)
{
  serpent_ctx *ctx = (serpent_ctx *) ctx_ptr;
  if (ctx)
    {
      /* Wipe the subkeys before releasing the memory. */
      volatile u32 *p = (volatile u32 *) ctx->keys;
      size_t n = sizeof (ctx->keys) / sizeof (u32);
      while (n--) *p++ = 0;
      free (ctx);
    }
}

/* Encrypt a single 16-byte block. */
SERPENT_API void
serpent_encrypt_block (const byte *in, void *ctx_ptr, byte *out)
{
  serpent_encrypt_block_internal (
      ((const serpent_ctx *) ctx_ptr)->keys, in, out);
}

/* Decrypt a single 16-byte block. */
SERPENT_API void
serpent_decrypt_block (const byte *in, void *ctx_ptr, byte *out)
{
  serpent_decrypt_block_internal (
      ((const serpent_ctx *) ctx_ptr)->keys, in, out);
}

/* CTR-mode encrypt/decrypt (the two operations are identical).
 *  in     - input bytes
 *  out    - output bytes (may overlap in==out)
 *  length - number of bytes
 *  ctx    - context from serpent_key_schedule
 *  iv     - 16-byte big-endian initial counter
 */
SERPENT_API void
serpent_ctr_crypt (const byte *in, byte *out, size_t length,
                   void *ctx_ptr, const byte *iv)
{
  const serpent_ctx *ctx = (const serpent_ctx *) ctx_ptr;
  byte ks[16];
  byte ctr[16];
  size_t i, j, chunk;

  if (!ctx || !in || !out || !iv)
    return;

  /* Initialise the 128-bit counter from IV (big-endian). */
  memcpy (ctr, iv, 16);

  while (length > 0)
    {
      serpent_encrypt_block_internal (ctx->keys, ctr, ks);

      chunk = (length < 16) ? length : 16;
      for (j = 0; j < chunk; j++)
        out[j] = in[j] ^ ks[j];

      /* Increment the 128-bit big-endian counter. */
      for (i = 16; i-- > 0;)
        {
          if (++ctr[i] != 0)
            break;
        }

      in   += chunk;
      out  += chunk;
      length -= chunk;
    }
}