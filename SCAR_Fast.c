/*
 * SCAR_Fast.c
 *
 * Fast C implementation of the SCAR cipher (Swap-Convert-Adjust-Repeat).
 * Base-512 substitution-permutation network operating on 16-symbol blocks.
 *
 * Build:
 *   Linux:   gcc -O3 -march=native -shared -fPIC -o SCAR_Fast.so SCAR_Fast.c
 *   Windows: cl /LD /O2 SCAR_Fast.c /Fe:SCAR_Fast.dll
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SCAR_BLOCK_LEN  16
#define SCAR_ROUNDS_DEF 5
#define SCAR_DOMAIN     513

#if defined(_WIN32) || defined(_WIN64)
  #define SCAR_API __declspec(dllexport)
#else
  #define SCAR_API __attribute__((visibility("default")))
#endif

#include "scar_table.h"

typedef struct {
    uint16_t swap[513];
    uint16_t inv_swap[513];
    uint16_t shift_vals[16];
    int8_t   shift_ops[16];
    int      rounds;
} ScarCtx;

static inline int abs_val(int a) { return a < 0 ? -a : a; }

/* Reverse lookup: UTF-8 bytes + length -> code.
 * Linear search is fine since this is only called once per character during
 * the initial decode phase (not per round). */
static uint16_t scar_char_to_code(const uint8_t *bytes, uint8_t len) {
    for (uint16_t i = 0; i < 513; i++) {
        if (scar_inv_utf8_len[i] == len &&
            memcmp(bytes, scar_inv_utf8 + i * 3, len) == 0)
            return i;
    }
    return 0;
}

/* ---------- Block operations ---------- */

static inline void scar_swap_block(uint16_t *blk, const uint16_t *swap) {
    for (int i = 0; i < SCAR_BLOCK_LEN; i++)
        blk[i] = swap[blk[i]];
}

static inline void scar_inv_swap_block(uint16_t *blk, const uint16_t *inv_swap) {
    for (int i = 0; i < SCAR_BLOCK_LEN; i++)
        blk[i] = inv_swap[blk[i]];
}

static inline void scar_shift_block(uint16_t *blk, const uint16_t *vals,
                                    const int8_t *ops) {
    for (int i = 0; i < SCAR_BLOCK_LEN; i++) {
        int v = (int)blk[i] + ops[i] * (int)vals[i];
        while (v < 0) v += SCAR_DOMAIN;
        blk[i] = (uint16_t)(v % SCAR_DOMAIN);
    }
}

static inline void scar_inv_shift_block(uint16_t *blk, const uint16_t *vals,
                                        const int8_t *ops) {
    for (int i = 0; i < SCAR_BLOCK_LEN; i++) {
        int v = (int)blk[i] - ops[i] * (int)vals[i];
        while (v < 0) v += SCAR_DOMAIN;
        blk[i] = (uint16_t)(v % SCAR_DOMAIN);
    }
}

static inline void scar_rotate_left(uint16_t *blk, int r) {
    r %= SCAR_BLOCK_LEN;
    if (r == 0) return;
    uint16_t tmp[SCAR_BLOCK_LEN];
    memcpy(tmp, blk + r, (SCAR_BLOCK_LEN - r) * sizeof(uint16_t));
    memcpy(tmp + (SCAR_BLOCK_LEN - r), blk, r * sizeof(uint16_t));
    memcpy(blk, tmp, SCAR_BLOCK_LEN * sizeof(uint16_t));
}

static inline void scar_rotate_right(uint16_t *blk, int r) {
    r %= SCAR_BLOCK_LEN;
    if (r == 0) return;
    /* rotate_right by r == rotate_left by (16 - r) */
    int lr = SCAR_BLOCK_LEN - r;
    uint16_t tmp[SCAR_BLOCK_LEN];
    memcpy(tmp, blk + lr, (SCAR_BLOCK_LEN - lr) * sizeof(uint16_t));
    memcpy(tmp + (SCAR_BLOCK_LEN - lr), blk, lr * sizeof(uint16_t));
    memcpy(blk, tmp, SCAR_BLOCK_LEN * sizeof(uint16_t));
}

static inline void scar_diffuse_fwd(uint16_t *blk) {
    uint16_t stack = 0;
    int i = 0;
    while (i + 2 < SCAR_BLOCK_LEN) {
        uint16_t a = blk[i], b = blk[i + 1], c = blk[i + 2];
        uint16_t c_new = (c + (uint16_t)abs_val((int)a - (int)b) + stack) % SCAR_DOMAIN;
        stack = c_new;
        blk[i + 2] = c_new;
        i += 3;
    }
}

static inline void scar_diffuse_inv(uint16_t *blk) {
    uint16_t stack = 0;
    int i = 0;
    while (i + 2 < SCAR_BLOCK_LEN) {
        uint16_t a = blk[i], b = blk[i + 1], cp = blk[i + 2];
        int64_t c = (int64_t)cp - (int64_t)abs_val((int)a - (int)b) - (int64_t)stack;
        while (c < 0) c += SCAR_DOMAIN;
        blk[i + 2] = (uint16_t)(c % SCAR_DOMAIN);
        stack = cp;
        i += 3;
    }
}

/* ---------- Encrypt / Decrypt blocks ---------- */

static void scar_encrypt_blocks(
    uint16_t *blocks, int num_blocks,
    const ScarCtx *ctx)
{
    for (int b = 0; b < num_blocks; b++) {
        uint16_t *blk = blocks + b * SCAR_BLOCK_LEN;
        for (int r = 0; r < ctx->rounds; r++) {
            scar_swap_block(blk, ctx->swap);
            scar_shift_block(blk, ctx->shift_vals, ctx->shift_ops);
            scar_rotate_left(blk, r + 3);
            scar_diffuse_fwd(blk);
        }
    }
}

static void scar_decrypt_blocks(
    uint16_t *blocks, int num_blocks,
    const ScarCtx *ctx)
{
    for (int b = 0; b < num_blocks; b++) {
        uint16_t *blk = blocks + b * SCAR_BLOCK_LEN;
        for (int r = ctx->rounds - 1; r >= 0; r--) {
            scar_diffuse_inv(blk);
            scar_rotate_right(blk, r + 3);
            scar_inv_shift_block(blk, ctx->shift_vals, ctx->shift_ops);
            scar_inv_swap_block(blk, ctx->inv_swap);
        }
    }
}

/* ---------- Base-512 encoding / decoding ---------- */

static int scar_bin_to_codes(
    const uint8_t *data, int data_len,
    uint16_t *codes, int max_codes)
{
    int idx = 0;
    uint64_t buf = 0;
    int bits = 0;

    /* Build 4-byte big-endian length header */
    uint8_t hdr[4];
    hdr[0] = (uint8_t)((data_len >> 24) & 0xFF);
    hdr[1] = (uint8_t)((data_len >> 16) & 0xFF);
    hdr[2] = (uint8_t)((data_len >> 8)  & 0xFF);
    hdr[3] = (uint8_t)( data_len        & 0xFF);

    /* Process length header */
    for (int i = 0; i < 4; i++) {
        buf = (buf << 8) | hdr[i];
        bits += 8;
        while (bits >= 9 && idx < max_codes) {
            bits -= 9;
            codes[idx++] = (uint16_t)((buf >> bits) & 0x1FF);
            buf &= (1ULL << bits) - 1;
        }
    }

    /* Process data payload */
    for (int i = 0; i < data_len; i++) {
        buf = (buf << 8) | data[i];
        bits += 8;
        while (bits >= 9 && idx < max_codes) {
            bits -= 9;
            codes[idx++] = (uint16_t)((buf >> bits) & 0x1FF);
            buf &= (1ULL << bits) - 1;
        }
    }

    /* Remaining bits */
    if (bits > 0 && idx < max_codes) {
        codes[idx++] = (uint16_t)((buf << (9 - bits)) & 0x1FF);
    }

    return idx;
}

static int scar_codes_to_bin(
    const uint16_t *codes, int num_codes,
    uint8_t *out, int max_out)
{
    uint64_t buf = 0;
    int bits = 0;
    int idx = 0;

    for (int i = 0; i < num_codes; i++) {
        buf = (buf << 9) | codes[i];
        bits += 9;
        while (bits >= 8 && idx < max_out) {
            bits -= 8;
            out[idx++] = (uint8_t)((buf >> bits) & 0xFF);
            buf &= (1ULL << bits) - 1;
        }
    }

    if (idx < 4) return -1;

    int length = (int)(
        ((uint64_t)out[0] << 24) |
        ((uint64_t)out[1] << 16) |
        ((uint64_t)out[2] <<  8) |
         (uint64_t)out[3]);

    if (length < 0 || length > max_out - 4) return -1;

    return length;
}

/* ---------- Public API ---------- */

SCAR_API ScarCtx *scar_key_schedule(
    const uint16_t *swap_map,
    const uint16_t *shift_vals,
    const int8_t  *shift_ops,
    int rounds)
{
    ScarCtx *ctx = (ScarCtx *)calloc(1, sizeof(ScarCtx));
    if (!ctx) return NULL;

    memcpy(ctx->swap, swap_map, 513 * sizeof(uint16_t));

    for (int i = 0; i < 513; i++)
        ctx->inv_swap[ctx->swap[i]] = (uint16_t)i;

    memcpy(ctx->shift_vals, shift_vals, 16 * sizeof(uint16_t));
    memcpy(ctx->shift_ops, shift_ops, 16 * sizeof(int8_t));
    ctx->rounds = rounds;

    return ctx;
}

SCAR_API void scar_free_ctx(ScarCtx *ctx) {
    free(ctx);
}

SCAR_API size_t scar_encrypt(
    const uint8_t *in_buf, size_t in_len,
    ScarCtx *ctx,
    uint8_t *out_buf, size_t out_buf_len)
{
    /* Encode input into base-512 codes, then pad to block boundary */
    int max_codes = (int)((in_len + 4) * 8 / 9) + 2;

    uint16_t *raw = (uint16_t *)malloc(max_codes * sizeof(uint16_t));
    if (!raw) return 0;

    int raw_codes = scar_bin_to_codes(in_buf, (int)in_len, raw, max_codes);

    int pad = (SCAR_BLOCK_LEN - (raw_codes % SCAR_BLOCK_LEN)) % SCAR_BLOCK_LEN;
    int total_codes = raw_codes + pad;
    int num_blocks = total_codes / SCAR_BLOCK_LEN;

    if ((size_t)(total_codes * 3 + 1) > out_buf_len) {
        free(raw);
        return 0;
    }

    uint16_t *blocks = (uint16_t *)malloc(num_blocks * SCAR_BLOCK_LEN * sizeof(uint16_t));
    if (!blocks) { free(raw); return 0; }

    memcpy(blocks, raw, raw_codes * sizeof(uint16_t));
    for (int i = raw_codes; i < total_codes; i++)
        blocks[i] = 0;

    scar_encrypt_blocks(blocks, num_blocks, ctx);

    /* Encode codes back to UTF-8 characters */
    int out_pos = 0;
    for (int i = 0; i < total_codes && out_pos < (int)out_buf_len - 1; i++) {
        uint16_t code = blocks[i];
        const uint8_t *utf8 = scar_inv_utf8 + code * 3;
        uint8_t len = scar_inv_utf8_len[code];
        if (out_pos + (int)len >= (int)out_buf_len) break;
        memcpy(out_buf + out_pos, utf8, len);
        out_pos += len;
    }
    out_buf[out_pos] = '\0';

    free(blocks);
    free(raw);
    return (size_t)out_pos;
}

SCAR_API size_t scar_decrypt(
    const uint8_t *in_buf, size_t in_len,
    ScarCtx *ctx,
    uint8_t *out_buf, size_t out_buf_len)
{
    int max_codes = (int)in_len;
    uint16_t *blocks = (uint16_t *)malloc(max_codes * sizeof(uint16_t));
    if (!blocks) return 0;

    /* Decode UTF-8 characters back to codes */
    int code_count = 0;
    int pos = 0;
    while (pos < (int)in_len && code_count < max_codes) {
        uint8_t b = in_buf[pos];
        uint8_t len;
        if ((b & 0x80) == 0) len = 1;
        else if ((b & 0xE0) == 0xC0) len = 2;
        else if ((b & 0xF0) == 0xE0) len = 3;
        else if ((b & 0xF8) == 0xF0) len = 4;
        else { pos++; continue; }

        if (pos + (int)len > (int)in_len) break;

        uint16_t code = scar_char_to_code(in_buf + pos, len);
        blocks[code_count++] = code;
        pos += len;
    }

    int pad = (SCAR_BLOCK_LEN - (code_count % SCAR_BLOCK_LEN)) % SCAR_BLOCK_LEN;
    for (int i = code_count; i < code_count + pad; i++)
        blocks[i] = 0;

    int num_blocks = (code_count + pad) / SCAR_BLOCK_LEN;

    scar_decrypt_blocks(blocks, num_blocks, ctx);

    int bytes_written = scar_codes_to_bin(blocks, code_count + pad, out_buf, (int)out_buf_len);

    free(blocks);

    if (bytes_written < 0) return 0;

    if (bytes_written > 0) {
        memmove(out_buf, out_buf + 4, (size_t)bytes_written);
    }

    return (size_t)bytes_written;
}
