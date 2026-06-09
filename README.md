# QuadraCrypt

A four layer encrypted container with a Tkinter GUI. Files are protected by a cascade of four independent ciphers **Kuznyechik → Serpent → Camellia → SCAR** — each with its own independently derived key, making the container secure even if any single cipher is broken or several.

---

## Features

- **Four layer encryption cascade** — Kuznyechik (GOST), Serpent, Camellia, and SCAR applied in sequence
- **Per-cipher key derivation** — each cipher gets its own key derived through a unique KDF chain (SHA-3, Streebog, PBKDF2, 3DPCC), so keys are never shared or reused
- **RAM disk support** — decrypted files are written to `/dev/shm` (Linux) or a RAM disk drive (Windows) to avoid touching persistent storage; falls back to a system temp folder if none is available
- **Parallel encryption** — files inside a container are encrypted concurrently using all available CPU cores
- **Toggleable cipher layers** — Kuznyechik, Serpent, and the Streebog KDF steps can be individually disabled from the GUI; Camellia and SCAR are always active
- **Self describing containers** — the toggle state used at creation time is stored in the container header so opening always uses the correct configuration automatically
- **Cross-platform** — works on Windows and Linux

---

## Requirements

### Python dependencies

```bash
pip install taigae2ee pycryptodome cryptography
```

| Package | Purpose |
|---|---|
| `pycryptodome` | PBKDF2 / SHA-512 HMAC |
| `cryptography` | Camellia cipher |
| `taigae2ee` / `gostcrypto` | Streebog-512 hash (GOST R 34.11-2012) |

### Compiled shared libraries

The Kuznyechik and Serpent ciphers are backed by compiled C libraries for performance. Place these next to `Main.py` before running.

**Kuznyechik:**

| Platform | Expected filename |
|---|---|
| Windows | `Kuznechik_Fast.dll` |
| Linux | `Kuznechik_Fast.so` or `libKuznechik_Fast.so` |

```bash
# Linux
gcc -O2 -shared -fPIC -o Kuznechik_Fast.so Kuznechik_Fast.c

# Windows (MSVC)
cl /LD /O2 Kuznechik_Fast.c /Fe:Kuznechik_Fast.dll

# Windows (MinGW)
gcc -O2 -shared -o Kuznechik_Fast.dll Kuznechik_Fast.c
```

**Serpent:**

| Platform | Expected filename |
|---|---|
| Windows | `Serp.dll` |
| Linux | `Serp.so` or `libSerp.so` |

```bash
# Linux
gcc -O2 -shared -fPIC -o Serp.so Serp.c

# Windows (MSVC)
cl /LD /O2 Serpent_Fast.c /Fe:Serp.dll

# Windows (MinGW)
gcc -O2 -shared -o Serp.dll Serp.c
```

### Additional data file

`512.json` must be present in the same directory. This file defines the SCAR cipher's Base-512 symbol map (513 entries).

---

## Directory layout

```
project/
├── Main_V3_1.py               # Main application
├── 512.json              # SCAR symbol map
├── Kuznechik_Fast.c      # Kuznyechik C source
├── Serp.c        # Serpent C source
```

---

## Usage

```bash
python Main_V3_1.py
```

### Creating a container

1. Click **Create** and choose a save location and password.
2. The app opens a working folder on the RAM disk and shows its path in the status bar.
3. Copy the files you want to encrypt into that folder.
4. Click **Encrypt** — the container is written to the path you chose.

### Opening a container

1. Click **Open**, select a `.enc` file, and enter the password.
2. The file list populates with all files stored inside.
3. Double-click any file to decrypt it to the RAM disk and open it with the default application.

### Extracting files

Select one or more files in the list and click **Extract** to decrypt them to the RAM disk folder without opening them.

### Re-encrypting / saving

Click **Re-encrypt & Save** to save a new container from the current RAM disk contents. You will be prompted for a password and a save path. The RAM disk is cleared afterward.

### Removing files from a container

Select a file in the list and click **Remove**, then re-encrypt to apply the change.

### Renaming files

Select a file, click **Rename**, enter the new name, then re-encrypt to apply.

### Clearing the RAM disk

Click **Clear RAM** to securely wipe all decrypted files from the working folder.

---

## Cipher architecture

Encryption is applied in this order (decryption reverses it):

```
Plaintext
    │
    ▼  Kuznyechik-CTR  (GOST R 34.12-2015, 256-bit key)   [optional]
    │
    ▼  Serpent-CTR     (256-bit key)                        [optional]
    │
    ▼  Camellia-CTR    (256-bit key)                        [always on]
    │
    ▼  SCAR            (Base-512 substitution-permutation)  [always on]
    │
Ciphertext (stored as UTF-8 text)
```

Each cipher's IV is derived deterministically from its key, the filename, and a per-cipher context tag, so no IVs need to be stored in the container.

### Key derivation

Each cipher gets an independent key derived from the password through a unique permuted KDF chain:

| Cipher | KDF chain (default) |
|---|---|
| Kuznyechik | SHA-3 → Streebog → PBKDF2 → 3DPCC |
| Serpent | Streebog → PBKDF2 → 3DPCC → SHA-3 |
| Camellia | PBKDF2 → 3DPCC → SHA-3 → Streebog |
| SCAR | 3DPCC → SHA-3 → Streebog → PBKDF2 |

When the Streebog KDF toggle is disabled, Streebog steps are removed from all chains and iteration counts are unchanged.

---

## How SCAR works

SCAR (Swap-Convert-Adjust-Repeat) is a custom symmetric cipher that operates on text rather than raw bytes. Instead of working in binary, it encodes data into a 513-symbol alphabet (Base-512) and then applies multiple cryptographic transformations per round over 5 rounds by default(64-4096 recommended but slow).

### Base-512 encoding

Binary data is first converted to Base-512: every 9 bits of input map to one symbol from the 513-character alphabet defined in `512.json`. This alphabet uses Unicode characters, so the ciphertext is valid UTF-8 text that can be stored and transmitted anywhere a string can.

### Per-round operations

Each of the 5 rounds applies four operations in sequence to 16-symbol blocks:

**1. Substitution (Swap)**
Every symbol index in the block is replaced using a key-derived permutation table that maps each of the 513 possible values to a different one. This is the S-box equivalent — a full bijection over the symbol domain, so every input maps to a unique output.

**2. Shift**
Each position in the block has its own key-derived shift value and direction (+ or −). The symbol index at position `i` is shifted by `shift_values[i]` modulo 513, either added or subtracted depending on `shift_ops[i]`. This is analogous to a Vigenère step but in Base-512 space.

**3. Rotation**
The block is rotated left by `round + 3` positions. This is round-dependent, so the same block at different rounds rotates by a different amount, preventing simple structural patterns from persisting across rounds.

**4. Diffusion**
A chained diffusion pass runs through the block in triplets. For each group `(a, b, c)`, a new value for `c` is computed as `(c + |a − b| + stack) % 513`, where `stack` carries forward the previous output. This makes every symbol dependent on all symbols before it within the block, spreading local changes across the entire block.

Decryption reverses all four steps in reverse order across all rounds: inverse diffusion → rotate right → inverse shift → inverse substitution.

### Key material

All SCAR parameters — the substitution table and the per-position shift values and directions — are derived from the SCAR cipher key using a seeded PRNG (`random.Random`). The key itself is produced by SCAR's KDF chain just like the other ciphers, so the entire structure is password-dependent.

---

## How 3DPCC works

3DPCC (3D Parametric Curve Cryptography) is a custom KDF step that generates a 64-byte output from an input seed using a chaotic dynamical system. It is designed to be computationally expensive and highly sensitive to small differences in the input — a single bit change in the seed produces a completely different output after the full iteration.

### Initialisation

The seed is first hashed with SHA3-512. The first 24 bytes of that hash are used to initialise three floating-point coordinates `(x, y, z)` inside a 1000³ unit cube, and a phase parameter `t` is set to `(x + y + z) mod (20π)`.

### Iteration

The system runs for a configurable number of rounds (3,000,000 when used as a KDF step). Each round:

1. A combined value `xyz_i = x + y + z + i` selects a step type (0–3) and a step size.
2. Depending on the step type, `t` is advanced using the derivative of one of three parametric curves driven by frequencies 53.0, 40.7, and 20.2:
   - **Type 0** — advances `t` proportionally to the 3D speed along all three curve axes simultaneously
   - **Types 1–3** — advances `t` by the step size divided by the derivative of one axis, alternating direction each iteration
3. `t` is wrapped to `[0, 200π)`, then all three coordinates are recomputed from `t`:

```
x = (sin(53.0 × t) + 1) × 500
y = (cos(40.7 × t) + 1) × 500
z = (sin(20.2 × t) + 1) × 500
```

The three irrational frequencies (53.0, 40.7, 20.2) are incommensurate, meaning the trajectory never exactly repeats. Small differences in the starting `t` compound rapidly across millions of iterations, giving the function its avalanche-like sensitivity.

### Output

After all iterations, `x`, `y`, and `z` are scaled to integers and packed into 24 bytes, then passed through SHA3-512 to produce the final 64-byte output. The final hash step ensures the output is uniformly distributed regardless of where in the cube the trajectory ended.

---

## RAM disk behaviour

| Platform | RAM disk location | Detection method |
|---|---|---|
| Linux | `/dev/shm/enc_container_<random>/` | Always available (tmpfs) |
| Windows | `R:\`, `V:\`, or `Z:\` (first found) | Directory existence check |
| Windows (override) | `ENCRYPTED_CONTAINER_RAMDISK` env var | Environment variable |
| Fallback (any) | System temp directory | Used when no RAM disk found |

On Linux, `/dev/shm` is a tmpfs mount backed entirely by RAM — data there does not survive a reboot and is never written to disk. On Windows, a third-party RAM disk tool (e.g. ImDisk, OSFMount) must create one of the candidate drives beforehand.

---

## Container file format

`.enc` files have the following binary layout:

```
[ 8 bytes ] Unencrypted header length (big-endian uint64)
[ N bytes ] Unencrypted header JSON  {"version": "V3.1"}
[ 8 bytes ] Encrypted header length  (big-endian uint64)
[ M bytes ] Encrypted header JSON    (all four cipher layers always active)
[ ...     ] Encrypted file blobs     (one per file, toggles from header)
```

The encrypted header contains the file table (names, offsets, sizes) and the toggle state active at creation time. The header is always encrypted with all four layers on so it can always be read regardless of which toggles were active for the file blobs.

---

## Troubleshooting

**`Kuznyechik shared library not found`** — compile `Kuznechik_Fast.c` and place the output next to `Main_V3_1.py`. See the compile commands above.

**`Serpent shared library not found`** — same as above for `Serp.c`.

**`Failed to decode container header. Wrong password...`** — either the password is incorrect, or the container was created with an older incompatible version of the app and needs to be re-created.

**`No RAM disk detected`** — on Windows, install a RAM disk tool and create a drive at `R:\`, `V:\`, or `Z:\`, or set the `ENCRYPTED_CONTAINER_RAMDISK` environment variable to your RAM disk path. On Linux this should not occur since `/dev/shm` is always present.

**`taigae2ee` install fails** — try `pip install gostcrypto` directly; `taigae2ee` bundles it but the standalone package also works.
