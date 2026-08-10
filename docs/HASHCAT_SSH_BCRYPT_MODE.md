# Design: GPU hash mode for OpenSSH bcrypt-pbkdf private keys

> **Status: implemented and working as `-m 37500`**, on a local hashcat branch,
> not yet submitted upstream. Measured 592 H/s on an RTX 4050. Self-test passes;
> ed25519 (rounds 8/16/64), RSA-2048 and ECDSA-256 recover across both
> `aes256-ctr` and `aes256-cbc`. See [Implementation notes](#implementation-notes)
> at the end for what the design below got wrong.

Target: a real OpenCL/CUDA/HIP/Metal kernel, not a CPU bridge. The v7
Assimilation Bridge (`-m 74000` Rust, `-m 72000/73000` Python) can express this
algorithm in a few lines, but it runs on CPU only — it is useful for generating
and checking test vectors, not for cracking.

## Why this mode

`ssh-keygen` has written the `openssh-key-v1` container with bcrypt-pbkdf key
derivation by default since OpenSSH 7.8 (2018). hashcat's `-m 22911-22951`
handle only legacy PEM keys with the MD5-based KDF, so **every SSH private key
generated with default options today is uncrackable in hashcat.** john has
supported the format for years, which means a settled specification and a
reference implementation to check against.

## Algorithm

```
bcrypt_pbkdf(pass, salt, rounds) -> key:
    pass_hash = SHA512(pass)                        # once, outside the loop
    for block i = 1, 2, ...:
        salt_hash = SHA512(salt || BE32(i))
        out = bcrypt_hash(pass_hash, salt_hash)
        tmp = out
        for j in 1..rounds:
            tmp = bcrypt_hash(pass_hash, SHA512(tmp))
            out ^= tmp
        scatter out into key
```

`bcrypt_hash(sha2pass, sha2salt)` is where all the cost lives:

```
    Blowfish_initstate(state)
    Blowfish_expandstate(state, sha2salt[64], sha2pass[64])
    for i in 1..64:
        Blowfish_expand0state(state, sha2salt)      # salt first -- see below
        Blowfish_expand0state(state, sha2pass)
    cdata = "OxychromaticBlowfishSwatDynamite"       # 32 bytes, 8 u32 words
    for i in 1..64:
        blf_enc(state, cdata, 4)                     # 4 two-word blocks
    output 32 bytes, little-endian
```

Work per candidate is `rounds x 128` key expansions. `ssh-keygen` defaults to
16 rounds, so ~2048 expansions — roughly bcrypt cost factor 11, i.e. the same
order of magnitude per guess as `-m 3200` at `$2b$11$`.

## What can be reused

- `OpenCL/inc_cipher_blowfish.cl` / `.h` — Blowfish P-array and S-box
  primitives already in the tree.
- `OpenCL/m03200-pure.cl` — the existing bcrypt kernel is the structural
  template. Its S-box residency strategy is the part that matters most;
  bcrypt-pbkdf has identical memory behaviour because it is the same primitive.
- `src/modules/module_03200.c` — module scaffold, in particular
  `OPTS_TYPE_DYNAMIC_SHARED` and the `module_extra_buffer_size` /
  `module_kernel_threads_*` logic that manages S-box residency.

**Correction to the above, from reading the primitives rather than assuming.**
"Just add SHA-512 glue" was too optimistic. What is actually reusable:

| Primitive | Reusable? |
|---|---|
| `blowfish_encrypt()` — the 521-encryption rekey core | **yes**, this is `expand0state`'s body |
| `c_pbox` / `c_sbox0..3` constants | **yes**, for `Blowfish_initstate` |
| `blowfish_set_key_salt()` | **no** — see below |
| `blowfish_set_key()` | **no** — re-initialises state on entry |

`blowfish_set_key_salt()` hardcodes a **4-word (16-byte) salt**: it indexes
`salt_buf[(i & 2) + 0]`, and its S-box loops reference `salt_buf[0..3]`
literally. bcrypt-pbkdf's `Blowfish_expandstate` takes a **64-byte
`sha2salt`** — 16 words, cycling over all of them. The existing helper cannot
express that, so `expandstate` needs a 16-word variant written for this mode.

Both `set_key` helpers also re-initialise P and the S-boxes on entry, which is
correct for the single `expandstate` call but wrong for the 128 `expand0state`
calls that follow — those must mutate the *existing* state. `-m 3200` handles
this by writing the expand0state step inline in its loop
(`P[i] ^= E[i]; blowfish_encrypt(...)`), and this mode should do the same.

So the new work is: a 16-word-salt `expandstate`, the inline `expand0state`
loop, SHA-512 glue, the two-block outer loop, and verification.

## Kernel structure

Standard slow-hash split (`ATTACK_EXEC_OUTSIDE_KERNEL`):

| Kernel | Work |
|---|---|
| `_init` | `SHA512(pass)`, `SHA512(salt \|\| BE32(1))`, seed `tmp_t` |
| `_loop` | one outer round per invocation: `bcrypt_hash` + `SHA512` + XOR accumulate |
| `_comp` | AES-256 decrypt the first ciphertext block, compare the two check integers |

`module_kernel_loops_min/max` map to the `rounds` value from the hash line, so
hashcat's autotuner splits the outer loop the way it does for `-m 3200`'s cost
factor.

`tmp_t` does **not** carry the Blowfish state, unlike `-m 3200`'s
`bcrypt_tmp_t`: bcrypt's loop is resumable across invocations, but every
`bcrypt_hash()` here rebuilds the state from scratch and discards it.

As built, it carries less than the sketch above assumed. Because a
`bcrypt_hash()` cannot be split across invocations (correction 1 below), the
whole derivation runs inside a single `_loop`, so the round accumulator never
has to survive a kernel boundary — only the finished key does:

```c
typedef struct sshng_bcrypt_tmp
{
  u32 pass_hash[16];   // SHA-512 of the password
  u32 dk[12];          // derived 48 bytes: 32 byte AES key + 16 byte IV
} sshng_bcrypt_tmp_t;  // 112 bytes, against 192 for the resumable design
```

Two corrections found while building the module, both of which change the cost
model above:

1. **A `bcrypt_hash()` cannot be split across invocations**, so `kernel_loops`
   is pinned at 1 and hashcat runs one invocation per round.
2. **A 48-byte key needs two blocks, not one** (`stride = 2`), and each runs the
   full round loop — so the real work is `2 x rounds` bcrypt_hash calls, double
   the naive estimate. The two chains are independent and can be interleaved.

So `salt_iter = 1` and the whole derivation runs in `_loop`. This was planned as
a first step to be split up later, but correction 1 makes it the permanent
shape: there is no finer granularity to split into.

### Occupancy

Blowfish needs 4 KB of S-boxes per work item. This is the binding constraint on
bcrypt and it applies unchanged here — expect `-m 3200`-like thread counts and
the same `OPTS_TYPE_DYNAMIC_SHARED` handling. There is no way around it; it is
what bcrypt was designed to cost.

## Hash line format

Reuse john's `$sshng$` encoding so the existing extractors work unmodified.
Hashcatizer already emits it (`src/converters/ssh.rs`), verified byte-identical
to `ssh2john.py` across RSA, ECDSA and Ed25519 keys:

```
$sshng$6$16$<salt>$<datalen>$<data>$<rounds>$<ciphertext_offset>
```

Eight tokens, versus six for the legacy PEM form — that token count is how the
module distinguishes them, so a new mode number can coexist with `-m 22921`
rather than complicating its parser.

- cipher id `6` = aes256-ctr, `2` = aes256-cbc (both occur)
- `data` is the whole `openssh-key-v1` blob
- `ciphertext_offset` locates the encrypted section within it

## Verification

Decrypt 16 bytes at `ciphertext_offset` with the derived key/IV and compare the
two 32-bit check integers, which OpenSSH writes equal before encryption:

```
checkint1 == checkint2   ->   candidate accepted
```

False-positive rate 2^-32 per guess — the same criterion OpenSSH itself uses.
For a single target that is acceptable; `-m 22921` and john behave identically.
A second-stage confirmation (parse the decrypted key type string) can be added
in `_comp` if a zero-false-positive guarantee is wanted.

Key/IV split from the 48 bytes of KDF output: first 32 bytes key, next 16 IV.

## Deliverables for the PR

Per `docs/hashcat-plugin-development-guide.md`: the module, the kernel, a
`tools/test_modules/` entry, an example hash for `--example-hashes`, and a
`docs/changes.txt` line. Current state of each is in the
[status table](#deliverables-status) below.

## Validation — what was actually done

1. Keys generated with `ssh-keygen -t ed25519/rsa/ecdsa` at `-a 8`, `16` and
   `64`, across `aes256-ctr` and `aes256-cbc`.
2. Extracted with `hashcatizer ssh`, cross-checked against `ssh2john.py`.
3. john cracked them, establishing ground truth independent of the new kernel.
4. A Rust CPU oracle (`bcrypt-pbkdf` crate) printed the derived key and IV. This
   is what localised both endianness bugs: the kernel was instrumented to dump
   the same intermediates and diffed against it, which separated "the KDF is
   wrong" from "the verification is wrong" in one run each.
   
   The Assimilation Bridge was *not* used for this after all — a standalone
   binary was simpler than running a reference inside hashcat's pipeline.
5. `hashcat -m 37500` against the fixtures with `--self-test-disable`, then with
   the self-test enabled once a real example hash was in place. All 5 keys
   recover; a wrong password recovers none; every cracked line re-encodes
   byte-identical to its input.

## Implementation notes

What the design above got right: the algorithm breakdown, the reusable-primitive
table, `stride = 2`, pinning `kernel_loops` at 1, and the cost estimate (583 H/s
predicted, 592 H/s measured).

What it did not anticipate — both are byte-order traps in hashcat's own
helpers, and both produce a plausible-looking wrong answer rather than an error:

**1. `hex_to_u32()` packs little-endian.** For `"2acfa730"` it returns
`0x30a7cf2a`, not `0x2acfa730`. The kernel feeds `salt_buf` straight into
`sha512_update()`, which reads big-endian packed, so every salt word reached
SHA-512 byte-reversed and the derived key was wrong from the first block.
`u32_to_hex()` is its exact inverse, so a `byte_swap_32()` is needed on both
sides — and note that this makes the *encoder* correct only once the decoder is
also swapped; the two bugs had been cancelling in neither direction.

**2. hashcat has two AES APIs and they disagree.** `AES256_set_encrypt_key()`
swaps, then calls `aes256_set_encrypt_key()` which swaps again — net no swap, so
the uppercase form wants **big-endian**. But `aes256_encrypt()` swaps its input
only once, so the lowercase form wants **little-endian**. Mixing
`AES256_set_encrypt_key()` with `aes256_encrypt()` silently byte-reverses the
IV. Use the uppercase pair throughout.

**Debugging note.** hashcat's autotune runs candidates whose "password" is HMAC
padding (`0x5c5c5c5c` / `0x36363636`). Any `printf` in a kernel fires for those
too. Reading their output as the real candidate leads to chasing a SHA-512 that
was never wrong — gate debug output on a known digest word.

### Verification

Three independent implementations of bcrypt-pbkdf agree byte-for-byte on the
derived key: a Rust CPU oracle (`bcrypt-pbkdf` crate), the CUDA kernel, and the
pure-Perl one in `tools/test_modules/m37500.pm`. Cross-checked in both
directions — hashcat cracks Perl-generated hashes, and the Perl module verifies
every key the GPU cracked. A wrong password neither cracks nor verifies.

### Deliverables status

| Item | State |
|---|---|
| `src/modules/module_37500.c` | done |
| `OpenCL/m37500-pure.cl` | done, CTR and CBC |
| `tools/test_modules/m37500.pm` | done, pure-Perl bcrypt-pbkdf |
| Example hash (`ST_HASH`/`ST_PASS`) | done, real `ssh-keygen` key, self-test passes |
| `docs/changes.txt` | done |
| Upstream PR | not raised |

### Note on upstreaming

hashcat's README asks that a bug fix have an issue open before the pull request,
and that each PR solve one problem. That splits this work into separate
submissions: the `-m 37500` mode, the unrelated `$PEM$2` parser fix for
`-m 24420`, and — if it is ever wanted as shared code — a 16-word-salt
`expandstate` for `inc_cipher_blowfish.cl`, which this mode currently keeps
local to its own kernel.
