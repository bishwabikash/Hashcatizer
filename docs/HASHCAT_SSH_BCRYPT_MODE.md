# Design: GPU hash mode for OpenSSH bcrypt-pbkdf private keys

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
        Blowfish_expand0state(state, sha2pass)
        Blowfish_expand0state(state, sha2salt)
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

The genuinely new work is the SHA-512 glue around `bcrypt_hash`, the outer
round loop, and the verification step — not the Blowfish core.

## Kernel structure

Standard slow-hash split (`ATTACK_EXEC_OUTSIDE_KERNEL`):

| Kernel | Work |
|---|---|
| `_init` | `SHA512(pass)`, `SHA512(salt \|\| BE32(1))`, seed `tmp_t` |
| `_loop` | one outer round per invocation: `bcrypt_hash` + `SHA512` + XOR accumulate |
| `_comp` | AES-256-CTR decrypt the private blob, compare the two check integers |

`module_kernel_loops_min/max` map to the `rounds` value from the hash line, so
hashcat's autotuner splits the outer loop the way it does for `-m 3200`'s cost
factor.

`tmp_t` carries: `pass_hash[8]` (u64), `salt_hash[8]`, `out[8]` (u32), `tmp[8]`,
plus the Blowfish state when it cannot stay in shared memory.

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

Per `docs/hashcat-plugin-development-guide.md`:

1. `src/modules/module_NNNNN.c` — parser, encoder, `module_init`
2. `OpenCL/mNNNNN-pure.cl` — init/loop/comp kernels
3. An entry in `tools/test_modules/mNNNNN.pm` for the test suite
4. An example hash — this is what `--example-hashes` prints, and what
   downstream tooling (including this project) verifies against
5. `docs/changes.txt` entry

## Validation plan

1. Generate keys with `ssh-keygen -t ed25519/rsa/ecdsa -N <pass>` at several
   `-a` round counts (16 default, plus 8 and 64).
2. Extract with `hashcatizer ssh`, cross-checked against `ssh2john.py`.
3. Confirm john cracks them, establishing ground truth independent of the new
   kernel.
4. Build a CPU reference with the `bcrypt-pbkdf` crate to produce known
   intermediate values — the Rust bridge (`-m 74000`) is a convenient host for
   this, since it can run the reference inside hashcat's own pipeline and
   compare against the GPU kernel candidate-for-candidate.
5. `hashcat -m NNNNN --self-test-disable` against the fixtures, then with
   self-test enabled once the example hash is in place.

Step 4 is where the bridge earns its place: not as the shipping implementation,
but as an oracle that runs in-process against the kernel under development.
