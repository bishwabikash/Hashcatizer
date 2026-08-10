# Cracking modern OpenSSH private keys: measurements and attack economics

All numbers below are measured on this hardware, not estimated from spec
sheets:

- GPU: NVIDIA GeForce RTX 4050 Laptop (Ada, 20 SM), CUDA 13.3, hashcat v7.1.2
- CPU: 16 cores, John the Ripper 1.9.0-jumbo (OpenMP)
- Key: `ssh-keygen -t ed25519`, default `-a 16`, extracted with `hashcatizer ssh`

## 1. The KDF change is the whole story

OpenSSH 7.8 (2018) made `openssh-key-v1` with bcrypt-pbkdf the default private
key format. Before it, encrypted PEM keys derived their key with **one MD5**.

| Format | Tool | Measured rate |
|---|---|---|
| Legacy PEM (MD5 KDF) | hashcat `-m 22921`, RTX 4050 | **2,075,900,000 H/s** |
| OpenSSH bcrypt-pbkdf | john `--format=ssh`, 16 cores | **86.5 c/s** |

That is a factor of **24 million**. It is the largest single-change defensive
improvement in any format this project touches, and it is why the missing
hashcat mode matters: the formats hashcat *can* crack are the ones that barely
need cracking.

Practical consequence, same wordlist (rockyou, 14.3M candidates):

| | Legacy PEM on GPU | bcrypt-pbkdf on 16-core CPU |
|---|---|---|
| rockyou | 0.007 s | 46 hours |
| 8-char lowercase (26⁸) | ~100 s | ~76 years |

## 2. What `-a 16` actually costs, in bcrypt units

`bcrypt_hash()` performs 1 `ExpandKey` plus 64 iterations of two more, so
**129 ExpandKey calls**. Standard bcrypt at cost *c* performs 1 + 2^(c+1).

Deriving a 48-byte key (32 key + 16 IV) needs `stride = 2`, so **two
independent blocks**, each running the full round loop:

```
total = 2 blocks x 16 rounds x 129 ExpandKey = 4128
2^(c+1) = 4128  ->  c ≈ 11
```

**Default `ssh-keygen` is equivalent to bcrypt cost factor 11.** For comparison,
that is above OpenBSD's historical `/etc/passwd` default and roughly what
current guidance suggests for password storage — on a key most users never
consider a password-strength decision.

Cross-check against measurement: hashcat's `-m 3200` benchmark runs cost 5
(65 ExpandKey) at 36,994 H/s. Scaling by 4128/65 = 63.5 predicts **≈583 H/s**
for the SSH mode on this GPU.

The mode now exists, so that prediction can be checked rather than argued:

```
hashcat -b -m 37500 --backend-devices 1
Speed.#01........:      592 H/s (810.43ms) @ Accel:1 Loops:1 Thr:24 Vec:1
```

**592 H/s measured against 583 H/s predicted — within 1.5%.** The cost model in
section 2 is therefore sound, and the `2 x rounds x 129` ExpandKey figure it
rests on can be trusted for other round counts.

Against the measured CPU figure that is a **6.8x** speedup — not the 10,000x
that GPUs buy against fast hashes. That ratio is the honest case for the mode:
real, worth having, and modest. Anyone expecting bcrypt-pbkdf to fall over on a
GPU has misread the algorithm.

## 3. Why GPUs gain so little here — measured

hashcat autotuned `-m 3200` on this card to **`Thr:24`**. Twenty-four threads
per block, on a GPU that runs 1024.

Blowfish needs 4 KB of S-boxes per work item. Ada offers 100 KB of shared
memory per SM, capping residency at ~25 work items per SM regardless of the
5,888 CUDA cores present. The card behaves like a ~500-way parallel machine
instead of a ~6,000-way one.

bcrypt-pbkdf inherits this exactly — same primitive, same 4 KB, same ceiling.
No kernel-level cleverness removes it; it is the property bcrypt was designed
around in 1999 and it still holds against 2024 silicon.

## 4. Optimisations that do not work here

Worth recording, because each looks plausible until you check:

**Early reject on partial key material — impossible.** The natural trick is to
derive part of the key, test, and bail. Here the 48 output bytes are
interleaved: `key[i * stride + (count - 1)] = out[i]`. With `stride = 2`, AES
key bytes 0..31 come from `out[0..15]` of *both* blocks, and IV bytes 32..47
from `out[16..23]` of *both*. Verification needs the key and the IV, so it
needs every byte of both chains. There is no prefix to test against.

**Skipping the second block — impossible**, for the same reason. Both blocks
are mandatory. This doubles the work relative to a naive reading of
`bcrypt_pbkdf`, and it is the correction that matters most for anyone
estimating this mode's cost.

**Amortising the password hash across candidates — no.** `SHA512(password)` is
per-candidate by definition.

**Amortising across rounds — no.** `sha2salt` is re-derived from the previous
round's output each iteration, so the chain is strictly sequential.

What *does* help: the two blocks are **independent chains**. They can be
interleaved in one work item to hide latency, or split across two. That is the
one genuine parallelism gain available, and it is free — 2x the in-flight work
at no extra shared memory, since the Blowfish state is rebuilt per
`bcrypt_hash` and never persists.

## 5. Where the attack surface actually is

Given 592 H/s, brute force is finished as a strategy. What remains:

**`rounds` is attacker-visible and usually default.** The extractor emits it in
the hash. Values above 16 are rare, so cost is predictable before committing
GPU time — and worth checking first, since a key at `-a 64` costs 4x more and
may not be worth attacking at all.

**Key comments leak.** The `openssh-key-v1` blob carries the public key and
comment in cleartext, typically `user@host`. Hashcatizer already emits the full
blob, so the comment is available for targeted wordlist generation without any
cracking. At 592 H/s a 10,000-candidate targeted list runs in 17 seconds; a
generic 14M list takes 7 hours. Targeting is worth roughly three orders of
magnitude more than hardware here.

**Passphrase reuse.** The same passphrase usually protects several keys, and
often matches a password recovered from a faster format elsewhere in the same
engagement. Crack the cheap hash, try it against the key.

**Agent memory and unencrypted copies.** `ssh-agent` holds decrypted keys;
backups and VM images routinely contain `-a 0` copies. Both defeat the KDF
completely and cost nothing.

## 6. What this says about hashcat's coverage

Stock hashcat implements `-m 22911..22951` — MD5-KDF PEM keys, deprecated for
seven years, crackable at 2 GH/s. It has no kernel for the format `ssh-keygen`
produces by default.

The gap is not that hashcat is missing a fast target. It is that hashcat is
missing the *only* SSH key format still in use, and users reading
`--example-hashes` reasonably conclude their modern keys are covered when they
are not.

**This gap is now closed in a local branch**, not yet upstream: `-m 37500`
implements bcrypt-pbkdf as a real GPU kernel and recovers ed25519, RSA and
ECDSA keys across both `aes256-ctr` and `aes256-cbc`, at the 592 H/s measured
above. Until it is merged, Hashcatizer keeps telling the truth about stock
hashcat rather than printing a `-m` that a released build cannot run:

```
[!] OpenSSH bcrypt-pbkdf key — hashcat has no kernel for these; use john
[*] Crack with: john --wordlist=<wordlist> <hashfile>
```

Design, implementation notes and the two endianness defects that made the first
version derive a wrong key: [HASHCAT_SSH_BCRYPT_MODE.md](HASHCAT_SSH_BCRYPT_MODE.md).

## Reproducing

```bash
hashcat -b -m 3200 --backend-devices 1        # 36,994 H/s  (bcrypt cost 5)
hashcat -b -m 22921 --backend-devices 1       # 2,075.9 MH/s (legacy PEM)

ssh-keygen -q -t ed25519 -f k -N hashcat1
hashcatizer ssh k > k.hash                     # or ssh2john.py
time john --wordlist=wl.txt --format=ssh k.hash
```

The john run above also cracked the fixture key, which independently confirms
the `$sshng$` extraction: two implementations, same bytes, real recovery.
