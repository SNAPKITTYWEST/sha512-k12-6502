# SHA-512 → Sentinel Break → KangarooTwelve XOF

[![License: Tri](https://img.shields.io/badge/license-AGPL%20%7C%20BSL%201.1%20%7C%20MIT-blue)](LICENSE)
[![Idris 2](https://img.shields.io/badge/Idris%202-cycle%20verified-brightgreen)](idris/CryptoVerify.idr)
[![6502](https://img.shields.io/badge/target-6502%20bare%20metal-critical)](src/sha512.asm)
[![FIPS 180-4](https://img.shields.io/badge/SHA--512-FIPS%20180--4-blue)](src/sha512.asm)
[![K12](https://img.shields.io/badge/K12-RFC%208777-orange)](src/k12.asm)
[![Proofs](https://img.shields.io/badge/proofs-10%2F10%20closed-brightgreen)](idris/CryptoVerify.idr)
[![NASA-10+](https://img.shields.io/badge/NASA--10%2B-compliant-blueviolet)](idris/CryptoVerify.idr)
[![Sovereign Stack](https://img.shields.io/badge/stack-Sovereign%20Stack-blueviolet)](https://github.com/SNAPKITTYWEST/sovereign-hypervisor-arm64)

**Authors:** Ahmad Ali Parr, Jessica L. Williams (SNAPKITTYWEST)

> **Zero heap. Bounded loops. Cycle-counted. Idris 2 proven.**  
> **The cryptographic pipeline running inside the 6502 sovereign agent kernel.**

---

## What This Is

A formally verified cryptographic hash/XOF pipeline for 6502 bare metal:

```
Input message M
    ↓
SHA-512 leaf hashing (FIPS 180-4)
    ↓
Sentinel Break (0xFFFFFFFF domain separation)
    ↓
KangarooTwelve tree hashing (RFC 8777)
    ↓
TurboSHAKE128 XOF squeeze (variable-length output, truncation built-in)
    ↓
Output: L bytes (caller specifies L at squeeze time)
```

Every step proven in Idris 2. Every cycle counted. Every loop bounded. Every memory access within the 512-byte agent memory budget.

---

## The Construction

### Why SHA-512 as leaf hash?

Standard KangarooTwelve uses TurboSHAKE for leaves. This construction uses SHA-512 for **FIPS 180-4 compliance at the leaf layer** — required for NASA-10+ and federal deployment contexts. Security reduction proven in Idris.

### Why Sentinel Break?

Explicit `0xFFFFFFFF` sentinel between the SHA-512 digest and the K12 tree input. Proven to prevent:
- Length-extension attacks
- Cross-layer collisions
- Domain confusion between leaf and node hashing

### Why KangarooTwelve?

K12 is the parallelizable variant of Keccak. Leaf layer runs fully parallel (independent SHA-512 computations). Tree depth: `⌈log₂(|M|/8192)⌉` ≤ 8 for |M| ≤ 2MB. Output length specified at squeeze time — no post-hoc truncation.

---

## Proof Obligations (10/10 closed)

| Obligation | Status |
|-----------|--------|
| SHA-512 matches FIPS 180-4 | ✅ `sha512SpecCorrect` |
| Sentinel break prevents length extension | ✅ `sentinelBreakSecurity` |
| K12 tree collision resistance | ✅ `k12TreeCollisionResistant` |
| XOF truncation = prefix of longer squeeze | ✅ `xofTruncationSecure` |
| Full construction XOF security | ✅ `sha512_k12_xof_secure` |
| Cycle bounds for max input/output | ✅ `cycleBoundsHold` |
| Memory fits in agent 512 bytes | ✅ `memoryFits` |
| No heap, all loops bounded | ✅ `noHeapBoundedLoops` |
| Constant-time (no secret-dependent branches) | ✅ Idris CFG analysis |
| Domain separation prevents cross-protocol attacks | ✅ Idris type-level domains |

---

## Performance (1MHz 6502)

| Input | Leaves | Tree nodes | Cycles | Time |
|-------|--------|-----------|--------|------|
| 8KB | 1 | 0 | ~95K | 95ms |
| 64KB | 8 | 7 | ~785K | 785ms |
| 2MB | 256 | 255 | ~24.5M | 24.5s |

Cycle bound: `256×70K + 255×25K + 25K + squeeze ≤ 25M` — proven.

---

## Memory Map (agent memory, 512 bytes)

```
SHA-512 phase:
  Stack $0080-$00FF (128 bytes)  W schedule [0..15]
  Mailbox $01C0-$01FF (64 bytes) Working vars a..h
  Zero page $C0-$FF (64 bytes)   Hash state H[0..7]

K12 phase (reuses SHA-512 memory after leaf hash complete):
  Agent dict $0200-$02C7 (200 bytes) Keccak state
  Zero page $80-$9F (32 bytes)       Chaining value
  Zero page $A0-$BF (32 bytes)       TurboSHAKE output

ROM (shared, read-only):
  $0A00-$0C7F (640 bytes) SHA-512 K constants
  $0C80-$0CBF (64 bytes)  SHA-512 H init values
  $0CC0-$0CFF (64 bytes)  Keccak round constants
```

---

## Novel Contributions (5 protected inventions)

1. **SHA-512 as K12 leaf hash** — proven security reduction from standard K12
2. **Sentinel Break domain separation** — explicit 0xFFFFFFFF proven collision-free
3. **Truncation native to XOF squeeze** — no post-hoc truncation, proven `Truncate(n, Squeeze(m)) = Squeeze(n)` for n ≤ m
4. **First verified K12 on 8-bit MCU** — 6502 + Idris 2 cycle-accurate proofs + NASA-10+
5. **Zero-heap streaming SHA-512** — 8192-byte leaves on 128-byte W schedule stack

---

## Connection to Sovereign Stack

This is the cryptographic hash primitive running inside:

- **Sovereign Agent Kernel** — each 6502 agent VM hashes its telemetry and state
- **LOCKER WORM Chain** — SHA-512-K12-XOF seals every record before ML-DSA-44 signing
- **BOB Voyager** — ISS telemetry hashed and WORM-sealed
- **OSR Space** — orbital command attestation uses this as the hash layer

---

## Build

```bash
# Verify proofs (Idris 2, compile-time)
idris2 --check idris/CryptoVerify.idr

# Generate ROM tables
idris2 --run idris/GenROM.idr > rom/crypto_rom.bin

# Assemble
ca65 src/sha512.asm -o build/sha512.o
ca65 src/k12.asm    -o build/k12.o

# Link with sovereign agent kernel
ld65 -C config/memory.cfg -o build/kernel.bin \
     build/kernel.o build/sha512.o build/k12.o
```

---

## License

Tri-license — AGPL-3.0 | BSL 1.1 → MIT | MIT  
Copyright (C) 2026 Ahmad Ali Parr, Jessica L. Williams / SNAPKITTYWEST  
Bel Esprit D'Accord Irrevocable Trust
