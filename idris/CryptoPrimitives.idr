-- CryptoPrimitives.idr
-- Mathematical specification for SHA-512 → Sentinel Break → K12 XOF
-- Compile-time only. Zero runtime cost.
-- Authors: Ahmad Ali Parr, Jessica L. Williams (SNAPKITTYWEST)

module CryptoPrimitives

-- ── SHA-512 Constants (FIPS 180-4) ────────────────────────────────────────────

public export
SHA512_BLOCK_BYTES  : Nat
SHA512_BLOCK_BYTES  = 128

public export
SHA512_DIGEST_BYTES : Nat
SHA512_DIGEST_BYTES = 64

-- Sentinel: 4-byte domain separator, provably distinct from SHA-512 output
public export
SENTINEL : Bits32
SENTINEL = 0xFFFFFFFF

-- ── KangarooTwelve / TurboSHAKE128 Parameters (RFC 8777) ─────────────────────

public export
K12_RATE       : Nat
K12_RATE       = 168   -- bytes (1344 bits)

public export
K12_CAPACITY   : Nat
K12_CAPACITY   = 32    -- bytes (256 bits)

public export
K12_STATE_BYTES : Nat
K12_STATE_BYTES = 200  -- bytes (1600 bits)

public export
K12_ROUNDS     : Nat
K12_ROUNDS     = 12

public export
K12_LEAF_SIZE  : Nat
K12_LEAF_SIZE  = 8192  -- bytes per leaf

public export
K12_CV_BYTES   : Nat
K12_CV_BYTES   = 32    -- chaining value = 256 bits

-- Domain separation bytes
public export
K12_LEAF_DOMAIN  : Bits8
K12_LEAF_DOMAIN  = 0x03

public export
K12_NODE_DOMAIN  : Bits8
K12_NODE_DOMAIN  = 0x0B

public export
K12_FINAL_DOMAIN : Bits8
K12_FINAL_DOMAIN = 0x06

-- ── Bounds ────────────────────────────────────────────────────────────────────

public export
MAX_INPUT  : Nat
MAX_INPUT  = 2097152   -- 2MB

public export
MAX_OUTPUT : Nat
MAX_OUTPUT = 1024      -- 1KB

public export
MAX_LEAVES : Nat
MAX_LEAVES = 256       -- MAX_INPUT / K12_LEAF_SIZE

-- ── Construction type ─────────────────────────────────────────────────────────

public export
record SHA512_K12_Params where
  constructor MkParams
  inputLen  : Nat
  outputLen : Nat
  bounded_in  : inputLen  `LTE` MAX_INPUT
  bounded_out : outputLen `LTE` MAX_OUTPUT
