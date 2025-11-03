# KEM Package - Deterministic RSA-OAEP

**Deterministic RSA-OAEP; not a general randomized KEM.**

---

**CRITICAL SECURITY WARNING**

## This is NOT a General-Purpose KEM!

**All KEM implementations in this package are DETERMINISTIC and designed for specialized cryptographic protocols.**

### What This Means

- **DETERMINISTIC**: Same (public_key, rho) produces same ciphertext
- **SPECIALIZED USE**: Only safe within specific protocol contexts (e.g., PVE, deterministic encryption schemes)
- **NOT RANDOMIZED**: Does not use random bytes for encryption
- **UNSAFE** for general public-key encryption use cases

---

## Quick Start

See `pkg/cbmpc/kem/rsa/example_test.go` for examples demonstrating:
- **Determinism**: Same (ek, rho) produces identical ciphertext (`Example_determinism`)
- **Key sizes**: Different RSA key size options - 2048, 3072, 4096 bits (`Example_keySizes`)

For a complete usage example within the PVE protocol, see `pkg/cbmpc/pve/example_test.go`.

---

## Why Determinism?

Traditional randomized public-key encryption (like standard RSA-OAEP) uses fresh random bytes for each encryption. This ensures that encrypting the same message twice produces different ciphertexts, which is critical for semantic security (IND-CCA2).

However, certain cryptographic protocols require **deterministic encryption** where the same inputs always produce the same output. This enables properties like:
- **Publicly Verifiable Encryption (PVE)**: Verifiers can reproduce ciphertexts to check correctness without seeing the plaintext
- **Deterministic protocols**: Where reproducibility is required for protocol correctness
- **Commitment schemes**: Where encryption acts as a binding commitment

### Example: PVE Construction

PVE is one example protocol that uses deterministic KEM with a **Fiat-Shamir-style** non-interactive proof:

1. **Commit to the secret**: Compute `Q = x·G` (elliptic curve point)
2. **Deterministic encryption**: Encrypt using `rho = Hash(Q, label, ...)` as the seed
3. **Zero-knowledge proof**: Prove knowledge of `x` such that `Q = x·G` and ciphertext matches

The deterministic property is **essential** for PVE because:
- The verifier must be able to recompute the ciphertext using `Q` and `label`
- If encryption were randomized, the verifier couldn't reproduce it
- Determinism binds the ciphertext to the commitment `Q`

### Domain Separation

To prevent cross-key attacks with deterministic encryption, this implementation provides **domain separation**:

```
ekHash = SHA-256(ek)
label = "cbmpc/pve/rsa-oaep:" || ekHash
seed = SHA-256(rho || ekHash)
ciphertext = RSA-OAEP(ek, ss, label, seed)
```

This ensures:
- Same `rho` with **different keys** produces **different ciphertexts**
- Ciphertexts are cryptographically bound to specific public keys
- Decryption requires the matching public key (via label check)

### References

- **Fiat-Shamir heuristic**: Converting interactive proofs to non-interactive
- **Deterministic protocols**: See use cases in `pkg/cbmpc/pve` (PVE implementation)
- **Domain Separation**: Security fix for deterministic OAEP binding

---

## DO NOT Use This For

- General-purpose public-key encryption
- Applications requiring IND-CCA2 security
- Any scenario where `rho` might be reused
- Encrypting multiple messages with the same seed
- Standard PKI/TLS applications
- File encryption, email encryption, etc.

## Safe Use Cases

**ONLY** use within specialized cryptographic protocols where deterministic encryption is required, such as:

1. **Publicly Verifiable Encryption (PVE)**: Where verifiers must reproduce ciphertexts
2. **Deterministic commitment schemes**: Where encryption acts as a binding commitment
3. **Protocol-specific contexts**: Where determinism is a security requirement

### Requirements for Safe Use:

1. **Fresh rho per encryption**: Each encryption uses a unique, unpredictable 32-byte seed
2. **Protocol context**: Used as part of a larger protocol (not standalone)
3. **Determinism is required**: Protocol properties depend on deterministic behavior
4. **Security model is understood**: Caller understands the security implications

---

## Security Properties

### Domain Separation

Implementations provide domain separation to prevent cross-key attacks:

- **Key-bound OAEP label**: Each public key has a unique label (`cbmpc/pve/rsa-oaep:SHA256(ek)`)
- **Key-bound seed derivation**: Deterministic seed includes hash of public key
- **Cross-key security**: Same `rho` with different keys produces different ciphertexts

### Cryptographic Binding

```
ekHash = SHA-256(ek)
label = "cbmpc/pve/rsa-oaep:" || ekHash
seed = SHA-256(rho || ekHash)
ciphertext = RSA-OAEP(ek, ss, label, seed)
```

This ensures:
- Ciphertexts are bound to specific public keys
- Same `rho` cannot leak information across different keys
- Decryption requires matching public key (via label check)

### Handle Metadata and Runtime Checks

To reduce misuse risk with `any` decapsulation handles, the built-in RSA private key handle stores:

- Algorithm ID (e.g., `rsa-oaep-2048`)
- Modulus size in bytes
- Public key hash `SHA-256(ek)`

At decapsulation time, the RSA KEM verifies:

- Algorithm family is RSA-OAEP
- Modulus size is one of 2048/3072/4096 bits and matches this KEM's configured size
- Public key hash in the handle matches the actual handle public key
- Optional: if the KEM instance is bound to a specific public key hash, it must match

Typed errors are returned on mismatch (no panics):

- `rsa.ErrInvalidHandleType`
- `rsa.ErrAlgorithmMismatch`
- `rsa.ErrUnsupportedKeySize`
- `rsa.ErrPublicKeyHashMismatch`

---

## Implementation: RSA-OAEP

The `rsa` package provides deterministic RSA-OAEP encryption:

### Key Sizes

- **2048 bits**: Minimum for current use
- **3072 bits**: Recommended for long-term security (post-2030)
- **4096 bits**: High-security applications

### Security Features

- SHA-256 for all hashing operations
- PKCS#8 DER format for private keys
- Secure key zeroization on free
- Key-bound OAEP labels for domain separation
- Deterministic seed derivation with key binding

---

## Security Auditing

When reviewing code that uses this package:

### Good Practices

- KEM only used via `pve.New(kem)`
- Fresh `rho` generated for each PVE encryption
- `rho` derived from cryptographically secure source
- KEM instances not shared across different security contexts

### Red Flags

- Direct calls to `kem.Encapsulate()` outside PVE
- Reusing `rho` values across multiple encryptions
- Using same `rho` for different messages
- Comments mentioning "general-purpose" or "randomized" KEM
- KEM used for non-PVE encryption

---

## Questions?

If you're unsure whether your use case is appropriate:

**Don't use this package.** Use a standard randomized KEM instead.

If you need deterministic encryption for PVE and understand the security implications, ensure:

1. You're implementing or using the full PVE protocol
2. Each encryption uses a fresh, unpredictable `rho`
3. You understand why determinism is safe in your specific context
4. You've reviewed the security properties and constraints
