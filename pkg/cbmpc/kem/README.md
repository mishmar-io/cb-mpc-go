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

However, certain cryptographic protocols require **deterministic encryption** where the same inputs always produce the same output. This enables properties like **Publicly Verifiable Encryption (PVE)**, where Verifiers can reproduce ciphertexts to check correctness without seeing the plaintext. See `pkg/cbmpc/pve` for details.


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
