# ZK Proofs Package

This package provides zero-knowledge proof protocols for use in secure multi-party computation.

## Available Protocols

- **UC_DL**: Universally composable discrete logarithm proof (single point)
- **UC_Batch_DL**: Batch discrete logarithm proof (multiple points)
- **UC_ElGamal_Com**: ElGamal commitment proof (proves knowledge of commitment opening)
- **DH**: Diffie-Hellman proof
- **ElGamal_Com_PubShare_Equ**: Proves equality of public share in ElGamal commitment
- **ElGamal_Com_Mult**: Proves multiplicative relationship between ElGamal commitments
- **UC_ElGamal_Com_Mult_Private_Scalar**: UC-secure multiplication with private scalar

## Usage

See `pkg/cbmpc/zk/example_test.go` for working Go examples of each protocol.

## Memory Management

**Proofs** are value types (`[]byte`) and require no resource management:
- No `Close()` method
- No finalizers
- Can be freely copied, serialized, and passed across goroutines
- Safe to store in structs or return from functions

**Points and Scalars** must be freed with `Free()` when no longer needed:
- Use `defer point.Free()` immediately after creation
- Use `defer scalar.Free()` immediately after creation

## Protocol Details

For detailed protocol specifications, security parameters, and implementation details, refer to the upstream C++ library:
- `cb-mpc/src/cbmpc/zk/zk_ec.h` - UC_DL, UC_Batch_DL, and DH implementations
- `cb-mpc/src/cbmpc/zk/zk_elgamal_com.h` - All ElGamal commitment proof implementations
