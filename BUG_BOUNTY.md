# Bug Bounty Scope

`cb-mpc-go` is currently in beta. Its primary purpose is to demonstrate and provide a Go wrapper over the public `cb-mpc` C API so that MPC protocols can be used more easily from Go.

We welcome security findings, correctness issues, unsafe edge cases, and other responsible reports. Community review is valuable and helps improve the wrapper and its examples.

However, findings that are specific to this repository are not eligible for a bounty through Coinbase's HackerOne program. The upstream `cb-mpc` bounty scope is focused on vulnerabilities in the core MPC implementation and its supported public protocol APIs, where the primary security guarantees of the system live. By contrast, `cb-mpc-go` is a beta Go binding over the public `cb-mpc` C API, together with examples and developer-facing integration code. Reports that are limited to this wrapper do not change the upstream bounty scope and are therefore reviewed as normal security or project reports rather than bounty submissions.

If a report identifies a vulnerability in the underlying `cb-mpc` library rather than in this Go wrapper, please follow the upstream disclosure guidance in `cb-mpc/SECURITY.md` and review `cb-mpc/BUG_BOUNTY.md` for the bounty scope and eligibility criteria.

Issues limited to the Go wrapper, its beta API surface, examples, or repository documentation are welcome, but they should be treated as normal project feedback rather than bounty submissions. Potential vulnerabilities should be reported privately as described in `SECURITY.md`; non-security bugs and documentation issues can be reported via [GitHub Issues](https://github.com/coinbase/cb-mpc-go/issues).
