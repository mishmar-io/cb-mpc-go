## Summary

- 

## Testing

- [ ] `bash scripts/go_with_cpp.sh go test ./...`
- [ ] `make examples`
- [ ] Relevant `make demo-*` workflow, if applicable

## Checklist

- [ ] Uses only the public `cb-mpc` install artifacts
- [ ] Keeps all `import "C"` usage inside `internal/cgo`
- [ ] Updates docs/examples/demos when behavior changes
- [ ] Avoids checked-in generated certs, binaries, or other build artifacts
