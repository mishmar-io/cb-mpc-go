.PHONY: help build test test-short clean deps examples force-build-cpp

# Marker file to track if C++ library is built
CPP_LIB := cb-mpc/build/install/public/lib/libcbmpc.a
CPP_PUBLIC_HEADER := cb-mpc/build/install/public/include/cbmpc/c_api/common.h
SUBMODULE_INIT := cb-mpc/.git

help:
	@echo "Available targets:"
	@echo "  deps         - Initialize git submodules"
	@echo "  build-cpp    - Build cb-mpc C++ library (only if needed)"
	@echo "  force-build-cpp - Force rebuild of C++ library"
	@echo "  build        - Build Go wrapper (builds C++ if needed)"
	@echo "  test         - Run Go tests (builds C++ if needed)"
	@echo "  test-short   - Run Go tests without checking C++ build"
	@echo "  examples     - Run example programs"
	@echo "  clean        - Clean Go build artifacts"
	@echo "  clean-all    - Clean everything including cb-mpc build"

# Initialize submodules if not already done
$(SUBMODULE_INIT):
	git submodule update --init --recursive

# Build C++ library + public install if it doesn't exist or is outdated
$(CPP_LIB): $(CPP_PUBLIC_HEADER)

$(CPP_PUBLIC_HEADER): $(SUBMODULE_INIT)
	@echo "Building C++ library (this may take a few minutes)..."
	bash scripts/build_cpp.sh Release

# Convenience target that checks if rebuild is needed
build-cpp: $(CPP_LIB)
	@echo "✅ C++ library is up to date"

# Force rebuild of C++ library
force-build-cpp: $(SUBMODULE_INIT)
	@echo "Force rebuilding C++ library..."
	bash scripts/build_cpp.sh Release

# Build Go code (will build C++ if needed)
build: $(CPP_LIB)
	bash scripts/go_with_cpp.sh go build ./...

# Run tests (will build C++ if needed)
test: $(CPP_LIB)
	bash scripts/go_with_cpp.sh go test -v -race ./...

# Run tests without checking C++ build (fast)
test-short:
	bash scripts/go_with_cpp.sh go test -v -short ./...

examples: $(CPP_LIB)
	@echo "Running ECDSA-2PC example..."
	bash scripts/go_with_cpp.sh go run examples/ecdsa2pc/main.go
	@echo "Running Schnorr-2PC example..."
	bash scripts/go_with_cpp.sh go run examples/schnorr2pc/main.go
	@echo "Running EdDSA-2PC example..."
	bash scripts/go_with_cpp.sh go run examples/eddsa2pc/main.go
	@echo "Running TDH2 example..."
	bash scripts/go_with_cpp.sh go run examples/tdh2/main.go
	@echo "Running PVE-Batch example..."
	bash scripts/go_with_cpp.sh go run examples/pve_batch/main.go

clean:
	go clean ./...

clean-all: clean
	cd cb-mpc && make clean || true
	rm -rf cb-mpc/build cb-mpc/lib
