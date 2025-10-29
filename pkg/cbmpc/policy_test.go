//go:build cgo && !windows

package cbmpc_test

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func loadCBMPCPackages(t *testing.T) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedFiles | packages.NeedName,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("load package: %v", err)
	}
	return pkgs
}

func TestNoDirectByteComparison(t *testing.T) {
	pkgs := loadCBMPCPackages(t)
	var findings []string

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			fset := pkg.Fset
			typesInfo := pkg.TypesInfo

			ast.Inspect(file, func(n ast.Node) bool {
				be, ok := n.(*ast.BinaryExpr)
				if !ok {
					return true
				}
				if be.Op != token.EQL && be.Op != token.NEQ {
					return true
				}

				left := typesInfo.TypeOf(be.X)
				right := typesInfo.TypeOf(be.Y)

				// Only flag slice-to-slice equality on byte slices.
				// Fixed-size arrays are often used for hashes/non-secrets and
				// equality is acceptable there; we avoid over-flagging.
				if isStrictByteSlice(left) && isStrictByteSlice(right) {
					pos := fset.Position(be.Pos())
					findings = append(findings, fmt.Sprintf("%s: avoid == on byte slices; use crypto/subtle", pos))
				}
				return true
			})
		}
	}

	if len(findings) > 0 {
		t.Fatalf("constant-time policy violation:\n%s", strings.Join(findings, "\n"))
	}
}

func isStrictByteSlice(typ types.Type) bool {
	if typ == nil {
		return false
	}
	switch tt := typ.(type) {
	case *types.Slice:
		return isByte(tt.Elem())
	case *types.Pointer:
		return isStrictByteSlice(tt.Elem())
	case *types.Named:
		return isStrictByteSlice(tt.Underlying())
	default:
		return false
	}
}

func isByte(t types.Type) bool {
	basic, ok := t.(*types.Basic)
	return ok && basic.Kind() == types.Byte
}

func TestNoHexFormatting(t *testing.T) {
	pkgs := loadCBMPCPackages(t)
	var findings []string

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			fset := pkg.Fset
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}

				obj := pkg.TypesInfo.Uses[selector.Sel]
				if obj == nil || obj.Pkg() == nil {
					return true
				}

				pkgPath := obj.Pkg().Path()
				name := obj.Name()

				formatIdx, ok := formatIndex(pkgPath, name)
				if !ok || len(call.Args) <= formatIdx {
					return true
				}

				lit, ok := call.Args[formatIdx].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}

				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}

				if containsHexVerb(value) && hasByteDataArg(pkg.TypesInfo, call.Args[formatIdx+1:]) {
					pos := fset.Position(lit.Pos())
					findings = append(findings, fmt.Sprintf("%s: avoid %%%%x formatting of secrets", pos))
				}
				return true
			})
		}
	}

	if len(findings) > 0 {
		t.Fatalf("secret logging policy violation:\n%s", strings.Join(findings, "\n"))
	}
}

func formatIndex(pkgPath, name string) (int, bool) {
	switch pkgPath {
	case "fmt":
		switch name {
		case "Errorf", "Printf", "Sprintf":
			return 0, true
		case "Fprintf":
			return 1, true
		}
	case "log":
		switch name {
		case "Printf", "Fatalf", "Panicf":
			return 0, true
		}
	}
	return 0, false
}

func containsHexVerb(s string) bool {
	return strings.Contains(s, "%x") || strings.Contains(s, "%X")
}

// hasByteDataArg returns true if any argument has type []byte or [N]byte (possibly named/pointer-wrapped).
func hasByteDataArg(info *types.Info, args []ast.Expr) bool {
	for _, a := range args {
		if isByteSliceOrArray(info.TypeOf(a)) {
			return true
		}
	}
	return false
}

func isByteSliceOrArray(typ types.Type) bool {
	if typ == nil {
		return false
	}
	switch tt := typ.(type) {
	case *types.Slice:
		return isByte(tt.Elem())
	case *types.Array:
		return isByte(tt.Elem())
	case *types.Pointer:
		return isByteSliceOrArray(tt.Elem())
	case *types.Named:
		return isByteSliceOrArray(tt.Underlying())
	default:
		return false
	}
}
