package main

import (
	"flag"
	"log"
	"strings"

	"github.com/coinbase/cb-mpc-go/examples/certutil"
)

func main() {
    var (
        outputDir = flag.String("output", "examples/certutil/certs", "directory to write certificates")
        namesFlag = flag.String("names", "p0,p1,p2", "comma-separated party names")
        keyBits   = flag.Int("key-bits", 3072, "RSA key size for CA and party certs")
        days      = flag.Int("days", 365, "certificate validity in days")
        localhost = flag.Bool("localhost", true, "include localhost SANs for local demos")
    )
    flag.Parse()

    names := strings.Split(*namesFlag, ",")
    opts := certutil.CertOptions{KeyBits: *keyBits, ValidityDays: *days, IncludeLocalhost: *localhost}
    if err := certutil.Generate(names, *outputDir, opts); err != nil {
        log.Fatalf("generate certificates: %v", err)
    }
}


