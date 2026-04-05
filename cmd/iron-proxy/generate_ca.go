package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ironsh/iron-proxy/internal/cagen"
)

func runGenerateCA(args []string) {
	fs := flag.NewFlagSet("generate-ca", flag.ExitOnError)
	outdir := fs.String("outdir", ".", "directory to write ca.crt and ca.key")
	name := fs.String("name", "iron-proxy CA", "common name of the CA")
	expiryHours := fs.Int("expiry-hours", 8760, "number of hours the CA is valid for")
	algStr := fs.String("alg", "rsa4096", "key algorithm: rsa4096 or ed25519")
	fs.Parse(args)

	alg, err := cagen.ParseAlgorithm(*algStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	result, err := cagen.Generate(cagen.Options{
		Name:        *name,
		ExpiryHours: *expiryHours,
		Algorithm:   alg,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	certPath, keyPath, err := cagen.WriteFiles(*outdir, result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %s\n", certPath)
	fmt.Printf("wrote %s\n", keyPath)
}
