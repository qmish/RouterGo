package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func main() {
	pubPath := flag.String("pub", "p2p_public.key", "path to public key file")
	privPath := flag.String("priv", "p2p_private.key", "path to private key file")
	flag.Parse()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Println("generate key:", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*pubPath, []byte(hex.EncodeToString(pub)), 0600); err != nil {
		fmt.Println("write public key:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*privPath, []byte(hex.EncodeToString(priv)), 0600); err != nil {
		fmt.Println("write private key:", err)
		os.Exit(1)
	}

	fmt.Println("generated keys:")
	fmt.Println("public:", *pubPath)
	fmt.Println("private:", *privPath)
}
