package main

import (
"crypto/ecdh"
"crypto/rand"
"encoding/hex"
"fmt"
"os"
)

func main() {
priv, err := ecdh.X25519().GenerateKey(rand.Reader)
if err != nil {
fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
os.Exit(1)
}
privBytes := priv.Bytes()          // 32 байта
pubBytes := priv.PublicKey().Bytes() // 32 байта

fmt.Printf("PRIVATE_KEY_HEX=%s\n", hex.EncodeToString(privBytes))
fmt.Printf("PUBLIC_KEY_HEX=%s\n", hex.EncodeToString(pubBytes))
fmt.Println()
fmt.Println("# Сохрани эти два значения. Приватный — только на сервере.")
fmt.Println("# Публичный — вшивается в клиент (в config.json).")
}
