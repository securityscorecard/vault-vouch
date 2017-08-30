package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/namsral/flag"
	"github.com/securityscorecard/vault-iam-vouch/vault"
)

var (
	VaultAddress = flag.String("vault_addr", "", "Vault address")
	fs           = flag.NewFlagSetWithEnvPrefix(os.Args[0], "IV", 0)
	Role         = fs.String("role", "", "Role to request from Vault")
	WrapToken    = fs.Bool("wrap_token", true, "Do we want a wrapped token")
	WrapTokenTTL = fs.String("wrap_token_ttl", "5m", "TTL for wrapped token")
)

func init() {
	fs.Parse(os.Args[1:])
	flag.Parse()
}

func main() {
	wrapTokenTTL, err := time.ParseDuration(*WrapTokenTTL)
	if err != nil {
		log.Fatal(err)
	}
	if wrapTokenTTL <= 0 {
		log.Fatal(fmt.Printf("WrapTokenTTL must be a positive duration, given: %s", wrapTokenTTL.String()))
	}
	token, err := vault.GetWrappedToken(*VaultAddress, *Role, *WrapToken, wrapTokenTTL)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", *token)
}
