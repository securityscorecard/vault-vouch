package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/namsral/flag"
	"github.com/securityscorecard/vault-vouch/vault"
	"github.com/securityscorecard/vault-vouch/vault/aws"
)

var (
	fs           = flag.NewFlagSetWithEnvPrefix(os.Args[0], "IV", 0)
	Role         = fs.String("role", "", "Role to request from Vault")
	AwsArnRole   = fs.String("aws_arn_role", "", "AWS role to assume before preparing auth payload for Vault")
	VaultAddress = fs.String("vault_addr", "", "Vault address")
	WrapTokenTTL = fs.String("wrap_token_ttl", "5m", "TTL for wrapped token")
)

func main() {
	err := fs.Parse(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		log.Fatal(err)
	}
	wrapTokenTTL, err := time.ParseDuration(*WrapTokenTTL)
	if err != nil {
		log.Fatal(err)
	}
	if wrapTokenTTL < 0 {
		log.Fatal(fmt.Printf("WrapTokenTTL must not be negative, given: %s", wrapTokenTTL.String()))
	}
	var gen vault.Generator
	if *AwsArnRole != "" {
		gen = aws.AssumeRoleGenerator(*VaultAddress, *AwsArnRole)
	} else {
		gen = aws.DefaultGenerator(*VaultAddress)
	}
	token, err := gen.WrappedToken(*Role, wrapTokenTTL)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", token)
}
