# vault-vouch [![Build Status](https://travis-ci.org/securityscorecard/vault-vouch.svg?branch=master)](https://travis-ci.org/securityscorecard/vault-vouch)

This tool is designed to act as glue between a Trusted Third Party & [Hashicorp Vault](https://www.vaultproject.io/). The
target use case is with [consul-template](https://github.com/hashicorp/consul-template).

The only supported Trusted Third Party is currently AWS IAM.

## Usage

| Command Argument   | Environment Variable | Default | Description                                                |
|--------------------|----------------------|---------|------------------------------------------------------------|
| `-role=`           | `IV_ROLE`            | `nil`   | Role to request from Vault                                 |
| `-aws_arn_role=`   | `IV_AWS_ARN_ROLE`    | `nil`   | AWS role to assume before preparing auth payload for Vault |
| `-vault_addr=`     | `IV_VAULT_ADDR`      | `nil`   | Vault address                                              |
| `-wrap_token_ttl=` | `IV_WRAP_TOKEN_TTL`  | `5m`    | TTL for wrapped token, to disable wrapping set to `0`      |

## Example

```
export VAULT_ADDR=https://vault.contoso.com
export VAULT_TOKEN=$(vault-vouch -role="my-role")
consul-template -template "in.tpl:out.conf" -config "conf.hcl" -vault-unwrap-token -vault-renew-token=false
```
