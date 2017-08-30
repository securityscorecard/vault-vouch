# vault-iam-vouch

This tool is designed to act as glue between AWS EC2/ECS & [Hashicorp Vault](https://www.vaultproject.io/). The
target use case is with [consul-template](https://github.com/hashicorp/consul-template).

## Usage

| Command Argument   | Environment Variable | Default | Description                |
|--------------------|----------------------|---------|----------------------------|
| `-role=`           | `IV_ROLE`            | `nil`   | Role to request from Vault |
| `-wrap_token=`     | `IV_WRAP_TOKEN`      | `true`  | Do we want a wrapped token |
| `-wrap_token_ttl=` | `IV_WRAP_TOKEN_TTL`  | `5m`    | TTL for wrapped token      |
| `-vault_addr=`     | `IV_VAULT_ADDR`      | `nil`   | Vault address              |

## Example

```
export VAULT_ADDR=https://vault.contoso.com
export VAULT_TOKEN=$(vault-iam-vouch -role="my-role")
consul-template -template "in.tpl:out.conf" -config "conf.hcl" -vault-unwrap-token -vault-renew-token=false
```
