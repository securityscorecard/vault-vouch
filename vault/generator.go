package vault

import "time"

// Generator hides the implementation details of fetching a WrappedToken from Vault
type Generator interface {
	WrappedToken(role string, wrapTTL time.Duration) (string, error)
}
