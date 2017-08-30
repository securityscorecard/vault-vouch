package vault

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/pkg/errors"
)

var HttpClient = http.DefaultClient

func GetWrappedToken(
	vaultUrl string,
	role string,
	wrap bool,
	wrapTTL time.Duration,
) (*string, error) {
	payload, err := generateLoginPayload(role)
	if err != nil {
		return nil, err
	}
	encPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", vaultUrl+"/v1/auth/aws/login", bytes.NewBuffer(encPayload))
	if err != nil {
		return nil, err
	}
	if wrap {
		req.Header.Set("X-Vault-Wrap-TTL", wrapTTL.String())
	}
	resp, err := HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	enc := json.NewDecoder(resp.Body)
	var awsResp logical.Response
	errs := struct {
		Errors []string `json:"errors"`
	}{}

	if resp.StatusCode != 200 {
		err = enc.Decode(&errs)
		if err != nil {
			return nil, errors.Wrap(err, "While decoding Error JSON")
		}
		return nil, errors.Wrap(errors.New(errs.Errors[0]), "Fetching Response")
	}

	err = enc.Decode(&awsResp)
	if err != nil {
		return nil, err
	}

	if wrap {
		return &awsResp.WrapInfo.Token, nil
	}
	return &awsResp.Auth.ClientToken, nil
}
