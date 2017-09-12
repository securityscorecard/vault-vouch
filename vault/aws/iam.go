package aws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/vault/logical"
	"github.com/pkg/errors"
	"github.com/securityscorecard/vault-vouch/vault"
)

const awsAuthUrl = "/v1/auth/aws/login"

var httpClient = http.DefaultClient

type generator struct {
	sts       *sts.STS
	vaultAddr string
}

// DefaultGenerator returns a vault.Generator implementation that uses the autoconfigured
// AWS credentials in the current environment
func DefaultGenerator(vaultAddress string) vault.Generator {
	sess := session.Must(session.NewSession())
	s := sts.New(sess)
	return &generator{
		sts:       s,
		vaultAddr: vaultAddress,
	}
}

// AssumeRoleArnGenerator returns a vault.Generator implementation that uses the provided
// AWS role before generating the login payload for Vault
func AssumeRoleArnGenerator(vaultAddress string, roleArn string) vault.Generator {
	sess := session.Must(session.NewSession())
	creds := stscreds.NewCredentials(sess, roleArn)
	return &generator{
		sts:       sts.New(sess, &aws.Config{Credentials: creds}),
		vaultAddr: vaultAddress,
	}
}

func AssumeRoleGenerator(vaultAddress string, role string) vault.Generator {
	c := sts.New(session.Must(session.NewSession()))
	resp, err := c.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		panic(err)
	}
	return AssumeRoleArnGenerator(vaultAddress, fmt.Sprintf("arn:aws:iam:%s:role/%s", aws.StringValue(resp.Account), role))
}

// WrappedToken returns a token for the role provided with the wrapTTL provided
// WARNING: If wrapTTL is a zero length duration we provide an unwrapped token
func (a generator) WrappedToken(role string, wrapTTL time.Duration) (string, error) {
	payload, err := a.loginPayload(role)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", a.vaultAddr+awsAuthUrl, payload)
	if wrapTTL.Seconds() > 0 {
		req.Header.Set("X-Vault-Wrap-TTL", wrapTTL.String())
	}
	r, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	e := json.NewDecoder(r.Body)

	if r.StatusCode == 200 {
		var token logical.Response
		err = e.Decode(&token)
		if err != nil {
			return "", err
		}

		if wrapTTL.Seconds() > 0 {
			return token.WrapInfo.Token, nil
		}
		return token.Auth.ClientToken, nil
	}

	errs := struct {
		Errors []string `json:"errors"`
	}{}
	err = e.Decode(&errs)
	if err != nil {
		return "", errors.Wrap(err, "Decoding response from Vault")
	}
	return "", errors.Wrap(errors.New(errs.Errors[0]), "Fetching response from Vault")
}

// loginPayload generates the request parameters for the call to Vault
// based off Vault CLI code here: https://github.com/hashicorp/vault/blob/79b63deaf50c216e8b1d5edd12388ad85d137537/builtin/credential/aws/cli.go#L21-L70
func (a generator) loginPayload(role string) (io.Reader, error) {
	req, _ := a.sts.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
	err := req.Sign()
	if err != nil {
		return nil, err
	}

	headers, err := json.Marshal(req.HTTPRequest.Header)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(req.HTTPRequest.Body)
	if err != nil {
		return nil, err
	}

	enc, err := json.Marshal(&struct {
		Role                 string `json:"role"`
		IAMHTTPRequestMethod string `json:"iam_http_request_method"`
		IAMRequestUrl        string `json:"iam_request_url"`
		IAMRequestHeaders    string `json:"iam_request_headers"`
		IAMRequestBody       string `json:"iam_request_body"`
	}{role, req.HTTPRequest.Method,
		base64.StdEncoding.EncodeToString([]byte(req.HTTPRequest.URL.String())),
		base64.StdEncoding.EncodeToString(headers),
		base64.StdEncoding.EncodeToString(body),
	})
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(enc), nil
}
