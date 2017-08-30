package vault

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

type AwsLogin struct {
	Role                 string `json:"role"`
	IAMHTTPRequestMethod string `json:"iam_http_request_method"`
	IAMRequestUrl        string `json:"iam_request_url"`
	IAMRequestHeaders    string `json:"iam_request_headers"`
	IAMRequestBody       string `json:"iam_request_body"`
}

func generateLoginPayload(role string) (*AwsLogin, error) {
	stsSession, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)

	if err := stsRequest.Sign(); err != nil {
		return nil, err
	}

	headersJson, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return nil, err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return nil, err
	}

	return &AwsLogin{
		Role:                 role,
		IAMHTTPRequestMethod: stsRequest.HTTPRequest.Method,
		IAMRequestUrl:        base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String())),
		IAMRequestHeaders:    base64.StdEncoding.EncodeToString(headersJson),
		IAMRequestBody:       base64.StdEncoding.EncodeToString(requestBody),
	}, nil
}
