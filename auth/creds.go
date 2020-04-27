package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"

	"golang.org/x/oauth2/google"
)

var ErrUnauthorized = errors.New("Unauthorized")

const credsEnvVar = "GCPUTIL_GOOGLE_APPLICATION_CREDENTIALS"

type Context struct {
	Type         string `json:"type"`
	ProjectId    string `json:"project_id"`
	PrivateKeyId string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientId     string `json:"client_id"`
}

func Credentials(dsn string, scopes ...string) (*google.Credentials, *Context, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, nil, err
	}

	var creds *google.Credentials
	if v := strings.TrimSpace(u.Query().Get("credentials")); v != "" {
		data, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, nil, err
		}
		creds, err = google.CredentialsFromJSON(context.Background(), data, scopes...)
		if err != nil {
			return nil, nil, err
		}
	} else if v = strings.TrimSpace(os.Getenv(credsEnvVar)); v != "" {
		var data []byte
		if v[0] == '{' {
			data = []byte(v)
		} else {
			data, err = base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, nil, err
			}
		}
		creds, err = google.CredentialsFromJSON(context.Background(), data, scopes...)
		if err != nil {
			return nil, nil, err
		}
	} else {
		creds, err = google.FindDefaultCredentials(context.Background(), scopes...)
		if err != nil {
			return nil, nil, err
		}
	if creds == nil {
		return nil, nil, ErrUnauthorized
	}

	context := &Context{}
	if len(creds.JSON) > 0 {
		err = json.Unmarshal(creds.JSON, context)
		if err != nil {
			return nil, nil, err
		}
	}

	return creds, context, nil
}
