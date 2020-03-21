package ekms

import (
	credentials2 "cloud.google.com/go/iam/credentials/apiv1"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/ekms/google_cloud_ekms_v0"
	"github.com/google/tink/go/tink"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	credentialsv1 "google.golang.org/genproto/googleapis/iam/credentials/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"io/ioutil"
	"os"
	"strings"
)

const (
	//prefix = "ekms://"
	prefix = "https://"
)

type ekmsClient struct {
	ctx     context.Context
	autogen bool
}

var _ registry.KMSClient = (*ekmsClient)(nil)

func NewClient(ctx context.Context, autogen bool) *ekmsClient {
	return &ekmsClient{
		ctx:     ctx,
		autogen: autogen,
	}

}

func (e *ekmsClient) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, prefix)
}

func (e *ekmsClient) GetAEAD(keyURI string) (aead tink.AEAD, err error) {
	if !e.Supported(keyURI) {
		err = errors.New("unsupported keyURI")
		return
	}


	return newEKMSAEAD(e.ctx, keyURI, true)
}

func getEKMSClient(ctx context.Context, ekmsHost string, ekmsPort string, insecure bool) (c google_cloud_ekms_v0.GCPExternalKeyManagementServiceClient, err error) {

	var conn *grpc.ClientConn
	if !insecure {
		// Get Client
		var options []grpc.DialOption
		if options, err = clientOptions(ctx, fmt.Sprintf("https://%s:%s", ekmsHost, ekmsHost)); err != nil {
			return
		}

		// Get Connection
		if conn, err = grpc.Dial(fmt.Sprintf("dns:///%s:%s", ekmsHost, ekmsHost), options...); err != nil {
			return
		}
	} else {
		// Get Connection
		if conn, err = grpc.Dial(fmt.Sprintf("dns:///%s:%s", ekmsHost, ekmsHost), grpc.WithInsecure()); err != nil {
			return
		}
	}

	c = google_cloud_ekms_v0.NewGCPExternalKeyManagementServiceClient(conn)
	return
}

func clientOptions(ctx context.Context, aud string) (options []grpc.DialOption, err error) {
	options = []grpc.DialOption{}
	var idTokenResponse *credentialsv1.GenerateIdTokenResponse
	idTokenResponse, err = getJWTFromCreds(ctx, aud)
	if err != nil {
		return
	}

	t := &oauth2.Token{
		AccessToken: idTokenResponse.Token,
	}

	options = append(options, grpc.WithPerRPCCredentials(oauth.NewOauthAccess(t)))
	var creds credentials.TransportCredentials
	var sp *x509.CertPool
	if sp, err = x509.SystemCertPool(); err != nil {
		sp = x509.NewCertPool()
	}

	creds = credentials.NewClientTLSFromCert(sp, "")
	options = append(options, grpc.WithTransportCredentials(creds))
	return
}

const googleAppCreds = "GOOGLE_APPLICATION_CREDENTIALS"
const googleAppCredsB64 = "GOOGLE_APPLICATION_CREDENTIALS_B64"

func getEmailFromCred(cred *google.Credentials) (email string, err error) {

	type EmailParse struct {
		ClientEmail string `json:"client_email"`
	}
	ep := EmailParse{}
	err = json.Unmarshal(cred.JSON, &ep)
	if err != nil {
		return
	}
	email = ep.ClientEmail

	return
}

func readCredentialsFile(ctx context.Context, filename string, scopes []string) (*google.Credentials, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return google.CredentialsFromJSON(ctx, b, scopes...)
}

// GetToken
func getJWTFromCreds(ctx context.Context, aud string) (accessToken *credentialsv1.GenerateIdTokenResponse, err error) {

	var creds *google.Credentials
	//First try GOOGLE_APPLICATION_CREDENTIALS environment variable.  If set, then let's use that.
	if filename := os.Getenv(googleAppCreds); filename != "" {
		if creds, err = readCredentialsFile(ctx, filename, credentials2.DefaultAuthScopes()); err != nil {
			err = fmt.Errorf("error getting credentials using %v environment variable: %v", googleAppCreds, err)
			return
		}
	}

	//Second try GOOGLE_APPLICATION_CREDENTIALS_B64.  This would be set for Cloud functions.
	if saB64 := os.Getenv(googleAppCredsB64); saB64 != "" {
		var saBytes []byte
		//saBytes, err = b64.StdEncoding.DecodeString(base64ServiceAccount)
		if saBytes, err = base64.StdEncoding.DecodeString(saB64); err != nil {
			return
		}
		if creds, err = google.CredentialsFromJSON(ctx, saBytes, credentials2.DefaultAuthScopes()...); err != nil {
			return
		}
	}

	if creds == nil {
		err = fmt.Errorf("error GOOGLE_APPLICATION_CREDENTIALS or GOOGLE_APPLICATION_CREDENTIALS_B64 should be set")
		return
	}

	var email string
	if email, err = getEmailFromCred(creds); err != nil {
		return
	}
	var iamC *credentials2.IamCredentialsClient
	if iamC, err = credentials2.NewIamCredentialsClient(ctx, option.WithCredentials(creds)); err != nil {
		return
	}
	if accessToken, err = iamC.GenerateIdToken(ctx, &credentialsv1.GenerateIdTokenRequest{
		Name:         fmt.Sprintf("projects/-/serviceAccounts/%s", email),
		Delegates:    nil,
		Audience:     aud,
		IncludeEmail: true,
	}); err != nil {
		return
	}
	return
}
