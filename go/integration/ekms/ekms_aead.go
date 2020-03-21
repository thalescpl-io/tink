package ekms

import (
	"context"
	"fmt"
	"github.com/ThalesIgnite/gose"
	"github.com/google/tink/go/integration/ekms/google_cloud_ekms_v0"
	"github.com/google/tink/go/tink"
	"net/url"
	"strings"
)

type ekmsAEAD struct {
	ctx    context.Context
	client google_cloud_ekms_v0.GCPExternalKeyManagementServiceClient
	jwee   gose.JweEncryptor
	jwed   gose.JweDecryptor
}

var _ tink.AEAD = (*ekmsAEAD)(nil)

func newEKMSAEAD(ctx context.Context, keyURI string, autogen bool) (p *ekmsAEAD, err error) {

	p = &ekmsAEAD{ctx: ctx}

	// Warm up Device...
	var k *Key
	if k, err = parseKeyURI(keyURI); err != nil {
		return
	}
	if k != nil {
		fmt.Println(k.id.String())
	}
	var u *url.URL
	if u, err = url.Parse(keyURI); err != nil {
		return
	}
	sp := strings.Split(u.Host, ":")
	var host, port string
	if len(sp) == 1 {
		host = sp[0]
		port = "443"
	} else if len(sp) == 2 {
		host = sp[0]
		host = sp[1]
	} else {
		err = fmt.Errorf("invalid EKMS host:port ")
	}
	if p.client, err = getEKMSClient(ctx, host, port, false); err != nil {
		return

	}

	// TODO: wire up EKMS Client for wrap/unwrap of wrapping key, OR use KeyURL for Encrypt=Wrap and Decrypt=Unwrap
	return
}

func (p *ekmsAEAD) Encrypt(plaintext, additionalData []byte) (cipherText []byte, err error) {
	var cipherString string
	if cipherString, err = p.jwee.Encrypt(plaintext, additionalData); err != nil {
		return
	}
	cipherText = []byte(cipherString)
	return
}

func (p *ekmsAEAD) Decrypt(ciphertext, additionalData []byte) (clearText []byte, err error) {

	if clearText, additionalData, err = p.jwed.Decrypt(string(ciphertext)); err != nil {
		return
	}

	return
}
