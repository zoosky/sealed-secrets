package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	certUtil "k8s.io/client-go/util/cert"
)

func TestHttpCert(t *testing.T) {
	_, cert, err := generatePrivateKeyAndCert(2048)
	if err != nil {
		t.Fatal(err)
	}

	cp := func() ([]*x509.Certificate, error) {
		return []*x509.Certificate{cert}, nil
	}

	server := httpserver(cp, nil, nil)
	defer server.Shutdown(context.Background())
	hp := *listenAddr
	if strings.HasPrefix(hp, ":") {
		hp = fmt.Sprintf("localhost%s", hp)
	}

	time.Sleep(1 * time.Second) // TODO(mkm) find a better way, e.g. retries
	resp, err := http.Get(fmt.Sprintf("http://%s/v1/cert.pem", hp))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := certUtil.ParseCertsPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(certs), 1; got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
	if got, want := certs[0], cert; !got.Equal(want) {
		t.Fatalf("got: %v, want: %v", got, want)
	}
}
