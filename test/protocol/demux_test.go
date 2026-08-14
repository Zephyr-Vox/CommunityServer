package protocol_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/protocol"
)

func startDemuxServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveDemux(t, protocol.NewHTTPDemuxListener(ln, testTLSConfig(t)), handler)
}

func serveDemux(t *testing.T, demux net.Listener, handler http.Handler) string {
	t.Helper()
	srv := &http.Server{Handler: handler}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(demux) }()
	t.Cleanup(func() {
		srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("demux server did not stop")
		}
	})
	return demux.Addr().String()
}

type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary accept error" }
func (temporaryError) Timeout() bool   { return false }
func (temporaryError) Temporary() bool { return true }

type flakyListener struct {
	net.Listener
	failures int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.failures > 0 {
		l.failures--
		return nil, temporaryError{}
	}
	return l.Listener.Accept()
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

func TestHTTPDemuxListenerServesHTTPAndTLS(t *testing.T) {
	addr := startDemuxServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plaintext status = %d, want 200", resp.StatusCode)
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}}
	resp, err = client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TLS status = %d, want 200", resp.StatusCode)
	}
}

func TestHTTPDemuxListenerSurvivesEmptyAndIdleConnections(t *testing.T) {
	addr := startDemuxServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// An empty connection must be dropped without killing the listener.
	empty, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	empty.Close()

	// An idle connection must not block the accept loop; classification
	// happens concurrently and times out on its own.
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status after empty/idle connections = %d, want 200", resp.StatusCode)
	}
}

func TestHTTPDemuxListenerRetriesTemporaryAcceptErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	flaky := &flakyListener{Listener: ln, failures: 3}
	addr := serveDemux(t, protocol.NewHTTPDemuxListener(flaky, testTLSConfig(t)), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status after temporary accept errors = %d, want 200", resp.StatusCode)
	}
}

var errPermanentAccept = errors.New("permanent accept error")

type permanentErrorListener struct{}

func (permanentErrorListener) Accept() (net.Conn, error) { return nil, errPermanentAccept }
func (permanentErrorListener) Close() error              { return nil }
func (permanentErrorListener) Addr() net.Addr            { return nil }

func TestHTTPDemuxListenerStopsOnPermanentAcceptError(t *testing.T) {
	demux := protocol.NewHTTPDemuxListener(permanentErrorListener{}, testTLSConfig(t))
	defer demux.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := demux.Accept()
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, errPermanentAccept) {
			t.Fatalf("Accept error = %v, want permanent accept error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return permanent error")
	}
}
