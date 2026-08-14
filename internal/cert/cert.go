// Package cert generates and loads the server's self-signed TLS identity.
//
// Trust model: there is no CA. Clients pin the SPKI SHA-256 fingerprint from
// a join URL, so this package's job is to keep one long-lived identity stable
// across restarts and to fail closed whenever it cannot prove the identity.
// That is why renewal reuses the same private key (fingerprint unchanged) and
// why a missing private key forces a new fingerprint instead of guessing.
//
// The package is deliberately independent of Echo, config and the HTTP layer
// so the same code can serve the control plane today and any future TLS
// listener. Domain packages do not log; callers inspect Bundle.Action and
// record the outcome with their own logger, which keeps a single boundary
// between "what happened" and "how operators are told about it".
package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Action describes what LoadOrCreate did with the certificate store. Callers
// use it for startup logs and for warnings when the fingerprint changed.
// Distinguishing the actions matters because "reused" is routine, "renewed"
// is worth an info line, and "regenerated" must warn operators that every
// already-pinned client will reject the new identity until it receives a new
// join URL through a trusted channel.
type Action string

const (
	ActionGenerated   Action = "generated"   // fresh key pair and certificate
	ActionReused      Action = "reused"      // existing valid pair, nothing written
	ActionRenewed     Action = "renewed"     // expired certificate, same private key
	ActionReissued    Action = "reissued"    // certificate missing, same private key
	ActionRegenerated Action = "regenerated" // new key pair (forced or key lost)
	ActionLoadedFile  Action = "loaded_file" // file mode, no writes
)

// Config selects the certificate source. Auto mode uses StorePath and creates
// server.crt / server.key / fingerprint.txt there; file mode loads exactly
// CertFile and KeyFile and never writes to disk.
//
// StorePath is named "path" rather than "dir" per project convention: the
// generated config writes an explicit value such as "./data/tls" instead of
// leaving an empty string as a hidden default.
type Config struct {
	// StorePath is the directory that holds the auto-generated identity. It
	// is enforced to 0700 because it contains the private key.
	StorePath string
	// CertFile is the PEM certificate in file mode. File mode is for
	// externally managed certificates (an internal CA, an existing ops
	// pipeline); this package must never overwrite those files.
	CertFile string
	// KeyFile is the PEM private key in file mode.
	KeyFile string
	// ValidYears controls the auto-mode certificate lifetime. Zero means the
	// 10-year default. This is an availability setting, not a security
	// control: security comes from private-key rotation, and renewal reuses
	// the same key so the pinned fingerprint stays stable.
	ValidYears int
	// ExtraSANs are additional DNS names / IPs appended to the built-in
	// localhost, 127.0.0.1 and ::1 set. SANs are not the trust anchor (the
	// SPKI fingerprint is), but they keep TLS tooling happy and allow the
	// certificate to be used with a real hostname.
	ExtraSANs []string
}

// Bundle is the loaded TLS identity plus the information callers need for
// logging and fingerprint distribution.
type Bundle struct {
	Certificate tls.Certificate
	Leaf        *x509.Certificate
	Fingerprint string
	CertFile    string
	KeyFile     string
	Action      Action
	BackupDir   string // non-empty when force regeneration moved old files
}

// BackupError reports a failed forced regeneration. The old identity was
// already moved to BackupDir before the failure, so operators can restore it;
// without this path the error would be ambiguous and the next startup could
// silently generate yet another fingerprint.
type BackupError struct {
	BackupDir string
	Err       error
}

func (e *BackupError) Error() string {
	return fmt.Sprintf("cert: forced regeneration failed after backing up old identity to %s: %v", e.BackupDir, e.Err)
}

func (e *BackupError) Unwrap() error {
	return e.Err
}

// LoadOrCreate loads the configured certificate.
//
// In auto mode the decision tree is deliberately ordered around keeping the
// fingerprint stable: reuse a valid pair, renew an expired certificate with
// the same key, reissue a missing certificate with the same key, and only
// generate a new key when the old one is gone or the operator forced it.
//
// In file mode the pair is externally managed, so the only safe behavior is
// to validate and fail loudly: silently regenerating an admin-owned identity
// would break their certificate pipeline and could invalidate a CA chain.
func LoadOrCreate(cfg Config, regenerate bool, now time.Time) (*Bundle, error) {
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, errors.New("cert: file mode requires both cert and key paths")
		}
		if regenerate {
			// The flag is explicitly a self-healing/operator tool for the
			// auto-generated identity. Overwriting file-mode certs would be a
			// destructive surprise, so refuse before touching the disk.
			return nil, errors.New("cert: cannot force regenerate in file mode")
		}
		return loadFile(cfg.CertFile, cfg.KeyFile, now)
	}
	if cfg.StorePath == "" {
		// No silent default inside the domain: the config layer computes the
		// actual default (db dir + "/tls") and passes it explicitly.
		return nil, errors.New("cert: store path is required in auto mode")
	}
	return loadAuto(cfg, regenerate, now)
}

// loadFile validates an externally managed pair. It performs no writes and
// no automatic renewal: an expired certificate here is an operator problem
// and must surface as a startup error instead of being papered over.
func loadFile(certPath, keyPath string, now time.Time) (*Bundle, error) {
	if err := rejectWorldAccessibleKey(keyPath); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cert: read certificate %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cert: read private key %s: %w", keyPath, err)
	}
	leaf, _, err := parsePair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("cert: file pair invalid: %w", err)
	}
	if !validAt(leaf, now) {
		return nil, fmt.Errorf("cert: certificate %s is expired or not yet valid", certPath)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("cert: build TLS pair: %w", err)
	}
	return &Bundle{
		Certificate: tlsCert,
		Leaf:        leaf,
		Fingerprint: Fingerprint(leaf),
		CertFile:    certPath,
		KeyFile:     keyPath,
		Action:      ActionLoadedFile,
	}, nil
}

func loadAuto(cfg Config, regenerate bool, now time.Time) (*Bundle, error) {
	storePath := cfg.StorePath
	// Create before touching anything else so the identity has a home, but
	// never create cert files before the TCP listener is bound: the caller
	// (server.Run) owns that ordering and calls us only after net.Listen.
	if err := os.MkdirAll(storePath, 0o700); err != nil {
		return nil, fmt.Errorf("cert: create store path %s: %w", storePath, err)
	}
	// MkdirAll leaves an existing directory's mode untouched; enforce 0700 so
	// the private key is never stored under a world-readable directory.
	if err := os.Chmod(storePath, 0o700); err != nil {
		return nil, fmt.Errorf("cert: chmod store path %s: %w", storePath, err)
	}
	certPath := filepath.Join(storePath, "server.crt")
	keyPath := filepath.Join(storePath, "server.key")
	fpPath := filepath.Join(storePath, "fingerprint.txt")

	if regenerate {
		// Forced regeneration is the one path where we intentionally change
		// the trust anchor. Move the old identity aside first so an operator
		// can roll back and so the old fingerprint remains explainable.
		backupDir, err := backupExisting(storePath, now)
		if err != nil {
			return nil, err
		}
		bundle, err := generateNewPair(cfg, certPath, keyPath, fpPath, ActionRegenerated, backupDir, now)
		if err != nil {
			// The old identity is no longer in the active store; surface where
			// it went instead of letting the next startup invent a new one.
			return nil, &BackupError{BackupDir: backupDir, Err: err}
		}
		return bundle, nil
	}

	// Missing files and unreadable files are different problems: a missing
	// file is a normal first-start or partial-write state we can heal, while
	// an unreadable file is a permissions/disk fault we must not paper over.
	certPEM, certExists, err := readOptionalFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cert: read certificate %s: %w", certPath, err)
	}
	keyPEM, keyExists, err := readOptionalFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cert: read private key %s: %w", keyPath, err)
	}
	if keyExists {
		// The reuse/renew/reissue paths all trust an existing key on disk.
		// Generation writes it 0600, but a restored backup or manual edit can
		// loosen permissions; fail closed here too, exactly like file mode.
		if err := rejectWorldAccessibleKey(keyPath); err != nil {
			return nil, err
		}
	}

	switch {
	case certExists && keyExists:
		// parsePair is strict: a mismatch between the cert and key is fail
		// fast, not "regenerate silently", because files that exist but do
		// not match usually mean someone tampered with the store.
		leaf, signer, err := parsePair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("cert: existing pair invalid: %w", err)
		}
		if validAt(leaf, now) {
			// Fast path: nothing to do. We still refresh fingerprint.txt if
			// it is missing or stale so the admin-facing file never drifts
			// from the real identity.
			fp := Fingerprint(leaf)
			if err := ensureFingerprintFile(fpPath, fp); err != nil {
				return nil, err
			}
			tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return nil, fmt.Errorf("cert: build TLS pair: %w", err)
			}
			return &Bundle{
				Certificate: tlsCert,
				Leaf:        leaf,
				Fingerprint: fp,
				CertFile:    certPath,
				KeyFile:     keyPath,
				Action:      ActionReused,
			}, nil
		}
		// The private key is still good: renew with the same key so the SPKI
		// fingerprint stays stable and already-pinned clients keep working.
		certPEM, err = issueCertificate(signer, cfg, now)
		if err != nil {
			return nil, err
		}
		if err := writePEMAtomic(certPath, certPEM, 0o644); err != nil {
			return nil, err
		}
		return buildAutoBundle(certPEM, keyPEM, certPath, keyPath, fpPath, ActionRenewed)
	case certExists && !keyExists:
		// A certificate without its private key is unusable, and there is no
		// safe way to recover the old fingerprint. Generate a new identity;
		// the resulting fingerprint change is reported through the action so
		// the boundary layer can warn operators.
		return generateNewPair(cfg, certPath, keyPath, fpPath, ActionRegenerated, "", now)
	case !certExists && keyExists:
		// The key survived but its certificate is gone (partial write, manual
		// deletion). Reuse the key: the SPKI fingerprint is unchanged, so
		// already-pinned clients are not disrupted.
		priv, err := parsePrivateKey(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("cert: parse private key %s: %w", keyPath, err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("cert: private key %s is not a signer", keyPath)
		}
		certPEM, err = issueCertificate(signer, cfg, now)
		if err != nil {
			return nil, err
		}
		if err := writePEMAtomic(certPath, certPEM, 0o644); err != nil {
			return nil, err
		}
		return buildAutoBundle(certPEM, keyPEM, certPath, keyPath, fpPath, ActionReissued)
	default:
		// Neither file exists: a fresh store, so this is the normal first
		// startup path.
		return generateNewPair(cfg, certPath, keyPath, fpPath, ActionGenerated, "", now)
	}
}

// generateNewPair creates a brand-new ECDSA P-256 identity. P-256 is chosen
// for speed, small keys and first-class Go stdlib support; RSA would be
// larger and slower without adding meaningful security for a pinned identity.
// The private key is written before the certificate: if the process dies
// between the two writes, the next startup sees a key without a cert and
// reissues with the same key, keeping the fingerprint stable.
func generateNewPair(cfg Config, certPath, keyPath, fpPath string, action Action, backupDir string, now time.Time) (*Bundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cert: generate ECDSA P-256 key: %w", err)
	}
	keyPEM, err := marshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM, err := issueCertificate(key, cfg, now)
	if err != nil {
		return nil, err
	}
	if err := writePEMAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writePEMAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	bundle, err := buildAutoBundle(certPEM, keyPEM, certPath, keyPath, fpPath, action)
	if err != nil {
		return nil, err
	}
	bundle.BackupDir = backupDir
	return bundle, nil
}

func buildAutoBundle(certPEM, keyPEM []byte, certPath, keyPath, fpPath string, action Action) (*Bundle, error) {
	// One shared construction path for every auto action keeps the bundle,
	// fingerprint.txt and the tls.Certificate consistent; callers should not
	// be able to observe a state where the files exist but the bundle was
	// built from a different view of them.
	leaf, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	fp := Fingerprint(leaf)
	if err := ensureFingerprintFile(fpPath, fp); err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("cert: build TLS pair: %w", err)
	}
	return &Bundle{
		Certificate: tlsCert,
		Leaf:        leaf,
		Fingerprint: fp,
		CertFile:    certPath,
		KeyFile:     keyPath,
		Action:      action,
	}, nil
}

func issueCertificate(signer crypto.Signer, cfg Config, now time.Time) ([]byte, error) {
	// Self-signed: the template is its own issuer. There is intentionally no
	// CA chain because clients never validate a chain—they pin the SPKI
	// fingerprint carried by the join URL.
	tmpl, err := newCertificateTemplate(cfg, now)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("cert: create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func newCertificateTemplate(cfg Config, now time.Time) (*x509.Certificate, error) {
	years := cfg.ValidYears
	if years <= 0 {
		// 10 years is an availability default, not a security claim: renewal
		// reuses the key, so the practical key lifetime is controlled by
		// rotation policy, not by this NotAfter.
		years = 10
	}
	// A random 128-bit serial makes two certificates for the same key
	// distinguishable and avoids predictable serials that some tooling flags.
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("cert: generate serial: %w", err)
	}
	serial.Add(serial, big.NewInt(1))

	// The built-in SANs keep local/loopback tooling happy. Extra SANs are
	// appended (never replace) because removing localhost would only make
	// diagnostics harder without improving security—the pin is the trust.
	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, san := range cfg.ExtraSANs {
		// Blank and whitespace-only entries would produce an invalid empty
		// dNSName that x509.CreateCertificate does not reject but strict TLS
		// tooling may. Trim and skip them defensively; the config layer also
		// validates, but this package should not emit a broken certificate
		// even when called directly.
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}

	// NotBefore is backdated one hour to absorb client clock skew; self-signed
	// leaf certs are not CAs, and the only extended usage is TLS server auth.
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "zephyrd"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(years, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}, nil
}

func parsePair(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	leaf, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, err
	}
	priv, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("cert: private key is not a signer")
	}
	// Compare the PKIX public-key encodings instead of type-switching on the
	// key algorithm. That works uniformly for ECDSA, RSA and Ed25519, and it
	// catches every mismatch without leaving a "close enough" branch.
	pubDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cert: marshal certificate public key: %w", err)
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("cert: marshal private key public key: %w", err)
	}
	if !bytes.Equal(pubDER, keyPubDER) {
		return nil, nil, errors.New("cert: certificate and private key do not match")
	}
	return leaf, signer, nil
}

func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("cert: no CERTIFICATE block found")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cert: parse certificate: %w", err)
	}
	return leaf, nil
}

func parsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	// OpenSSL commonly writes EC PARAMETERS before EC PRIVATE KEY, and the
	// standard library's tls.X509KeyPair skips every block whose type does
	// not end in "PRIVATE KEY". We mirror that behavior here, otherwise file
	// mode would reject a key that the TLS stack itself accepts.
	rest := keyPEM
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("cert: no private key block found")
		}
		rest = remaining
		if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			continue
		}
		// We write PKCS#8, but file mode should also accept legacy SEC1 EC
		// keys and PKCS#1 RSA keys that operators may already have.
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, errors.New("cert: unsupported private key format")
	}
}

func marshalPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	// PKCS#8 is the modern container: algorithm-agnostic, supported by Go's
	// TLS stack, and avoids the curve-identification ambiguity of SEC1.
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("cert: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func validAt(cert *x509.Certificate, now time.Time) bool {
	return !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
}

func readOptionalFile(path string) ([]byte, bool, error) {
	// os.ErrNotExist is a normal "not created yet" signal; any other read
	// error is a real fault and must stop startup.
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func rejectWorldAccessibleKey(path string) error {
	// Auto mode enforces 0600 on the private key; file mode must not silently
	// accept a world-readable key, or the fail-closed posture is bypassed.
	// Group-readable (0640) is allowed because external pipelines often share
	// keys with a trusted group. Windows has no meaningful POSIX permission
	// bits, so the check is skipped there.
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cert: stat private key %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		return fmt.Errorf("cert: private key %s is accessible by other users (mode %o)", path, perm)
	}
	return nil
}

func ensureFingerprintFile(path, fingerprint string) error {
	// fingerprint.txt is derived data that admins copy into join URLs. Keep
	// it byte-identical when nothing changed so an ordinary restart does not
	// touch the file (mtime noise), but repair it whenever it drifts.
	content := []byte("spki_sha256 = " + fingerprint + "\n")
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, content) {
		return nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cert: read fingerprint %s: %w", path, err)
	}
	if err := writePEMAtomic(path, content, 0o600); err != nil {
		return err
	}
	return nil
}

func writePEMAtomic(path string, data []byte, mode os.FileMode) error {
	// A crash mid-write must never leave a truncated server.key or server.crt:
	// the next startup would misdiagnose a healthy store. Temp file + fsync +
	// rename gives atomic replacement on POSIX filesystems.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("cert: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cert: write temp file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("cert: chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("cert: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cert: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("cert: rename %s to %s: %w", tmpName, path, err)
	}
	// The file fsync above only persists the file's contents; the rename
	// itself becomes durable only when the parent directory entry is synced.
	// Without this, a power loss could surface the "cert exists, key missing"
	// state even though we wrote the key first, which would force a new
	// fingerprint on the next boot. Filesystems that do not support directory
	// fsync (EINVAL/ENOTSUP/ENOSYS) are tolerated because there is no stronger
	// portable guarantee available.
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		// FlushFileBuffers does not support directory handles on Windows, so
		// directory fsync has no portable equivalent there. The permissions
		// check is skipped for the same reason; platform parity is handled by
		// the OS rather than by this package.
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cert: open directory for sync %s: %w", path, err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) {
			return nil
		}
		return fmt.Errorf("cert: sync directory %s: %w", path, err)
	}
	return nil
}

func backupExisting(storePath string, now time.Time) (string, error) {
	// Forced regeneration destroys the active trust anchor, so the old files
	// are moved aside (not deleted): operators can roll back, and an
	// accidental run leaves clear evidence of what happened and when.
	backupDir := filepath.Join(storePath, fmt.Sprintf("backup-%s", now.UTC().Format("20060102-150405.000000000")))
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return "", fmt.Errorf("cert: create backup path %s: %w", backupDir, err)
	}
	movedAny := false
	for _, name := range []string{"server.crt", "server.key", "fingerprint.txt"} {
		src := filepath.Join(storePath, name)
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, filepath.Join(backupDir, name)); err != nil {
				if movedAny {
					// Some files are already in the backup and the active
					// store is partially empty. Report the backup path so the
					// operator can restore instead of guessing.
					return backupDir, &BackupError{BackupDir: backupDir, Err: fmt.Errorf("cert: backup %s: %w", src, err)}
				}
				return "", fmt.Errorf("cert: backup %s: %w", src, err)
			}
			movedAny = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("cert: stat %s: %w", src, err)
		}
	}
	return backupDir, nil
}
