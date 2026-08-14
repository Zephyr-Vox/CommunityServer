package cert_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/cert"
)

func TestGenerateCreatesFilesWithExpectedPermissions(t *testing.T) {
	cfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	b, err := cert.LoadOrCreate(cfg, false, time.Now())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if b.Action != cert.ActionGenerated {
		t.Fatalf("action = %q, want %q", b.Action, cert.ActionGenerated)
	}
	info, err := os.Stat(cfg.StorePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("store mode = %o, want 700", info.Mode().Perm())
	}
	for path, want := range map[string]os.FileMode{
		b.KeyFile:  0o600,
		b.CertFile: 0o644,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
		}
	}
	fpData, err := os.ReadFile(filepath.Join(cfg.StorePath, "fingerprint.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(fpData, []byte(b.Fingerprint)) {
		t.Fatalf("fingerprint.txt = %q, want it to contain %q", fpData, b.Fingerprint)
	}
}

func TestReuseKeepsFingerprint(t *testing.T) {
	cfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	now := time.Now()
	b1, err := cert.LoadOrCreate(cfg, false, now)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := cert.LoadOrCreate(cfg, false, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if b2.Action != cert.ActionReused {
		t.Fatalf("action = %q, want %q", b2.Action, cert.ActionReused)
	}
	if b1.Fingerprint != b2.Fingerprint {
		t.Fatalf("fingerprint changed: %q != %q", b1.Fingerprint, b2.Fingerprint)
	}
}

func TestRenewExpiredCertificateKeepsFingerprint(t *testing.T) {
	cfg := cert.Config{StorePath: t.TempDir(), ValidYears: 1}
	now := time.Now()
	b1, err := cert.LoadOrCreate(cfg, false, now)
	if err != nil {
		t.Fatal(err)
	}
	expired := now.AddDate(1, 0, 1)
	b2, err := cert.LoadOrCreate(cfg, false, expired)
	if err != nil {
		t.Fatal(err)
	}
	if b2.Action != cert.ActionRenewed {
		t.Fatalf("action = %q, want %q", b2.Action, cert.ActionRenewed)
	}
	if b1.Fingerprint != b2.Fingerprint {
		t.Fatalf("renewal changed fingerprint: %q != %q", b1.Fingerprint, b2.Fingerprint)
	}
	if !b2.Leaf.NotAfter.After(expired) {
		t.Fatalf("renewed NotAfter = %v, want after %v", b2.Leaf.NotAfter, expired)
	}
}

func TestMissingCertificateReissuesWithSameKey(t *testing.T) {
	cfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	now := time.Now()
	b1, err := cert.LoadOrCreate(cfg, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(b1.CertFile); err != nil {
		t.Fatal(err)
	}
	b2, err := cert.LoadOrCreate(cfg, false, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if b2.Action != cert.ActionReissued {
		t.Fatalf("action = %q, want %q", b2.Action, cert.ActionReissued)
	}
	if b1.Fingerprint != b2.Fingerprint {
		t.Fatalf("reissue changed fingerprint: %q != %q", b1.Fingerprint, b2.Fingerprint)
	}
}

func TestMissingKeyRegeneratesNewFingerprint(t *testing.T) {
	cfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	now := time.Now()
	b1, err := cert.LoadOrCreate(cfg, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(b1.KeyFile); err != nil {
		t.Fatal(err)
	}
	b2, err := cert.LoadOrCreate(cfg, false, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if b2.Action != cert.ActionRegenerated {
		t.Fatalf("action = %q, want %q", b2.Action, cert.ActionRegenerated)
	}
	if b1.Fingerprint == b2.Fingerprint {
		t.Fatal("regenerated certificate kept the old fingerprint")
	}
}

func TestForceRegenerateBacksUpOldFiles(t *testing.T) {
	cfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	now := time.Now()
	b1, err := cert.LoadOrCreate(cfg, false, now)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := cert.LoadOrCreate(cfg, true, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if b2.Action != cert.ActionRegenerated {
		t.Fatalf("action = %q, want %q", b2.Action, cert.ActionRegenerated)
	}
	if b2.BackupDir == "" {
		t.Fatal("force regeneration did not create a backup path")
	}
	if b1.Fingerprint == b2.Fingerprint {
		t.Fatal("force regeneration kept the old fingerprint")
	}
	for _, name := range []string{"server.crt", "server.key", "fingerprint.txt"} {
		if _, err := os.Stat(filepath.Join(b2.BackupDir, name)); err != nil {
			t.Fatalf("backup missing %s: %v", name, err)
		}
	}
}

func TestBackupPartialFailureReturnsBackupPath(t *testing.T) {
	cfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	now := time.Now()
	if _, err := cert.LoadOrCreate(cfg, false, now); err != nil {
		t.Fatal(err)
	}
	// Make server.key a directory so moving it into the backup fails after
	// server.crt has already been moved: the backup path must still be
	// reported, otherwise the operator cannot find the old identity.
	keyPath := filepath.Join(cfg.StorePath, "server.key")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(cfg.StorePath, fmt.Sprintf("backup-%s", now.UTC().Format("20060102-150405.000000000")))
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "server.key"), []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := cert.LoadOrCreate(cfg, true, now)
	if err == nil {
		t.Fatal("backup with a blocking destination must fail")
	}
	var backupErr *cert.BackupError
	if !errors.As(err, &backupErr) {
		t.Fatalf("err = %v, want *cert.BackupError", err)
	}
	if backupErr.BackupDir != backupDir {
		t.Fatalf("BackupError.BackupDir = %q, want %q", backupErr.BackupDir, backupDir)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "server.crt")); err != nil {
		t.Fatalf("backup missing server.crt: %v", err)
	}
}

func TestFileModeLoadsExistingPair(t *testing.T) {
	autoCfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	b1, err := cert.LoadOrCreate(autoCfg, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fileCfg := cert.Config{CertFile: b1.CertFile, KeyFile: b1.KeyFile}
	b2, err := cert.LoadOrCreate(fileCfg, false, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if b2.Action != cert.ActionLoadedFile {
		t.Fatalf("action = %q, want %q", b2.Action, cert.ActionLoadedFile)
	}
	if b1.Fingerprint != b2.Fingerprint {
		t.Fatalf("file mode fingerprint = %q, want %q", b2.Fingerprint, b1.Fingerprint)
	}
}

func TestFileModeRejectsWorldReadableKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	autoCfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	b, err := cert.LoadOrCreate(autoCfg, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := os.ReadFile(b.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(keyPath, keyData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	fileCfg := cert.Config{CertFile: b.CertFile, KeyFile: keyPath}
	if _, err := cert.LoadOrCreate(fileCfg, false, time.Now()); err == nil {
		t.Fatal("file mode must reject a world-readable private key")
	}
}

func TestAutoModeRejectsWorldReadableKeyOnReuse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	cfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	now := time.Now()
	b, err := cert.LoadOrCreate(cfg, false, now)
	if err != nil {
		t.Fatal(err)
	}
	// A restored backup or a manual chmod can loosen the key permissions; the
	// reuse path must fail closed instead of silently accepting it.
	if err := os.Chmod(b.KeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cert.LoadOrCreate(cfg, false, now.Add(time.Minute)); err == nil {
		t.Fatal("auto mode reuse must reject a world-readable private key")
	}
}

func TestFileModeAcceptsOpenSSLStyleECParametersPrefix(t *testing.T) {
	autoCfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	b, err := cert.LoadOrCreate(autoCfg, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(b.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	// OpenSSL's ecparam output puts an EC PARAMETERS block before the private
	// key block. tls.X509KeyPair skips the non-key block, so our parser must
	// accept the same file instead of failing on the first PEM block.
	var opensslStyle bytes.Buffer
	opensslStyle.WriteString("-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n")
	opensslStyle.Write(keyPEM)
	keyPath := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(keyPath, opensslStyle.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	fileCfg := cert.Config{CertFile: b.CertFile, KeyFile: keyPath}
	b2, err := cert.LoadOrCreate(fileCfg, false, time.Now())
	if err != nil {
		t.Fatalf("LoadOrCreate with EC PARAMETERS prefix: %v", err)
	}
	if b2.Fingerprint != b.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", b2.Fingerprint, b.Fingerprint)
	}
}

func TestExtraSANsIgnoreBlankEntries(t *testing.T) {
	cfg := cert.Config{
		StorePath:  t.TempDir(),
		ValidYears: 10,
		ExtraSANs:  []string{"", "   ", "voice.example.com"},
	}
	b, err := cert.LoadOrCreate(cfg, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, dns := range b.Leaf.DNSNames {
		if dns == "voice.example.com" {
			found = true
		}
		if strings.TrimSpace(dns) == "" {
			t.Fatalf("blank dNSName %q in generated certificate", dns)
		}
	}
	if !found {
		t.Fatalf("DNSNames = %v, want voice.example.com", b.Leaf.DNSNames)
	}
}

func TestFileModeRejectsForceRegenerate(t *testing.T) {
	autoCfg := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	b, err := cert.LoadOrCreate(autoCfg, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fileCfg := cert.Config{CertFile: b.CertFile, KeyFile: b.KeyFile}
	if _, err := cert.LoadOrCreate(fileCfg, true, time.Now()); err == nil {
		t.Fatal("force regenerate in file mode must fail")
	}
}

func TestFileModeRejectsExpiredCertificate(t *testing.T) {
	autoCfg := cert.Config{StorePath: t.TempDir(), ValidYears: 1}
	now := time.Now()
	b, err := cert.LoadOrCreate(autoCfg, false, now)
	if err != nil {
		t.Fatal(err)
	}
	fileCfg := cert.Config{CertFile: b.CertFile, KeyFile: b.KeyFile}
	if _, err := cert.LoadOrCreate(fileCfg, false, now.AddDate(1, 0, 1)); err == nil {
		t.Fatal("file mode must reject expired certificates")
	}
}

func TestMismatchedKeyAndCertFails(t *testing.T) {
	cfg1 := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	cfg2 := cert.Config{StorePath: t.TempDir(), ValidYears: 10}
	b1, err := cert.LoadOrCreate(cfg1, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b2, err := cert.LoadOrCreate(cfg2, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fileCfg := cert.Config{CertFile: b1.CertFile, KeyFile: b2.KeyFile}
	if _, err := cert.LoadOrCreate(fileCfg, false, time.Now()); err == nil {
		t.Fatal("mismatched certificate and key must fail")
	}
}

func TestAutoModeRequiresStorePath(t *testing.T) {
	if _, err := cert.LoadOrCreate(cert.Config{}, false, time.Now()); err == nil {
		t.Fatal("auto mode without store path must fail")
	}
}

func TestFileModeRequiresBothPaths(t *testing.T) {
	if _, err := cert.LoadOrCreate(cert.Config{CertFile: "only.crt"}, false, time.Now()); err == nil {
		t.Fatal("file mode with one path must fail")
	}
}
