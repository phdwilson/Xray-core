package phantom

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"io"
	"os"

	"net"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/hkdf"
)

// phantomLabel is the HKDF info label used to distinguish Phantom keys from
// other protocols that might also use HKDF on a password.
const phantomLabel = "phantom-v1"

// DerivePrivateKey derives a 32-byte X25519 private key from a human-readable
// password using HKDF-SHA256.  The same password always produces the same key.
func DerivePrivateKey(password string) ([]byte, error) {
	priv := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(password), nil, []byte(phantomLabel+"-private-key"))
	if _, err := io.ReadFull(r, priv); err != nil {
		return nil, err
	}
	return priv, nil
}

// DerivePublicKey returns the X25519 public key that corresponds to the private
// key derived from password.
func DerivePublicKey(password string) ([]byte, error) {
	priv, err := DerivePrivateKey(password)
	if err != nil {
		return nil, err
	}
	privKey, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return privKey.PublicKey().Bytes(), nil
}

// GetREALITYConfig converts a Phantom Config into the underlying reality.Config
// used by the xtls/reality library.  When Password is provided and the explicit
// key fields are absent, the key pair is derived automatically from the password.
func (c *Config) GetREALITYConfig() (*goreality.Config, error) {
	privateKey := c.PrivateKey
	if len(privateKey) == 0 && c.Password != "" {
		var err error
		if privateKey, err = DerivePrivateKey(c.Password); err != nil {
			return nil, errors.New("phantom: failed to derive private key from password").Base(err)
		}
	}

	var dialer net.Dialer
	cfg := &goreality.Config{
		DialContext: dialer.DialContext,

		Show: c.Show,
		Type: c.Type,
		Dest: c.Dest,
		Xver: byte(c.Xver),

		PrivateKey:             privateKey,
		SessionTicketsDisabled: true,

		KeyLogWriter: KeyLogWriterFromConfig(c),
	}

	cfg.ServerNames = make(map[string]bool)
	for _, sn := range c.ServerNames {
		cfg.ServerNames[sn] = true
	}

	cfg.ShortIds = make(map[[8]byte]bool)
	for _, sid := range c.ShortIds {
		var key [8]byte
		copy(key[:], sid)
		cfg.ShortIds[key] = true
	}

	return cfg, nil
}

// GetEffectivePublicKey returns the public key to be used by the client.
// If PublicKey is set explicitly it is returned as-is; otherwise it is
// derived from Password.
func (c *Config) GetEffectivePublicKey() ([]byte, error) {
	if len(c.PublicKey) > 0 {
		return c.PublicKey, nil
	}
	if c.Password != "" {
		return DerivePublicKey(c.Password)
	}
	return nil, errors.New("phantom: neither PublicKey nor Password is set")
}

// GetEffectiveShortId returns the short ID bytes to embed in the client hello.
// A zero-length short ID (empty) is valid and acts as "no short ID".
func (c *Config) GetEffectiveShortId() []byte {
	return c.ShortId
}

// GetEffectiveFingerprint returns the uTLS fingerprint name, defaulting to "chrome".
func (c *Config) GetEffectiveFingerprint() string {
	if c.Fingerprint == "" {
		return "chrome"
	}
	return c.Fingerprint
}

// KeyLogWriterFromConfig opens the MasterKeyLog file for writing TLS secrets.
func KeyLogWriterFromConfig(c *Config) io.Writer {
	if len(c.MasterKeyLog) == 0 || c.MasterKeyLog == "none" {
		return nil
	}
	writer, err := os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		errors.LogErrorInner(context.Background(), err,
			"phantom: failed to open master key log file", c.MasterKeyLog)
	}
	return writer
}

// ConfigFromStreamSettings extracts a *phantom.Config from a MemoryStreamConfig.
func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}
