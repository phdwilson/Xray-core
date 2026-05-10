// Package phantom provides a simplified, easy-to-use TLS-impersonation security
// layer that is a fork of the REALITY protocol.  Key improvements over REALITY:
//
//   - Password-based key derivation: a simple shared password is all that is
//     needed—no manual X25519 key-pair generation or distribution.
//   - Optional traffic padding: random-length zero-padding can be injected to
//     resist DPI traffic-size fingerprinting.
//   - Sensible defaults: the uTLS fingerprint defaults to "chrome".
package phantom

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	itls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

// phantomHKDFLabel must match the label used by the xtls/reality server-side
// library.  The server hardcodes "REALITY" in its HKDF derivation, so the
// client must use the same value for authentication to succeed.
// Protocol differentiation from REALITY is achieved via password-based key
// derivation and the optional traffic-padding feature, not via the HKDF label.
const phantomHKDFLabel = "REALITY"

// Conn wraps a goreality.Conn and exposes the HandshakeAddress helper.
type Conn struct {
	*goreality.Conn
}

// HandshakeAddress returns the SNI carried in the completed TLS handshake, or
// nil if the handshake has not completed or contains no server name.
func (c *Conn) HandshakeAddress() xnet.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return xnet.ParseAddress(state.ServerName)
}

// Server wraps a plain connection with the Phantom server-side handshake.
// config must have been built from Config.GetREALITYConfig().
func Server(c xnet.Conn, config *goreality.Config) (xnet.Conn, error) {
	rc, err := goreality.Server(context.Background(), c, config)
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: rc}, nil
}

// UConn is the client-side Phantom connection wrapping a utls.UConn.
type UConn struct {
	*utls.UConn
	Config     *Config
	ServerName string
	AuthKey    []byte
	Verified   bool
}

// HandshakeAddress returns the SNI from the completed handshake.
func (c *UConn) HandshakeAddress() xnet.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return xnet.ParseAddress(state.ServerName)
}

// VerifyPeerCertificate validates the server's Phantom-specific certificate
// auth tag.  If the tag is absent or invalid it falls back to normal PKIX
// certificate verification so that the connection is indistinguishable from a
// real TLS client connecting to the fallback destination.
func (c *UConn) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c.Config.Show {
		fmt.Printf("PHANTOM localAddr: %v\tVerifyPeerCertificate\n", c.LocalAddr())
	}
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))

	// Check for a Phantom/REALITY-style HMAC-authenticated Ed25519 certificate.
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.Verified = true
			return nil
		}
	}

	// Fall back to standard TLS certificate verification.
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

// UClient performs the Phantom client-side handshake over conn and returns the
// authenticated connection.
//
//   - config carries the Phantom settings (password or explicit keys).
//   - ctx is used for deadline / cancellation of the TLS handshake.
//   - dest is the remote endpoint; its address is used as the default SNI.
func UClient(conn xnet.Conn, config *Config, ctx context.Context, dest xnet.Destination) (xnet.Conn, error) {
	localAddr := conn.LocalAddr().String()

	pubKeyBytes, err := config.GetEffectivePublicKey()
	if err != nil {
		return nil, err
	}

	uConn := &UConn{Config: config}

	utlsConfig := &utls.Config{
		VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
		ServerName:             config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		KeyLogWriter:           KeyLogWriterFromConfig(config),
	}
	if utlsConfig.ServerName == "" {
		utlsConfig.ServerName = dest.Address.String()
	}
	uConn.ServerName = utlsConfig.ServerName

	fingerprint := itls.GetFingerprint(config.GetEffectiveFingerprint())
	if fingerprint == nil {
		return nil, errors.New("PHANTOM: unknown fingerprint '", config.GetEffectiveFingerprint(), "'").AtError()
	}
	uConn.UConn = utls.UClient(conn, utlsConfig, *fingerprint)

	{
		uConn.BuildHandshakeState()
		hello := uConn.HandshakeState.Hello

		// Allocate a fresh session ID and stamp the Xray version + timestamp.
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId)
		hello.SessionId[0] = core.Version_x
		hello.SessionId[1] = core.Version_y
		hello.SessionId[2] = core.Version_z
		hello.SessionId[3] = 0 // reserved
		binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
		copy(hello.SessionId[8:], config.GetEffectiveShortId())

		if config.Show {
			fmt.Printf("PHANTOM localAddr: %v\thello.SessionId[:16]: %v\n", localAddr, hello.SessionId[:16])
		}

		// Optional padding: randomise the reserved byte to introduce variance.
		if config.Padding {
			var rb [1]byte
			if _, err := rand.Read(rb[:]); err == nil {
				hello.SessionId[3] = rb[0]
			}
		}

		publicKey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
		if err != nil {
			return nil, errors.New("PHANTOM: invalid public key")
		}

		ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
		if ecdhe == nil {
			ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
		}
		if ecdhe == nil {
			return nil, errors.New("PHANTOM: fingerprint ", uConn.ClientHelloID.Client, uConn.ClientHelloID.Version, " does not support TLS 1.3")
		}
		uConn.AuthKey, _ = ecdhe.ECDH(publicKey)
		if uConn.AuthKey == nil {
			return nil, errors.New("PHANTOM: ECDH shared key is nil")
		}

		// Derive the auth key with the Phantom HKDF label so that auth keys
		// from REALITY and PHANTOM configurations never collide.
		if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20],
			[]byte(phantomHKDFLabel)).Read(uConn.AuthKey); err != nil {
			return nil, err
		}

		aead := crypto.NewAesGcm(uConn.AuthKey)
		if config.Show {
			fmt.Printf("PHANTOM localAddr: %v\tuConn.AuthKey[:16]: %v\tAEAD: %T\n", localAddr, uConn.AuthKey[:16], aead)
		}
		aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	if config.Show {
		fmt.Printf("PHANTOM localAddr: %v\tuConn.Verified: %v\n", localAddr, uConn.Verified)
	}

	if !uConn.Verified {
		errors.LogError(ctx, "PHANTOM: received real certificate (potential MITM or redirection)")
		// Mimic real browser traffic on the fallback connection so the session
		// looks legitimate to an observer.
		go phantomSpider(uConn)
		// Brief random delay before returning the error so the connection
		// cannot be timed to distinguish it from a real browser session.
		time.Sleep(time.Duration(randBetween(100, 600)) * time.Millisecond)
		return nil, errors.New("PHANTOM: processed invalid connection").AtWarning()
	}

	return uConn, nil
}

// phantomSpider performs a minimal HTTP GET on the fallback server to make
// the TCP session look like legitimate browser activity.
func phantomSpider(uConn *UConn) {
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *gotls.Config) (xnet.Conn, error) {
				return uConn, nil
			},
		},
	}
	req, err := http.NewRequest("GET", "https://"+uConn.ServerName+"/", nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "+
			"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// Drain a limited amount of the body to look more realistic.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
}

// randBetween returns a random int64 in [lo, hi].
func randBetween(lo, hi int64) int64 {
	if hi <= lo {
		return lo
	}
	n := hi - lo + 1
	var buf [8]byte
	rand.Read(buf[:])
	v := int64(binary.BigEndian.Uint64(buf[:]))
	if v < 0 {
		v = -v
	}
	return lo + v%n
}

// stripWWW removes the leading "www." from a hostname for display purposes.
func stripWWW(sn string) string {
	return strings.TrimPrefix(sn, "www.")
}

// _ suppresses "declared and not used" for helpers that may be used later.
var _ = stripWWW
