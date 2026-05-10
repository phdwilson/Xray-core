// Package phantom provides a simplified, easy-to-use TLS-impersonation security
// layer forked from the REALITY protocol.  Compared with REALITY, Phantom adds:
//
//   - Password-based X25519 key derivation — no manual key generation needed.
//   - Full browser-spider on verification failure — multi-page, concurrent,
//     with realistic cookie padding and timing (same quality as REALITY's spider).
//   - Optional per-handshake session-ID padding to increase DPI resistance.
//   - A default uTLS fingerprint of "chrome" so clients need minimal config.
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
	"sync"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	itls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

// phantomHKDFLabel must match the label hardcoded in the xtls/reality server
// library so that the server can authenticate the client session ID.
const phantomHKDFLabel = "REALITY"

// Conn wraps a goreality.Conn and exposes the HandshakeAddress helper.
type Conn struct {
	*goreality.Conn
}

// HandshakeAddress returns the SNI from the completed TLS handshake.
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

// VerifyPeerCertificate validates the Phantom HMAC certificate tag.  If the
// tag is absent or invalid, the method falls back to standard PKIX certificate
// verification so the connection is indistinguishable from a normal browser.
func (c *UConn) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c.Config.Show {
		fmt.Printf("PHANTOM localAddr: %v\tVerifyPeerCertificate\n", c.LocalAddr())
	}
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))

	// Phantom/REALITY style: server embeds HMAC-SHA512(authKey, ed25519Pub) as
	// the certificate signature, so the certificate is unforgeable without the
	// shared key derived during this TLS session.
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.Verified = true
			return nil
		}
	}

	// Fall back to standard PKIX certificate verification.
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

// UClient performs the Phantom client-side handshake and returns the
// authenticated connection.
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

		// Build the session ID: Xray version (3 B) | reserved (1 B) | timestamp (4 B) | short-ID (8 B) | ...
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

		// Session-ID padding: randomise the reserved byte to add per-connection
		// variance that confuses size-based DPI classifiers.
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
			return nil, errors.New("PHANTOM: fingerprint ", uConn.ClientHelloID.Client,
				uConn.ClientHelloID.Version, " does not support TLS 1.3")
		}
		uConn.AuthKey, _ = ecdhe.ECDH(publicKey)
		if uConn.AuthKey == nil {
			return nil, errors.New("PHANTOM: ECDH shared key is nil")
		}
		if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20],
			[]byte(phantomHKDFLabel)).Read(uConn.AuthKey); err != nil {
			return nil, err
		}

		aead := crypto.NewAesGcm(uConn.AuthKey)
		if config.Show {
			fmt.Printf("PHANTOM localAddr: %v\tuConn.AuthKey[:4]: %v\tAEAD: %T\n", localAddr, uConn.AuthKey[:4], aead)
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
		// Mimic authentic browser activity so the TCP session is
		// indistinguishable from a real user visiting the fallback site.
		go phantomSpider(uConn, config)
		returnDelay := crypto.RandBetween(spiderY(config, 8), spiderY(config, 9))
		if returnDelay == 0 {
			returnDelay = crypto.RandBetween(100, 600)
		}
		time.Sleep(time.Duration(returnDelay) * time.Millisecond)
		return nil, errors.New("PHANTOM: processed invalid connection").AtWarning()
	}

	return uConn, nil
}

// spiderY returns config.SpiderY[idx] when available, otherwise 0.
func spiderY(config *Config, idx int) int64 {
	if int(idx) < len(config.SpiderY) {
		return config.SpiderY[idx]
	}
	return 0
}

// ---------------------------------------------------------------------------
// Spider — realistic multi-page browser simulation
// ---------------------------------------------------------------------------

var (
	href = []byte(`href="`)
	dot  = []byte(".")
)

// phantomPaths tracks per-hostname sets of discovered URLs, shared across
// connections so subsequent spiders can crawl a wider surface area.
var phantomPaths struct {
	sync.Mutex
	m map[string]map[string]struct{}
}

func getPhantomPathLocked(paths map[string]struct{}) string {
	stopAt := int(crypto.RandBetween(0, int64(len(paths)-1)))
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}

// extractHrefs scans body for href="/..." or href="http..." paths and adds
// them to paths (stripping the scheme+host prefix when present).
func extractHrefs(body []byte, serverName string, paths map[string]struct{}) {
	prefix := append([]byte("https://"), serverName...)
	remaining := body
	for {
		idx := bytes.Index(remaining, href)
		if idx < 0 {
			break
		}
		remaining = remaining[idx+len(href):]
		end := bytes.IndexByte(remaining, '"')
		if end < 0 {
			break
		}
		link := remaining[:end]
		remaining = remaining[end+1:]
		link = bytes.TrimPrefix(link, prefix)
		if len(link) == 0 || link[0] != '/' {
			continue
		}
		if !bytes.Contains(link, dot) {
			paths[string(link)] = struct{}{}
		}
	}
}

// phantomSpider simulates realistic browser browsing on the fallback site.
// It mirrors REALITY's spider in quality: multiple concurrent sub-requests,
// cookie padding, timing intervals, and link following.
func phantomSpider(uConn *UConn, config *Config) {
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *gotls.Config) (xnet.Conn, error) {
				if config.Show {
					fmt.Printf("PHANTOM localAddr: %v\tspider DialTLSContext\n", uConn.LocalAddr())
				}
				return uConn, nil
			},
		},
	}

	prefix := "https://" + uConn.ServerName

	// Initialise the per-hostname path set.
	phantomPaths.Lock()
	if phantomPaths.m == nil {
		phantomPaths.m = make(map[string]map[string]struct{})
	}
	paths := phantomPaths.m[uConn.ServerName]
	if paths == nil {
		spiderX := config.SpiderX
		if spiderX == "" {
			spiderX = "/"
		}
		paths = map[string]struct{}{spiderX: {}}
		phantomPaths.m[uConn.ServerName] = paths
	}
	firstURL := prefix + getPhantomPathLocked(paths)
	phantomPaths.Unlock()

	localAddr := uConn.LocalAddr().String()

	get := func(first bool) {
		var (
			req  *http.Request
			resp *http.Response
			err  error
			body []byte
		)
		if first {
			req, _ = http.NewRequest("GET", firstURL, nil)
		} else {
			phantomPaths.Lock()
			req, _ = http.NewRequest("GET", prefix+getPhantomPathLocked(paths), nil)
			phantomPaths.Unlock()
		}
		if req == nil {
			return
		}
		// Set realistic browser headers (Accept, Accept-Language, User-Agent, etc.)
		utils.TryDefaultHeadersWith(req.Header, "nav")
		if first && config.Show {
			fmt.Printf("PHANTOM localAddr: %v\tspider req.UserAgent(): %v\n", localAddr, req.UserAgent())
		}

		times := 1
		if !first {
			times = int(crypto.RandBetween(spiderY(config, 4), spiderY(config, 5)))
			if times <= 0 {
				times = 1
			}
		}

		for j := 0; j < times; j++ {
			if !first && j == 0 {
				req.Header.Set("Referer", firstURL)
			}
			// Cookie padding: add a variable-length cookie to vary TLS record sizes.
			padLen := crypto.RandBetween(spiderY(config, 0), spiderY(config, 1))
			if padLen > 0 {
				pad := make([]byte, padLen)
				for i := range pad {
					pad[i] = '0'
				}
				req.AddCookie(&http.Cookie{Name: "padding", Value: string(pad)})
			}

			if resp, err = client.Do(req); err != nil {
				break
			}
			defer resp.Body.Close()
			req.Header.Set("Referer", req.URL.String())

			if body, err = io.ReadAll(resp.Body); err != nil {
				break
			}

			// Harvest links for subsequent requests.
			phantomPaths.Lock()
			extractHrefs(body, uConn.ServerName, paths)
			req.URL.Path = getPhantomPathLocked(paths)
			if config.Show {
				fmt.Printf("PHANTOM localAddr: %v\tspider Referer: %v\tlen(body): %v\tlen(paths): %v\n",
					localAddr, req.Referer(), len(body), len(paths))
			}
			phantomPaths.Unlock()

			if !first {
				interval := crypto.RandBetween(spiderY(config, 6), spiderY(config, 7))
				if interval > 0 {
					time.Sleep(time.Duration(interval) * time.Millisecond)
				}
			}
		}
	}

	get(true)

	concurrency := int(crypto.RandBetween(spiderY(config, 2), spiderY(config, 3)))
	for i := 0; i < concurrency; i++ {
		go get(false)
	}
	// Do not close the connection — let it time out naturally so the session
	// duration matches that of a real browser.
}
