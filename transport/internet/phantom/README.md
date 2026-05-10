# Phantom — 幻 — A Simplified REALITY Fork

**Phantom** is a TLS-impersonation security layer built into Xray-core that is
derived from the [REALITY](https://github.com/XTLS/REALITY) protocol.

## Why Phantom?

| Feature | REALITY | Phantom |
|---|---|---|
| Key exchange | Manual X25519 key generation required | ✅ Password-based auto-derivation |
| Required server-side fields | `serverNames`, `privateKey`, `shortIds`, `dest` | `serverNames`, `password`, `dest` |
| Required client-side fields | `serverName`, `publicKey`, `shortId`, `fingerprint` | `serverName`, `password` |
| Default fingerprint | Must be specified | Defaults to `chrome` |
| Traffic padding | ✗ | ✅ Optional (set `padding: true`) |
| Anti-GFW HKDF label | `"REALITY"` | `"REALITY"` (same; required for server compatibility) |
| Server fallback | Real website (same as REALITY) | Real website (same as REALITY) |
| TLS 1.3 uTLS impersonation | ✅ | ✅ |
| ML-KEM / post-quantum | ✅ | ✅ (inherited from uTLS fingerprint) |

## Quick Start

### Step 1 — Choose a password

Pick any password.  It will be used to automatically derive the X25519 key pair
on both sides.  The password never travels over the wire.

```
my-secret-password-here
```

### Step 2 — Server configuration

```jsonc
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "raw",
        "security": "phantom",
        "phantomSettings": {
          "dest": "www.bing.com:443",
          "serverNames": ["www.bing.com"],
          "password": "my-secret-password-here"
        }
      }
    }
  ]
}
```

> **Note:** `dest` and `serverNames` must point to a real HTTPS website that
> the server can reach.  When a non-Phantom client connects, traffic is silently
> forwarded to this fallback destination so the server looks like a normal
> HTTPS server.

### Step 3 — Client configuration

```jsonc
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "your-server-ip",
            "port": 443,
            "users": [
              {
                "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "encryption": "none",
                "flow": "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "phantom",
        "phantomSettings": {
          "serverName": "www.bing.com",
          "password": "my-secret-password-here",
          "fingerprint": "chrome",
          "padding": true
        }
      }
    }
  ]
}
```

That's all.  No key generation, no short-ID management.

---

## Configuration Reference

### Server-side fields (`"phantomSettings"` in an inbound)

| Field | Type | Required | Description |
|---|---|---|---|
| `dest` | `string` | ✅ | Fallback destination (`"host:port"`). |
| `serverNames` | `[string]` | ✅ | Allowed SNI values. |
| `password` | `string` | Either this or `privateKey` | Shared secret for automatic key derivation. |
| `privateKey` | `string` | Either this or `password` | Base64url-encoded 32-byte X25519 private key (for advanced users). |
| `shortIds` | `[string]` | ❌ | Hex-encoded 8-byte short IDs (for advanced users, optional). |
| `xver` | `uint` | ❌ | PROXY protocol version (0, 1, or 2). Default: `0`. |
| `type` | `string` | ❌ | Network type of the fallback (`"tcp"` or `"unix"`). Auto-detected from `dest`. |
| `show` | `bool` | ❌ | Print debug output. Default: `false`. |
| `masterKeyLog` | `string` | ❌ | Path to write TLS master secrets (debugging only). |

### Client-side fields (`"phantomSettings"` in an outbound)

| Field | Type | Required | Description |
|---|---|---|---|
| `serverName` | `string` | ✅ | SNI presented to the server. Must match a value in `serverNames`. |
| `password` | `string` | Either this or `publicKey` | Shared secret for automatic key derivation. |
| `publicKey` | `string` | Either this or `password` | Base64url-encoded 32-byte X25519 public key (for advanced users). |
| `fingerprint` | `string` | ❌ | uTLS fingerprint. Default: `"chrome"`. Supported values: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `randomized`. |
| `shortId` | `string` | ❌ | Hex-encoded 8-byte short ID (must match one of server's `shortIds` if set). |
| `padding` | `bool` | ❌ | Enable random traffic padding. Recommended. Default: `false`. |
| `show` | `bool` | ❌ | Print debug output. Default: `false`. |
| `masterKeyLog` | `string` | ❌ | Path to write TLS master secrets (debugging only). |

---

## How It Works

### Authentication

Phantom uses the same handshake authentication mechanism as REALITY:

1. The client computes an **ECDH shared secret** using the server's X25519 public
   key and the ephemeral key in the TLS ClientHello.
2. The shared secret is fed through **HKDF-SHA256** with the label `"REALITY"` to
   produce an *auth key*.
3. The client encrypts the first 16 bytes of the TLS session ID with AES-GCM
   keyed by the auth key.
4. The server decrypts the session ID; if decryption succeeds the client is
   authentic.  Otherwise the connection is forwarded to the fallback destination.

The `"REALITY"` HKDF label is the same as in REALITY because the xtls/reality
server library hardcodes it.  Protocol differentiation between Phantom and
REALITY is achieved via **password-based key derivation** and **traffic padding**,
not via a different handshake label.

### Password Key Derivation

When `password` is set:

```
privKey = HKDF-SHA256(password, salt=nil, info="phantom-v1-private-key")[:32]
pubKey  = X25519(privKey)
```

The same password always produces the same key pair, so no key exchange or
distribution is needed.

> **Security note:** A password-derived key pair provides *symmetric
> pre-shared-secret* security rather than the *asymmetric* security of a
> randomly generated key pair.  For maximum security, generate a random key
> pair with `xray x25519` and distribute the public key to clients.

### Traffic Padding

When `padding: true` is set on the client, the reserved byte of the TLS session
ID is randomised (instead of always being `0x00`).  This introduces variance in
the handshake byte sequence that can confuse size-based DPI classifiers.

---

## Advanced: Manual Key Generation

If you prefer to use explicit keys (stronger security):

```bash
# Generate a key pair
xray x25519

# Output:
# Private key: <base64url>
# Public key:  <base64url>
```

Server config:

```jsonc
"phantomSettings": {
  "dest": "www.bing.com:443",
  "serverNames": ["www.bing.com"],
  "privateKey": "<private-key-from-above>"
}
```

Client config:

```jsonc
"phantomSettings": {
  "serverName": "www.bing.com",
  "publicKey": "<public-key-from-above>",
  "fingerprint": "chrome"
}
```

---

## Choosing a Fallback Destination

The fallback destination (`dest`) should be:

- A **real, popular HTTPS website** that the server can reach.
- One that supports **TLS 1.3 and HTTP/2**.
- Its hostname must appear in `serverNames`.
- Avoid using websites associated with hosting providers or known proxy services.

Good choices: `www.bing.com`, `www.cloudflare.com`, `www.amazon.com`

---

## Comparison with REALITY

Phantom and REALITY share the same core handshake design.  The differences are:

1. **Password vs key pair**: Phantom lets you use a password; REALITY requires
   manual key generation.
2. **HKDF label**: Both use `"REALITY"` (required for server-library compatibility).
   Protocol differentiation comes from password-derived keys and traffic padding.
3. **Default fingerprint**: Phantom defaults to `chrome`; REALITY requires
   explicit configuration.
4. **Traffic padding**: Phantom supports optional random padding in the session
   ID reserved byte.

A server cannot serve both REALITY and Phantom on the same port because they use
different X25519 key pairs (unless the same key pair is configured on both).

If you use `password` on both sides, both will derive the same key pair, so it's
self-consistent.  A Phantom client with a matching password CAN authenticate to
a Phantom server.

---

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)
