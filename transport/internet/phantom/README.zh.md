# Phantom（幻）—— 易用版 REALITY 分叉协议

**Phantom** 是内置于 Xray-core 的 TLS 拟态安全层，派生自 [REALITY](https://github.com/XTLS/REALITY) 协议。

## 为什么选择 Phantom？

| 特性 | REALITY | Phantom |
|---|---|---|
| 密钥配置 | 需要手动生成并分发 X25519 密钥对 | ✅ 密码自动派生密钥，无需手动生成 |
| 服务端必填字段 | `serverNames`、`privateKey`、`shortIds`、`dest` | `serverNames`、`password`、`dest` |
| 客户端必填字段 | `serverName`、`publicKey`、`shortId`、`fingerprint` | `serverName`、`password` |
| 默认指纹 | 必须手动指定 | 默认 `chrome`，可省略 |
| 浏览器爬虫模拟 | ✅ 支持（需配置 spiderX） | ✅ 支持（配置同 REALITY，默认更合理） |
| 握手填充 | ✗ | ✅ 可选（`padding: true`） |
| TLS 1.3 uTLS 拟态 | ✅ | ✅ |
| 后量子密钥交换（ML-KEM） | ✅ | ✅（继承自 uTLS 指纹） |
| 与 REALITY 互通 | — | ❌（使用密码派生的独立密钥对） |

---

## 快速开始

### 第一步：选择密码

双端共享一个密码即可，密码**不会在网络上传输**，仅用于在本地派生 X25519 密钥对。

```
my-secret-password-here
```

### 第二步：服务端配置

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

> **注意：** `dest` 和 `serverNames` 必须指向服务端能够访问的真实 HTTPS 网站。当非 Phantom 客户端连接时，流量会被无缝转发至该目标，使服务器看起来和普通 HTTPS 服务器完全相同。

### 第三步：客户端配置

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

**就这么简单** — 无需生成密钥，无需管理 shortId。

---

## 配置字段说明

### 服务端字段（入站 `streamSettings.phantomSettings`）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `dest` | `string` | ✅ | 回落目标地址（如 `"www.bing.com:443"`） |
| `serverNames` | `[string]` | ✅ | 允许的 SNI 列表 |
| `password` | `string` | 与 `privateKey` 二选一 | 用于自动派生密钥的共享密码 |
| `privateKey` | `string` | 与 `password` 二选一 | Base64url 编码的 32 字节 X25519 私钥（高级用法） |
| `shortIds` | `[string]` | ❌ | 16 进制编码的 8 字节短 ID 列表（高级用法，可省略） |
| `xver` | `uint` | ❌ | PROXY 协议版本（0、1 或 2），默认 `0` |
| `type` | `string` | ❌ | 回落网络类型（`"tcp"` 或 `"unix"`），自动推断 |
| `spiderX` | `string` | ❌ | 爬虫起始路径，支持查询参数控制行为（见下文） |
| `show` | `bool` | ❌ | 打印调试输出，默认 `false` |
| `masterKeyLog` | `string` | ❌ | TLS 主密钥日志路径（仅调试使用） |

### 客户端字段（出站 `streamSettings.phantomSettings`）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `serverName` | `string` | ✅ | 向服务端发送的 SNI，必须在 `serverNames` 中 |
| `password` | `string` | 与 `publicKey` 二选一 | 用于自动派生密钥的共享密码 |
| `publicKey` | `string` | 与 `password` 二选一 | Base64url 编码的 32 字节 X25519 公钥（高级用法） |
| `fingerprint` | `string` | ❌ | uTLS 指纹，默认 `"chrome"`。可选值：`chrome`、`firefox`、`safari`、`ios`、`android`、`edge`、`360`、`qq`、`randomized` |
| `shortId` | `string` | ❌ | 16 进制 8 字节短 ID（若服务端配置了 `shortIds` 则填写） |
| `padding` | `bool` | ❌ | 启用握手填充，建议开启，默认 `false` |
| `spiderX` | `string` | ❌ | 爬虫起始路径（同服务端） |
| `show` | `bool` | ❌ | 打印调试输出，默认 `false` |
| `masterKeyLog` | `string` | ❌ | TLS 主密钥日志路径（仅调试使用） |

---

## spiderX 参数说明

`spiderX` 是验证失败时启动的浏览器爬虫的起始路径，支持与 REALITY 相同的查询参数格式：

```
/?p=100-200&c=1-3&t=1-2&i=300-600&r=100-400
```

| 参数 | 含义 | 示例 |
|---|---|---|
| `p` | Cookie 填充字节数范围 | `p=100-300` |
| `c` | 并发子请求数量范围 | `c=1-3` |
| `t` | 每个链接的访问次数范围 | `t=1-2` |
| `i` | 访问间隔时间范围（毫秒） | `i=300-600` |
| `r` | 验证失败后返回错误的延迟范围（毫秒） | `r=100-400` |

范围格式为 `min-max`；若只填一个值则作为固定值使用。所有参数均为可选，不填则使用内部默认值。

**爬虫行为：**
1. 首先访问 `spiderX` 指定的起始路径
2. 从页面中提取 `href` 链接，建立 URL 路径池
3. 按 `c` 参数并发启动多个子请求，每个子请求按 `t` 参数随机访问多个页面
4. 每次请求附加随机长度的 Cookie 填充（`p` 参数），使每次 TLS 记录大小不同
5. 按 `i` 参数控制间隔，模拟真实用户浏览节奏

---

## 工作原理

### 握手认证

Phantom 使用与 REALITY 相同的握手认证机制：

1. 客户端利用服务端 X25519 公钥和 TLS ClientHello 中的临时密钥，计算 **ECDH 共享密钥**
2. 共享密钥通过 **HKDF-SHA256**（标签 `"REALITY"`）派生出**认证密钥**
3. 客户端用 AES-GCM 加密 TLS session ID 的前 16 字节，将认证信息嵌入握手
4. 服务端解密 session ID，若成功则认证通过，否则将连接转发至回落目标

### 密码派生密钥

当配置了 `password` 时：

```
私钥 = HKDF-SHA256(password, salt=nil, info="phantom-v1-private-key")[:32]
公钥 = X25519(私钥)
```

相同的密码始终产生相同的密钥对，因此双端只需共享密码，无需传输密钥。

> **安全提示：** 基于密码派生的密钥对属于**对称预共享密钥**安全模型，安全强度取决于密码复杂度。如需更高安全性，可使用 `xray x25519` 生成随机密钥对，并将公钥分发给客户端。

### 握手填充（`padding: true`）

开启 `padding` 后，每次握手的 TLS session ID 保留字节会被随机化（而非固定为 `0x00`），从而在握手字节序列中引入逐连接的随机变化，干扰基于大小特征的 DPI 分类器。

---

## 高级用法：手动生成密钥对

如需使用显式密钥（安全性更强）：

```bash
# 生成密钥对
xray x25519

# 输出示例：
# Private key: <base64url>
# Public key:  <base64url>
```

服务端配置：

```jsonc
"phantomSettings": {
  "dest": "www.bing.com:443",
  "serverNames": ["www.bing.com"],
  "privateKey": "<上面生成的私钥>"
}
```

客户端配置：

```jsonc
"phantomSettings": {
  "serverName": "www.bing.com",
  "publicKey": "<上面生成的公钥>",
  "fingerprint": "chrome"
}
```

---

## 如何选择回落目标（dest）

回落目标应满足：

- 是**真实的、访问量大的 HTTPS 网站**，且服务端能正常访问
- 支持 **TLS 1.3 和 HTTP/2**
- 其域名必须出现在 `serverNames` 中
- 避免使用与托管服务商或已知代理服务相关的网站

推荐选择：`www.bing.com`、`www.cloudflare.com`、`www.amazon.com`、`www.microsoft.com`

---

## 与 REALITY 的对比

Phantom 与 REALITY 共享相同的核心握手设计，主要区别如下：

1. **密钥配置**：Phantom 支持密码自动派生；REALITY 需要手动生成并分发密钥对
2. **默认指纹**：Phantom 默认 `chrome`；REALITY 必须显式指定
3. **握手填充**：Phantom 支持可选的 session ID 随机化；REALITY 无此功能
4. **爬虫质量**：Phantom 的验证失败爬虫与 REALITY 同等精细（多页、并发、Cookie 填充、链接跟踪）

---

## 许可证

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)
