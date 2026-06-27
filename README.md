# libhttp

A lightweight, single-file HTTP(S) client written in C++. No libcurl dependency - TLS is handled directly via OpenSSL, BoringSSL, or mbedTLS, with manual socket and request/response handling.

## Features

- HTTP and HTTPS support (TLS 1.2/1.3)
- GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
- Custom headers (`-H`)
- Redirect following (`-L`)
- TLS certificate verification bypass (`-k`)
- Custom CA bundle (`--cacert`)
- Silent mode for scripting (`-s`)
- Request body from argument, file (`@file`), or stdin
- Automatic gzip/deflate decompression
- Chunked transfer-encoding support

## Build

### Desktop (OpenSSL)

```bash
g++ -O2 -o http http.cpp -lssl -lcrypto -lz
```

### Desktop (mbedTLS)

```bash
g++ -O2 -o http http.cpp -lmbedtls -lmbedx509 -lmbedcrypto -lz
```

### Android (Android Studio)

Cloning and open the project in Android Studio and build normally (`Build > Make Project`). mbedTLS is vendored under `src/main/cpp/third_party/mbedtls` - no internet connection required at build time.

**Project structure:**
```
src/main/cpp/
├── CMakeLists.txt
├── http.cpp
├── mbedtls_config.h
└── third_party/
    └── mbedtls/
```

## Usage

```
http [-L] [-k] [-s] [--cacert FILE] [-H 'Name: Value']... METHOD URL [BODY]
```

### Options

| Flag | Description |
|------|-------------|
| `-L` | Follow redirects (3xx responses) |
| `-k` | Skip TLS certificate verification |
| `-s` | Silent mode — print response body only |
| `--cacert FILE` | Use a custom CA bundle for TLS verification |
| `-H 'Name: Value'` | Add a request header (repeatable) |

### Methods

`GET` `POST` `PUT` `PATCH` `DELETE` `OPTIONS` `HEAD`

## Examples

```bash
# Simple GET
http GET https://example.com

# Follow redirects
http -L GET https://example.com

# Skip TLS verification
http -k GET https://example.com

# Silent mode (body only, useful for piping)
http -s GET https://example.com

# POST with JSON body
http POST https://example.com '{"key":"value"}'

# Custom header
http -H 'Authorization: Bearer xxx' GET https://api.example.com

# Body from stdin
echo 'body' | http PUT https://example.com

# Body from file
http POST https://example.com @payload.json

# Custom CA bundle
http -cacert /etc/ssl/my-ca.pem GET https://internal.example.com
```

## Output

Response status and headers are printed to **stderr**. The body is printed to **stdout**. Use `-s` to suppress status and headers.

Exit code is `1` if the request fails or the response status is `400` or higher, `0` otherwise.

## TLS / CA certificates

| Platform | Behavior |
|----------|----------|
| Linux/macOS | Auto-detects system CA bundle (`/etc/ssl/certs/ca-certificates.crt`, `/etc/ssl/cert.pem`, etc.) |
| Android | Skips mbedTLS cert verification by default; pass `--cacert <file>` to enable it |
| Any | Use `--cacert <file>` to supply a custom bundle, or `-k` to disable verification entirely |

## Notes

- URLs must include the scheme (`http://` or `https://`).
- Connections use `Connection: close`; persistent connections are not supported.
- Minimal implementation intended for scripting and embedded use, not a general-purpose curl replacement.
