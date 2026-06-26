# libhttp

A lightweight, single-file HTTP(S) client written in C++. No libcurl dependency — TLS is handled directly via BoringSSL/OpenSSL, with manual socket and request/response handling.

## Features

- HTTP and HTTPS support (TLS 1.x via OpenSSL/BoringSSL)
- GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
- Custom headers
- Redirect following (`-L`)
- Optional TLS certificate verification bypass (`-k`)
- Custom CA bundle (`--cacert`)
- Silent mode for scripting (`-s`)
- Request body from argument, file (`@file`), or stdin
- Automatic gzip/deflate decompression
- Chunked transfer-encoding support

## Build

```bash
g++ -o http http.cpp -lssl -lcrypto -lz
```

Requires OpenSSL (or BoringSSL) and zlib development headers.

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

`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`

## Examples

Simple GET request:

```bash
http GET https://example.com
```

Follow redirects:

```bash
http -L GET https://example.com
```

Skip TLS certificate verification:

```bash
http -k GET https://example.com
```

Silent mode (body only, useful for piping):

```bash
http -s GET https://example.com
```

POST with a JSON body:

```bash
http POST https://example.com '{"key":"value"}'
```

Custom headers:

```bash
http -H 'Authorization: Bearer xxx' GET https://api.example.com
```

Body from stdin:

```bash
echo 'body' | http PUT https://example.com
```

Body from a file:

```bash
http POST https://example.com @payload.json
```

## Output

By default, the response status line and headers are printed to stderr, and the body is printed to stdout. Use `-s` to suppress everything except the body.

Exit code is `1` if the request fails or the response status is `400` or higher, otherwise `0`.

## Notes

- URLs must include the scheme (`http://` or `https://`).
- Connections are made with `Connection: close`; this client does not reuse connections.
- This is a minimal implementation intended for scripting and debugging, not a general-purpose replacement for curl.
