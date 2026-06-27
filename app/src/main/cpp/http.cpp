//
// Created by binhmod on 2026/6/27.
// Refactored: BoringSSL -> mbedTLS
//
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>

// mbedTLS headers
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/debug.h>

#include <zlib.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>

static void die(const char* msg) {
    fprintf(stderr, "http: %s\n", msg);
    exit(1);
}

static int dnsResolve(const std::string& host,
                      sockaddr_storage& out, socklen_t& outLen) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) || !res)
        return -1;

    outLen = (socklen_t)res->ai_addrlen;
    memcpy(&out, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    return 0;
}

static void setPort(sockaddr_storage& addr, int port) {
    if (addr.ss_family == AF_INET)
        ((sockaddr_in*)&addr)->sin_port = htons((uint16_t)port);
    else if (addr.ss_family == AF_INET6)
        ((sockaddr_in6*)&addr)->sin6_port = htons((uint16_t)port);
}

static int tcpConnect(sockaddr_storage& addr, socklen_t addrLen, int timeoutSec) {
    int fd = socket(addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(fd, (const sockaddr*)&addr, addrLen);
    if (ret < 0 && errno != EINPROGRESS) { close(fd); return -1; }

    pollfd pfd{fd, POLLOUT, 0};
    if (poll(&pfd, 1, timeoutSec * 1000) <= 0) { close(fd); return -1; }

    int err = 0;
    socklen_t errLen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errLen);
    if (err != 0) { close(fd); return -1; }

    fcntl(fd, F_SETFL, flags);
    return fd;
}

static std::string gunzip(const std::string& compressed) {
    if (compressed.empty()) return "";

    z_stream s{};
    s.next_in  = (Bytef*)compressed.data();
    s.avail_in = (uInt)compressed.size();

    if (inflateInit2(&s, 16 + MAX_WBITS) != Z_OK) return "";

    std::string out;
    char buf[4096];
    int r;
    do {
        s.next_out  = (Bytef*)buf;
        s.avail_out = sizeof(buf);
        r = inflate(&s, Z_NO_FLUSH);
        if (r == Z_STREAM_ERROR || r == Z_DATA_ERROR || r == Z_MEM_ERROR) break;
        out.append(buf, sizeof(buf) - s.avail_out);
    } while (r != Z_STREAM_END);

    inflateEnd(&s);
    return out;
}

static std::string dechunk(const std::string& chunked) {
    std::string out;
    size_t pos = 0;
    while (pos < chunked.size()) {
        size_t lineEnd = chunked.find("\r\n", pos);
        if (lineEnd == std::string::npos) break;

        long chunkSize = strtol(chunked.c_str() + pos, nullptr, 16);
        if (chunkSize <= 0) break;

        pos = lineEnd + 2;
        if (pos + (size_t)chunkSize > chunked.size()) break;
        out.append(chunked, pos, (size_t)chunkSize);
        pos += (size_t)chunkSize + 2;
    }
    return out;
}

struct Header {
    std::string name;
    std::string value;
};

struct HttpResponse {
    int status = 0;
    std::vector<Header> headers;
    std::string body;
};

struct HttpRequest {
    std::string method;
    std::string url;
    std::string body;
    std::string cacert;
    std::vector<Header> headers;
    int  timeoutSec      = 30;
    bool followRedirects = false;
    int  maxRedirects    = 10;
    int  redirectCount   = 0;
    bool insecure        = false;
    bool silent          = false;
};

static std::string getHeader(const std::vector<Header>& hdrs,
                             const std::string& name) {
    std::string nl = name;
    std::transform(nl.begin(), nl.end(), nl.begin(), ::tolower);
    for (auto& h : hdrs) {
        std::string hl = h.name;
        std::transform(hl.begin(), hl.end(), hl.begin(), ::tolower);
        if (hl == nl) return h.value;
    }
    return "";
}

static HttpResponse parseResponse(const std::string& raw) {
    HttpResponse r;
    size_t hdrEnd = raw.find("\r\n\r\n");
    if (hdrEnd == std::string::npos) return r;

    std::string headerBlock = raw.substr(0, hdrEnd);

    size_t sp1 = headerBlock.find(' ');
    if (sp1 == std::string::npos) return r;
    r.status = (int)strtol(headerBlock.c_str() + sp1 + 1, nullptr, 10);

    size_t pos = headerBlock.find("\r\n") + 2;
    while (pos < headerBlock.size()) {
        size_t lineEnd = headerBlock.find("\r\n", pos);
        if (lineEnd == std::string::npos || lineEnd == pos) break;

        std::string line = headerBlock.substr(pos, lineEnd - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name  = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            while (!value.empty() && value[0] == ' ') value.erase(0, 1);
            r.headers.push_back({name, value});
        }
        pos = lineEnd + 2;
    }

    r.body = raw.substr(hdrEnd + 4);

    std::string te = getHeader(r.headers, "Transfer-Encoding");
    std::transform(te.begin(), te.end(), te.begin(), ::tolower);
    if (te.find("chunked") != std::string::npos)
        r.body = dechunk(r.body);

    return r;
}

struct TlsCtx {
    mbedtls_ssl_context      ssl{};
    mbedtls_ssl_config       conf{};
    mbedtls_x509_crt         cacert{};
    mbedtls_entropy_context  entropy{};
    mbedtls_ctr_drbg_context ctr_drbg{};
    bool                     initialized = false;

    TlsCtx() {
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
    }

    ~TlsCtx() {
        if (initialized) mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }

    // Non-copyable
    TlsCtx(const TlsCtx&)            = delete;
    TlsCtx& operator=(const TlsCtx&) = delete;
};

// mbedTLS send/recv callbacks that wrap a plain fd
static int mbedSend(void* ctx, const unsigned char* buf, size_t len) {
    int fd = *(int*)ctx;
    int r  = (int)write(fd, buf, len);
    if (r < 0) return MBEDTLS_ERR_NET_SEND_FAILED;
    return r;
}

static int mbedRecv(void* ctx, unsigned char* buf, size_t len) {
    int fd = *(int*)ctx;
    int r  = (int)read(fd, buf, len);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return r;
}

static bool httpRequest(HttpRequest& req, HttpResponse& resp) {

    bool useTls = false;
    std::string host, path;
    int port = 80;

    if (req.url.find("https://") == 0) {
        useTls = true; port = 443;
    } else if (req.url.find("http://") == 0) {
        useTls = false;
    } else {
        die("URL must start with http:// or https://");
    }

    size_t schemeEnd = req.url.find("://") + 3;
    size_t pathStart = req.url.find('/', schemeEnd);
    std::string hostPart = (pathStart != std::string::npos)
        ? req.url.substr(schemeEnd, pathStart - schemeEnd)
        : req.url.substr(schemeEnd);
    path = (pathStart != std::string::npos)
        ? req.url.substr(pathStart) : "/";

    if (!hostPart.empty() && hostPart[0] == '[') {
        size_t bracketEnd = hostPart.find(']');
        host = hostPart.substr(1, bracketEnd - 1);
        if (bracketEnd + 1 < hostPart.size() && hostPart[bracketEnd + 1] == ':')
            port = (int)strtol(hostPart.c_str() + bracketEnd + 2, nullptr, 10);
    } else {
        size_t colon = hostPart.rfind(':');
        if (colon != std::string::npos) {
            host = hostPart.substr(0, colon);
            port = (int)strtol(hostPart.c_str() + colon + 1, nullptr, 10);
        } else {
            host = hostPart;
        }
    }

    sockaddr_storage addr{};
    socklen_t addrLen = 0;
    if (dnsResolve(host, addr, addrLen) < 0) {
        fprintf(stderr, "http: DNS fail for %s\n", host.c_str());
        return false;
    }
    setPort(addr, port);

    int fd = tcpConnect(addr, addrLen, req.timeoutSec);
    if (fd < 0) {
        fprintf(stderr, "http: TCP connect failed\n");
        return false;
    }

    TlsCtx tls;
    if (useTls) {
        const char* pers = "http_client";
        int ret;

        ret = mbedtls_ctr_drbg_seed(&tls.ctr_drbg, mbedtls_entropy_func,
                                     &tls.entropy,
                                     (const unsigned char*)pers, strlen(pers));
        if (ret != 0) {
            fprintf(stderr, "http: mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
            close(fd); return false;
        }

        ret = mbedtls_ssl_config_defaults(&tls.conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            fprintf(stderr, "http: mbedtls_ssl_config_defaults failed: -0x%04x\n", -ret);
            close(fd); return false;
        }

        mbedtls_ssl_conf_rng(&tls.conf, mbedtls_ctr_drbg_random, &tls.ctr_drbg);

        if (req.insecure) {
            mbedtls_ssl_conf_authmode(&tls.conf, MBEDTLS_SSL_VERIFY_NONE);
        } else {
#if defined(__ANDROID__)
            // Android raw socket bypasses the framework trust store.
            // If --cacert is supplied, use it; otherwise skip mbedTLS cert
            // verification and let the app layer handle trust via the platform.
            if (!req.cacert.empty()) {
                ret = mbedtls_x509_crt_parse_file(&tls.cacert, req.cacert.c_str());
                if (ret != 0) {
                    fprintf(stderr, "http: cannot load -cacert %s: -0x%04x\n",
                            req.cacert.c_str(), -ret);
                    close(fd); return false;
                }
                mbedtls_ssl_conf_ca_chain(&tls.conf, &tls.cacert, nullptr);
                mbedtls_ssl_conf_authmode(&tls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
            } else {
                mbedtls_ssl_conf_authmode(&tls.conf, MBEDTLS_SSL_VERIFY_NONE);
            }
#else
            // Desktop: -cacert takes priority, then probe system bundle paths.
            if (!req.cacert.empty()) {
                ret = mbedtls_x509_crt_parse_file(&tls.cacert, req.cacert.c_str());
                if (ret != 0) {
                    fprintf(stderr, "http: cannot load -cacert %s: -0x%04x\n",
                            req.cacert.c_str(), -ret);
                    close(fd); return false;
                }
            } else {
                const char* caFiles[] = {
                    "/etc/ssl/certs/ca-certificates.crt",   // Debian/Ubuntu
                    "/etc/pki/tls/certs/ca-bundle.crt",     // RHEL/CentOS
                    "/etc/ssl/ca-bundle.pem",                // openSUSE
                    "/etc/ssl/cert.pem",                     // macOS/Alpine
                    nullptr
                };
                bool loaded = false;
                for (int i = 0; caFiles[i]; ++i) {
                    if (mbedtls_x509_crt_parse_file(&tls.cacert, caFiles[i]) == 0) {
                        loaded = true; break;
                    }
                }
                if (!loaded) {
                    fprintf(stderr, "http: no CA bundle found - use -cacert <file> or -k\n");
                    close(fd); return false;
                }
            }
            mbedtls_ssl_conf_ca_chain(&tls.conf, &tls.cacert, nullptr);
            mbedtls_ssl_conf_authmode(&tls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#endif
        }

        ret = mbedtls_ssl_setup(&tls.ssl, &tls.conf);
        if (ret != 0) {
            fprintf(stderr, "http: mbedtls_ssl_setup failed: -0x%04x\n", -ret);
            close(fd); return false;
        }

        ret = mbedtls_ssl_set_hostname(&tls.ssl, host.c_str());
        if (ret != 0) {
            fprintf(stderr, "http: mbedtls_ssl_set_hostname failed: -0x%04x\n", -ret);
            close(fd); return false;
        }

        // Wire up our plain fd via custom BIO callbacks
        mbedtls_ssl_set_bio(&tls.ssl, &fd, mbedSend, mbedRecv, nullptr);

        // Handshake
        while ((ret = mbedtls_ssl_handshake(&tls.ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                char errBuf[256];
                mbedtls_strerror(ret, errBuf, sizeof(errBuf));
                fprintf(stderr, "http: TLS handshake failed: %s\n", errBuf);
                fprintf(stderr, "http: tip - use -k to skip cert verify\n");
                close(fd); return false;
            }
        }
        tls.initialized = true;

        // Verify peer cert result
        if (!req.insecure) {
            uint32_t flags = mbedtls_ssl_get_verify_result(&tls.ssl);
            if (flags != 0) {
                char vrfBuf[512];
                mbedtls_x509_crt_verify_info(vrfBuf, sizeof(vrfBuf), "  ! ", flags);
                fprintf(stderr, "http: certificate verify failed:\n%s\n", vrfBuf);
                fprintf(stderr, "http: tip - use -k to skip cert verify\n");
                close(fd); return false;
            }
        }
    }

    auto tlsWrite = [&](const void* data, size_t len) -> int {
        if (!useTls) return (int)write(fd, data, len);
        int r;
        do {
            r = mbedtls_ssl_write(&tls.ssl,
                                  (const unsigned char*)data, len);
        } while (r == MBEDTLS_ERR_SSL_WANT_WRITE ||
                 r == MBEDTLS_ERR_SSL_WANT_READ);
        return r;
    };

    auto tlsRead = [&](char* buf, int maxLen) -> int {
        if (!useTls) return (int)read(fd, buf, (size_t)maxLen);
        int r = mbedtls_ssl_read(&tls.ssl,
                                 (unsigned char*)buf, (size_t)maxLen);
        if (r == MBEDTLS_ERR_SSL_WANT_READ ||
            r == MBEDTLS_ERR_SSL_WANT_WRITE) return 0; // retry
        if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0; // EOF
        return r; // negative = error, positive = bytes
    };

    std::string httpReq;
    httpReq.reserve(1024 + req.body.size());
    httpReq += req.method + " " + path + " HTTP/1.1\r\n";
    httpReq += "Host: " + host + "\r\n";

    bool hasContentType   = false;
    bool hasContentLength = false;

    for (auto& h : req.headers) {
        httpReq += h.name + ": " + h.value + "\r\n";
        std::string lower = h.name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower == "content-type")   hasContentType   = true;
        if (lower == "content-length") hasContentLength = true;
    }

    if (!hasContentType && !req.body.empty())
        httpReq += "Content-Type: application/x-www-form-urlencoded\r\n";
    if (!hasContentLength)
        httpReq += "Content-Length: " + std::to_string(req.body.size()) + "\r\n";

    httpReq += "Accept-Encoding: gzip, deflate\r\n";
    httpReq += "Connection: close\r\n";
    httpReq += "\r\n";
    httpReq += req.body;

    int totalSent = 0;
    while (totalSent < (int)httpReq.size()) {
        int n = tlsWrite(httpReq.data() + totalSent,
                         httpReq.size() - (size_t)totalSent);
        if (n <= 0) goto cleanup;
        totalSent += n;
    }

    {
        std::string raw;
        raw.reserve(8192);
        char buf[4096];

        // Read until we have full headers
        while (raw.find("\r\n\r\n") == std::string::npos) {
            int n = tlsRead(buf, sizeof(buf));
            if (n > 0) { raw.append(buf, (size_t)n); continue; }
            if (n < 0) break;
            // n == 0 -> WANT_READ, keep polling
        }

        size_t hdrEnd = raw.find("\r\n\r\n");
        if (hdrEnd == std::string::npos) {
            fprintf(stderr, "http: incomplete headers\n");
            goto cleanup;
        }

        std::string headerBlock = raw.substr(0, hdrEnd);
        std::string initialBody = raw.substr(hdrEnd + 4);

        int64_t contentLength = -1;
        bool isChunked  = false;
        bool isGzipped  = false;

        {
            size_t pos = headerBlock.find("\r\n") + 2;
            while (pos < headerBlock.size()) {
                size_t lineEnd = headerBlock.find("\r\n", pos);
                if (lineEnd == std::string::npos || lineEnd == pos) break;

                std::string line = headerBlock.substr(pos, lineEnd - pos);
                size_t colon = line.find(':');
                if (colon != std::string::npos) {
                    std::string name  = line.substr(0, colon);
                    std::string value = line.substr(colon + 1);
                    while (!value.empty() && value[0] == ' ') value.erase(0, 1);

                    std::string nl = name, vl = value;
                    std::transform(nl.begin(), nl.end(), nl.begin(), ::tolower);
                    std::transform(vl.begin(), vl.end(), vl.begin(), ::tolower);

                    if (nl == "content-length")
                        contentLength = strtoll(value.c_str(), nullptr, 10);
                    else if (nl == "transfer-encoding" &&
                             vl.find("chunked") != std::string::npos)
                        isChunked = true;
                    else if (nl == "content-encoding" &&
                             (vl.find("gzip") != std::string::npos ||
                              vl.find("deflate") != std::string::npos))
                        isGzipped = true;
                }
                pos = lineEnd + 2;
            }
        }

        std::string fullBody = initialBody;

        if (!isChunked && contentLength >= 0) {
            while ((int64_t)fullBody.size() < contentLength) {
                int n = tlsRead(buf, sizeof(buf));
                if (n > 0) { fullBody.append(buf, (size_t)n); continue; }
                if (n < 0) break;
            }
        } else {
            while (true) {
                int n = tlsRead(buf, sizeof(buf));
                if (n > 0) { fullBody.append(buf, (size_t)n); continue; }
                if (n == 0 && !useTls) break; // plain socket EOF
                if (n < 0) break;
            }
        }

        resp = parseResponse(headerBlock + "\r\n\r\n" + fullBody);
        if (isGzipped && !resp.body.empty())
            resp.body = gunzip(resp.body);

        if (req.followRedirects && req.redirectCount < req.maxRedirects) {
            int st = resp.status;
            if (st == 301 || st == 302 || st == 303 ||
                st == 307 || st == 308) {

                std::string location = getHeader(resp.headers, "Location");
                if (!location.empty()) {
                    HttpRequest rr = req;
                    rr.url = location;
                    rr.redirectCount++;

                    if (st == 301 || st == 302 || st == 303) {
                        rr.method = "GET";
                        rr.body.clear();
                        rr.headers.erase(
                            std::remove_if(rr.headers.begin(), rr.headers.end(),
                                [](const Header& h) {
                                    std::string l = h.name;
                                    std::transform(l.begin(), l.end(),
                                                   l.begin(), ::tolower);
                                    return l == "content-type" ||
                                           l == "content-length";
                                }),
                            rr.headers.end());
                    }

                    if (!req.silent)
                        fprintf(stderr, "http: redirect -> %s\n", location.c_str());

                    // TlsCtx destructor handles SSL shutdown automatically
                    close(fd);
                    return httpRequest(rr, resp);
                }
            }
        }
    }

cleanup:
    // TlsCtx destructor calls mbedtls_ssl_close_notify + frees everything
    close(fd);
    return resp.status > 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr,
            "libhttp v1.1 (mbedTLS) - github.com/binhmod/libhttp\n"
            "\n"
            "Usage:\n"
            "  http [-L] [-k] [-s] [--cacert FILE] [-H 'Name: Value']... METHOD URL [BODY]\n"
            "\n"
            "Options:\n"
            "  -L              follow redirects\n"
            "  -k              skip TLS certificate verification\n"
            "  -s              silent mode (print body only, no status/headers)\n"
            "  --cacert FILE   use FILE as the CA bundle for TLS verification\n"
            "  -H 'Name: Val'  add a request header (repeatable)\n"
            "\n"
            "Methods:\n"
            "  GET POST PUT PATCH DELETE OPTIONS HEAD\n"
            "\n"
            "Examples:\n"
            "  http GET https://example.com\n"
            "  http -L GET https://example.com\n"
            "  http -k GET https://example.com\n"
            "  http -s GET https://example.com\n"
            "  http POST https://example.com '{\"key\":\"value\"}'\n"
            "  http -H 'Authorization: Bearer xxx' GET https://api.example.com\n"
            "  echo 'body' | http PUT https://example.com\n"
        );
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    HttpRequest req;
    int idx = 1;

    while (idx < argc) {
        if (!strcmp(argv[idx], "-L")) {
            req.followRedirects = true;
            idx++;
        } else if (!strcmp(argv[idx], "-k")) {
            req.insecure = true;
            idx++;
        } else if (!strcmp(argv[idx], "-s")) {
            req.silent = true;
            idx++;
        } else if (!strcmp(argv[idx], "--cacert") && idx + 1 < argc) {
            req.cacert = argv[idx + 1];
            idx += 2;
        } else if (!strcmp(argv[idx], "-H") && idx + 1 < argc) {
            std::string hv = argv[idx + 1];
            size_t colon = hv.find(':');
            if (colon != std::string::npos) {
                std::string name  = hv.substr(0, colon);
                std::string value = hv.substr(colon + 1);
                while (!value.empty() && value[0] == ' ') value.erase(0, 1);
                req.headers.push_back({name, value});
            }
            idx += 2;
        } else {
            break;
        }
    }

    if (idx >= argc) die("Missing METHOD");
    req.method = argv[idx++];
    for (auto& c : req.method) c = (char)toupper((unsigned char)c);

    if (idx >= argc) die("Missing URL");
    req.url = argv[idx++];

    if (idx < argc) {
        req.body = argv[idx++];
        if (!req.body.empty() && req.body[0] == '@') {
            std::string filepath = req.body.substr(1);
            FILE* f = fopen(filepath.c_str(), "rb");
            if (!f) {
                fprintf(stderr, "http: cannot open %s\n", filepath.c_str());
                return 1;
            }
            fseek(f, 0, SEEK_END);
            long fsize = ftell(f);
            fseek(f, 0, SEEK_SET);
            req.body.resize((size_t)fsize);
            fread(&req.body[0], 1, (size_t)fsize, f);
            fclose(f);
        }
    } else if (req.method == "POST" || req.method == "PUT" ||
               req.method == "PATCH") {
        if (!isatty(STDIN_FILENO)) {
            char b[4096]; ssize_t n;
            while ((n = read(STDIN_FILENO, b, sizeof(b))) > 0)
                req.body.append(b, (size_t)n);
        }
    }

    HttpResponse resp;
    if (!httpRequest(req, resp)) {
        fprintf(stderr, "http: request failed\n");
        return 1;
    }

    if (!req.silent) {
        fprintf(stderr, "HTTP/1.1 %d\n", resp.status);
        for (auto& h : resp.headers)
            fprintf(stderr, "%s: %s\n", h.name.c_str(), h.value.c_str());
    }

    if (req.method != "HEAD" && !resp.body.empty()) {
        fwrite(resp.body.data(), 1, resp.body.size(), stdout);
        if (resp.body.back() != '\n') fputc('\n', stdout);
    }

    fflush(stdout);
    return resp.status >= 400 ? 1 : 0;
}
