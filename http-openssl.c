#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <ctype.h>

#include "http.h"
#include "config.h"

#ifndef DEFAULT_CA_FILE
# define DEFAULT_CA_FILE "/etc/ssl/cert.pem"
#endif

struct httpcfg {
    SSL_CTX *ssl_config;
};

struct httpxfer {
    char *response;
    size_t response_size;
};

struct http {
    BIO *web;
    SSL *ssl;
    char *host;
    char *path;
};

int openssl_error_print(const char *error, size_t error_length, void *buffer)
{
    (void)buffer;

    warnx("%s\n", error);

    return (int)error_length;
}

void openssl_error_report(const char *error)
{
    warnx("%s\n", error);
    ERR_print_errors_cb(openssl_error_print, NULL);
}

int openssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    int err = X509_STORE_CTX_get_error(ctx);

    if (err != X509_V_OK) {
        warnx("Certificate verification failed with result: [%d] %s\n", err, X509_verify_cert_error_string(err));
    }

    return preverify_ok;
}

SSL *ssl_connect(BIO *web, const char *hostname)
{
    SSL *ssl = NULL;

    BIO_get_ssl(web, &ssl);
    if (ssl == NULL) {
        openssl_error_report("Unable to get SSL for BIO");

        return NULL;
    }

    if (SSL_set_tlsext_host_name(ssl, hostname) != 1) {
        openssl_error_report("Unable to set SNI hostname");

        return NULL;
    }

    if (BIO_do_connect(web) != 1) {
        openssl_error_report("Unable to connect BIO");

        return NULL;
    }

    if (BIO_do_handshake(web) != 1) {
        openssl_error_report("SSL BIO handshake failed");

        return NULL;
    }

    return ssl;
}

struct http *http_alloc(
    struct httpcfg *cfg,
    const struct source *addrs,
    size_t addrsz,
    const char *host,
    short port,
    const char *path
) {
    long res = -1;
    BIO *web = NULL;
    SSL *ssl = NULL;
    char *socket = NULL;
    struct http *result = NULL;

    if (asprintf(&socket, "%s:%d", addrs->ip, port) == -1) {
        warn("Unable to allocate memory for socket address.\n");

        goto fail;
    }

    web = BIO_new_ssl_connect(cfg->ssl_config);
    if(web == NULL) {
        openssl_error_report("Unable to create SSL BIO");

        goto fail;
    }

    res = BIO_set_conn_hostname(web, socket);
    if (res != 1) {
        openssl_error_report("Unable to connect BIO");

        goto fail;
    }

    free(socket);

    ssl = ssl_connect(web, host);
    if (ssl == NULL) {
        goto fail;
    }

    result = calloc(1, sizeof(struct http));
    if (result == NULL) {
        warn("Unable to allocate memory for http struct.\n");

        goto fail;
    }

    result->web = web;
    result->ssl = ssl;
    result->host = strdup(host);
    result->path = strdup(path);

    if (result->host == NULL) {
        warn("Unable to duplicate host");

        goto fail;
    }

    if (result->path == NULL) {
        warn("Unable to duplicate path");

        goto fail;
    }

    return result;

fail:
    if (result != NULL) {
        http_free(result);
    } else if (web != NULL) {
        BIO_ssl_shutdown(web);
        BIO_free_all(web);
    }

    if (socket != NULL) {
        free(socket);
    }

    return NULL;
}

void http_free(struct http *p)
{
    if (p == NULL) {
        return;
    }

    if (p->web != NULL) {
        BIO_free_all(p->web);
    }

    if (p->host != NULL) {
        free(p->host);
    }

    if (p->path != NULL) {
        free(p->path);
    }

    free(p);
}

void httpxfer_free(struct httpxfer *p) {
    if (p == NULL) {
        return;
    }

    if (p->response) {
        free(p->response);
    }

    free(p);
}

struct httpxfer *http_open(const struct http *http, const void *p, size_t psz)
{
    struct httpxfer *result = NULL;
    char *request = NULL;
    int bytes_written;

    if (p == NULL) {
        bytes_written = asprintf(&request, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", http->path, http->host);
    } else {
        bytes_written = asprintf(
            &request,
            "POST %s HTTP/1.0\r\nHost: %s\r\nContent-Length: %zu\r\n\r\n",
            http->path,
            http->host,
            psz
        );
    }

    if (bytes_written == -1) {
        warn("Unable to allocate memory for request.\n");

        goto fail;
    }

    bytes_written = BIO_puts(http->web, request);
    if (bytes_written < 0) {
        goto fail;
    }

    if (p != NULL) {
        BIO_puts(http->web, p);
    }

    result = calloc(1, sizeof(struct httpxfer));
    if (result == NULL) {
        warn("Unable to allocate memory for httpxfer.\n");

        goto fail;
    }

fail:
    if (request != NULL) {
        free(request);
    }

    return result;
}

void httphead_free(struct httphead *headers, size_t headers_count)
{
    if (headers == NULL) {
        return;
    }

    for (size_t i = 0; i < headers_count; ++i) {
        if (headers[i].key != NULL) {
            free((void *)headers[i].key);
        }

        if (headers[i].val != NULL) {
            free((void *)headers[i].val);
        }
    }

    free(headers);
}

void http_get_free(struct httpget *g)
{
    if (g == NULL) {
        return;
    }

    http_free(g->http);
    httpxfer_free(g->xfer);
    httphead_free(g->head, g->headsz);

    if (g->bodypart != NULL) {
        free(g->bodypart);
    }

    free(g);
}

char *http_read(const struct http *http, struct httpxfer *xfer, size_t *sz)
{
    size_t len = 0;
    char *response = NULL;
    int read_size;

    do {
        char buff[500];

        read_size = BIO_read(http->web, buff, sizeof(buff));
        if (read_size < 0) {
            goto fail;
        }
        buff[read_size] = '\0';

        if (read_size > 0) {
            char *tmp = realloc(response, len + read_size);
            if (tmp == NULL) {
                goto fail;
            }

            response = tmp;

            memcpy(response + len, &buff, read_size);
            len += read_size;
        }
    } while (read_size > 0 || BIO_should_retry(http->web));

    response[len] = '\0';
    *sz = (size_t)len;

    return response;

fail:
    if (response != NULL) {
        free(response);
    }

    return NULL;
}

char *http_head_read(const struct http *http, struct httpxfer *xfer, size_t *sz)
{
    char *head;
    char *header_end;
    size_t header_length;

    header_end = strstr(xfer->response, "\r\n\r\n");
    if (header_end == NULL) {
        return NULL;
    }

    header_length = header_end - xfer->response + 2;

    head = calloc(header_length + 1, sizeof(char));
    if (head == NULL) {
        return NULL;
    }

    strncpy(head, xfer->response, header_length);
    *sz = header_length;

    return head;
}

char *http_body_read(const struct http *http, struct httpxfer *xfer, size_t *sz)
{
    char *body;
    char *body_start;
    size_t body_start_position;
    size_t body_size;

    body_start = strstr(xfer->response, "\r\n\r\n");
    if (body_start == NULL) {
        return NULL;
    }

    body_start_position = body_start - xfer->response + 4;
    body_size = xfer->response_size - body_start_position;

    body = calloc(body_size + 1, sizeof(char));
    if (body == NULL) {
        return NULL;
    }

    strncpy(body, xfer->response + body_start_position, body_size);
    *sz = body_size;

    return body;
}

char *header_part(const char **headers_buff, char needle)
{
    const char *buff = *headers_buff;
    char *end = NULL;
    char *part = NULL;
    char *tmp = NULL;

    part = calloc(1, sizeof(char));
    if (part == NULL) {
        warnx("Failed to allocate memory for header part\n");

        return NULL;
    }

    end = strchr(buff, needle);
    if (end == NULL) {
        return part;
    }

    tmp = realloc(part, sizeof(char) * (end - buff + 1));
    if (tmp == NULL) {
        warnx("Failed to allocate memory for header key/value\n");
        free(part);

        return NULL;
    }

    part = tmp;
    strncpy(part, buff, end - buff);

    while(end != 0 && isspace(*(++end)));

    *headers_buff = end;

    return part;
}

struct httphead *headers_parse(const char *headers_buff, size_t headers_count)
{
    struct httphead *headers = NULL;
    size_t header = 0;

    headers = calloc(headers_count, sizeof(struct httphead));
    if (headers == NULL) {
        warn("Unable to allocate memory for httphead\n");

        return NULL;
    }

    while (*headers_buff) {
        char *key;
        key = header_part(&headers_buff, ':');

        if (key == NULL) {
            goto fail;
        }

        if (*key == 0) {
            warnx("Malformed header detected\n");

            continue;
        }

        char *value;
        value = header_part(&headers_buff, '\r');
        if (value == NULL) {
            goto fail;
        }

        headers[header].key = key;
        headers[header++].val = value;
    }

    return headers;

fail:
    httphead_free(headers, header);

    return NULL;
}

struct httphead *http_head_parse(const struct http *http, struct httpxfer *xfer, size_t *sz)
{
    char *headers_buff = NULL;
    char *headers_end = NULL;
    struct httphead *headers = NULL;
    size_t headers_count = 0;

    headers_end = strstr(xfer->response, "\r\n\r\n") + 2;
    if (headers_end == NULL) {
        warn("Unable to parse headers.\n");

        return NULL;
    }

    headers_buff = calloc(headers_end - xfer->response + 9, sizeof(char));
    if (headers_buff == NULL) {
        warn("Unable to allocate memory for headers buffer\n");

        return NULL;
    }
    strncpy(headers_buff, "Status: ", 8);
    strncpy(headers_buff + 8, xfer->response, headers_end - xfer->response);

    char *tmp = headers_buff;
    while (*tmp != '\0') {
        tmp = strchr(tmp, '\r') + 2;
        ++headers_count;
    }

    headers = headers_parse(headers_buff, headers_count);
    if (headers == NULL) {
        free(headers_buff);

        return NULL;
    }

    free(headers_buff);
    *sz = headers_count;

    return headers;
}

struct httphead *http_head_get(const char *key, struct httphead *h, size_t hsz)
{
    for (size_t i = 0; i < hsz; ++i) {
        if (strcmp(key, h[i].key) == 0) {
            return &h[i];
        }
    }

    return NULL;
}

int http_head_status(const struct http *http, struct httphead *h, size_t sz)
{
    int status = -1;
    struct httphead *header;

    header = http_head_get("Status", h, sz);
    if (header == NULL) {
        warn("Status field is missing in request\n");

        return -1;
    }

    if (sscanf(header->val, "%*s %d %*s", &status) == EOF) {
        warn("Unable to detect response status\n");

        return -1;
    }

    return status;
}

struct httpget *http_get(
    struct httpcfg *cfg,
    const struct source *addrs,
    size_t addrsz,
    const char *domain,
    short port,
    const char *path,
    const void *post,
    size_t postsz
) {
    struct httpget *result = NULL;
    struct http *h = NULL;
    struct httpxfer *x = NULL;
    struct httphead *headers = NULL;
    char *body = NULL;
    char *response = NULL;
    size_t body_size;
    size_t headers_count;
    size_t response_size;
    int response_status;

    h = http_alloc(cfg, addrs, addrsz, domain, port, path);
    if (h == NULL) {
        goto fail;
    }

    x = http_open(h, post, postsz);
    if (x == NULL) {
        goto fail;
    }

    response = http_read(h, x, &response_size);
    if (response == NULL) {
        goto fail;
    }

    x = calloc(1, sizeof(struct httpxfer));
    if (x == NULL) {
        warn("Unable to allocate space for httpxfer");
        goto fail;
    }

    BIO_ssl_shutdown(h->web);

    x->response = response;
    x->response_size = response_size;

    body = http_body_read(h, x, &body_size);
    if (body == NULL) {
        goto fail;
    }

    headers = http_head_parse(h, x, &headers_count);
    if (headers == NULL) {
        goto fail;
    }

    response_status = http_head_status(h, headers, headers_count);
    if (response_status < 0) {
        goto fail;
    }

    result = calloc(1, sizeof(struct httpget));
    if (result == NULL) {
        warn("Unable to allocate memory for httpget.\n");

        goto fail;
    }

    result->bodypart = body;
    result->bodypartsz = body_size;
    result->headpart = NULL;
    result->headpartsz = 0;
    result->http = h;
    result->xfer = x;
    result->head = headers;
    result->headsz = headers_count;
    result->code = response_status;

    return result;

fail:
    if (headers != NULL) {
        httphead_free(headers, headers_count);
    }

    if (h->web != NULL) {
        BIO_ssl_shutdown(h->web);
    }

    if (h != NULL) {
        http_free(h);
    }

    if (x != NULL) {
        httpxfer_free(x);
    }

    if (body != NULL) {
        free(body);
    }

    return NULL;
}

struct httpcfg *http_init(void)
{
    SSL_CTX *ctx = NULL;
    const SSL_METHOD *method = NULL;
    struct httpcfg *config = NULL;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    method = TLSv1_2_method();
    if (method == NULL) {
        openssl_error_report("Unable to create TLSv1.2 SSL method");

        return NULL;
    }

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        openssl_error_report("Unable to create SSL context");

        return NULL;
    }

    if (SSL_CTX_load_verify_locations(ctx, DEFAULT_CA_FILE, NULL) != 1) {
        warnx("Unable to load CA file: %s\n", DEFAULT_CA_FILE);

        goto fail;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, openssl_verify_callback);

    config = calloc(1, sizeof(struct httpcfg));
    if (config == NULL) {
        goto fail;
    }

    config->ssl_config = ctx;

    return config;

fail:
    SSL_CTX_free(ctx);

    return NULL;
}

void http_uninit(struct httpcfg *p)
{
    if (NULL == p) {
        return;
    }

    if (p->ssl_config != NULL) {
        SSL_CTX_free(p->ssl_config);
    }

    free(p);
}
