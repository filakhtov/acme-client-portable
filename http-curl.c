#include <curl/curl.h>
#include <err.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"
#include "http.h"

struct httpcfg {
    CURL* curl_handle;
};

struct string {
    char *data;
    size_t length;
};

struct string initialize_string(void)
{
    struct string buffer;
    buffer.data = calloc(1, sizeof(char));

    if (buffer.data == NULL) {
        return buffer;
    }

    buffer.data[0] = '\0';
    buffer.length = 0;

    return buffer;
}

size_t response_writer(void *read_buffer, size_t element_size, size_t elements_number, struct string *write_buffer)
{
    size_t read_buffer_size = element_size * elements_number;
    size_t new_write_buffer_length = write_buffer->length + read_buffer_size;

    char *new_write_buffer_data = realloc(write_buffer->data, new_write_buffer_length + 1);
    if (NULL == new_write_buffer_data) {
        warn("realloc write_buffer");
        return 0;
    }

    write_buffer->data = new_write_buffer_data;

    memcpy(write_buffer->data + write_buffer->length, read_buffer, read_buffer_size);
    write_buffer->data[new_write_buffer_length] = '\0';
    write_buffer->length = new_write_buffer_length;

    return read_buffer_size;
}

char *header_part(char **buffer, char *needle)
{
    char* beginning = *buffer;
    char* part;
    char* end;
    if (NULL == (end = strstr(beginning, needle))) {
        return NULL;
    }

    size_t needle_length = end - beginning;
    if (NULL == (part = calloc(needle_length + 1, sizeof(char)))) {
        return NULL;
    }

    strncpy(part, beginning, needle_length);
    part[needle_length] = '\0';

    end += 2;
    *buffer = end;

    return part;
}

void free_headers(struct httphead *parsed_headers, size_t parsed_headers_count)
{
    if (parsed_headers == NULL) {
        return;
    }

    for (size_t i = 0; i < parsed_headers_count; ++i) {
        free((void *) parsed_headers[i].key);
        free((void *) parsed_headers[i].val);
    }

    free(parsed_headers);
}

struct httphead *parse_headers(struct string response_headers, size_t *parsed_headers_count)
{
    struct httphead *parsed_headers = NULL;
    size_t headers_count = 0;

    char *buffer = strstr(response_headers.data, "\r\n");
    if (buffer == NULL) {
        goto failure;
    }
    buffer += 2;

    while (*buffer) {
        char *key;
        if (NULL == (key = header_part(&buffer, ":"))) {
            break;
        }

        char *value;
        if (NULL == (value = header_part(&buffer, "\r\n"))) {
            warn("http_header_parse value");
            free(key);
            goto failure;
        }

        struct httphead *header;
        size_t parsed_headers_size = sizeof(struct httphead) * (headers_count + 1);
        if (NULL == (header = realloc(parsed_headers, parsed_headers_size))) {
            warn("realloc fail");
            free(key);
            free(value);
            goto failure;
        }

        header[headers_count].key = key;
        header[headers_count].val = value;
        parsed_headers = header;

        ++headers_count;
    }

    *parsed_headers_count = headers_count;

    return parsed_headers;

failure:
    free_headers(parsed_headers, headers_count);

    return NULL;
}

int reinit_curl_handle(struct httpcfg *cfg)
{
    curl_easy_reset(cfg->curl_handle);

    if (CURLE_OK != curl_easy_setopt(cfg->curl_handle, CURLOPT_SSL_VERIFYHOST, 2)) {
        warn("curl_setopt verifyhost");
        return -1;
    }

    if (CURLE_OK != curl_easy_setopt(cfg->curl_handle, CURLOPT_SSL_VERIFYPEER, 1)) {
        warn("curl_setopt verifypeer");
        return -1;
    }

#if 0
    if (CURLE_OK != curl_easy_setopt(cfg->curl_handle, CURLOPT_SSL_VERIFYSTATUS, 1)) {
        warn("curl_setopt verifystatus");
        return -1;
    }
#endif
    curl_easy_setopt(cfg->curl_handle, CURLOPT_WRITEFUNCTION, response_writer);
    curl_easy_setopt(cfg->curl_handle, CURLOPT_HEADERFUNCTION, response_writer);

    return 0;
}

struct httpget * http_get(
    struct httpcfg *cfg,
    const struct source *addrs,
    size_t addrsz,
    const char *domain,
    short port,
    const char *path,
    const void *post,
    size_t postsz
) {
    if (reinit_curl_handle(cfg) < 0) {
        warn("reinit_curl");
        goto failure;
    }

    struct httpget *result = NULL;

    struct string response_body = { .data = NULL, .length = 0 };
    struct string response_headers = { .data = NULL, .length = 0 };

    char *request_url = NULL;
    size_t https_prefix_length = 9;
    size_t request_string_length = https_prefix_length + strlen(domain) + strlen(path);

    if (NULL == (request_url = calloc(request_string_length + 1, sizeof(char)))) {
        warn("calloc");
        goto failure;
    }

    if (port == 443) {
        strcpy(request_url, "https://");
    } else {
        strcpy(request_url, "http://");
    }

    strcat(request_url, domain);
    strcat(request_url, path);

    if (CURLE_OK != (curl_easy_setopt(cfg->curl_handle, CURLOPT_URL, request_url))) {
        warn("curl_easy_setopt CURLOPT_URL");
        goto failure;
    }

    curl_easy_setopt(cfg->curl_handle, CURLOPT_PORT, port);

    size_t dns_record_length = 8 + strlen(domain) + strlen(addrs->ip);
    char *dns_record = NULL;
    if (NULL == (dns_record = calloc(dns_record_length, sizeof(char)))) {
        warn("calloc dns_record");
        goto failure;
    }

    char port_string[8];
    sprintf(port_string, ":%d:", port);

    strcpy(dns_record, domain);
    strcat(dns_record, port_string);
    strcat(dns_record, addrs->ip);

    struct curl_slist *dns_table = NULL;
    if (NULL == (dns_table = curl_slist_append(dns_table, dns_record))) {
        warn("curl_slist_append dns_table");
        goto failure;
    }

    curl_easy_setopt(cfg->curl_handle, CURLOPT_RESOLVE, dns_table);

    struct curl_slist *request_headers = NULL;
    request_headers = curl_slist_append(request_headers, "Accept: application/json");

    if (post != NULL) {
        request_headers = curl_slist_append(request_headers, "Content-Type: application/json");

        curl_easy_setopt(cfg->curl_handle, CURLOPT_HTTPHEADER, request_headers);
        curl_easy_setopt(cfg->curl_handle, CURLOPT_POSTFIELDSIZE, postsz);
        curl_easy_setopt(cfg->curl_handle, CURLOPT_POSTFIELDS, post);
        curl_easy_setopt(cfg->curl_handle, CURLOPT_POST, 1);
    } else {
        curl_easy_setopt(cfg->curl_handle, CURLOPT_HTTPGET, 1);
    }

    response_headers = initialize_string();
    if (response_headers.data == NULL) {
        goto failure;
    }
    curl_easy_setopt(cfg->curl_handle, CURLOPT_HEADERDATA, &response_headers);

    response_body = initialize_string();
    if (response_body.data == NULL) {
        goto failure;
    }
    curl_easy_setopt(cfg->curl_handle, CURLOPT_WRITEDATA, &response_body);

    if (CURLE_OK != curl_easy_perform(cfg->curl_handle)) {
        free(response_body.data);
        warn("curl_easy_perform");
        goto failure;
    }

    long response_code = 0;
    curl_easy_getinfo(cfg->curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code > 299) {
        warnx("http_error_code %ld", response_code);
        goto failure;
    }

    size_t parsed_headers_count = 0;
    struct httphead *parsed_headers = parse_headers(response_headers, &parsed_headers_count);
    if (parsed_headers == NULL) {
        warn("parse_headers");
        return NULL;
    }

    if (NULL == (result = calloc(1, sizeof(struct httpget)))) {
        warn("calloc");
        goto failure;
    }

    result->headpart = NULL;
    result->headpartsz = 0;
    result->bodypart = response_body.data;
    result->bodypartsz = response_body.length;
    result->head = parsed_headers;
    result->headsz = parsed_headers_count;
    result->code = response_code;
    result->xfer = NULL;
    result->http = NULL;

    goto success;

failure:
    if (NULL != response_headers.data) {
        free(response_headers.data);
    }

    if (NULL != response_body.data) {
        free(response_body.data);
    }

success:
    if (NULL != request_headers) {
        curl_slist_free_all(request_headers);
    }

    if (NULL != dns_table) {
        curl_slist_free_all(dns_table);
    }

    if (NULL != dns_record) {
        free(dns_record);
    }

    if (NULL != request_url) {
        free(request_url);
    }

    return result;
}

void http_get_free(struct httpget *g)
{
    if (NULL == g) {
        return;
    }

    free(g);
}


struct httphead *http_head_get(const char *v, struct httphead *h, size_t hsz)
{
    for (size_t i = 0; i < hsz; i++) {
        if (strcmp(h[i].key, v)) {
            continue;
        }

        return (&h[i]);
    }

    return NULL;
}

struct httpcfg *http_init(void)
{
    struct httpcfg *cfg = NULL;

    if (NULL == (cfg = calloc(1, sizeof(struct httpcfg)))) {
        warn("calloc");
        goto failure;
    }

    cfg->curl_handle = NULL;

    if (NULL == (cfg->curl_handle = curl_easy_init())) {
        warn("curl_init");
        goto failure;
    }

    return cfg;

failure:
    http_uninit(cfg);

    return NULL;
}

void http_uninit(struct httpcfg *cfg)
{
    if (cfg == NULL) {
        return;
    }

    curl_easy_cleanup(cfg->curl_handle);
    free(cfg);

    curl_global_cleanup();
}
