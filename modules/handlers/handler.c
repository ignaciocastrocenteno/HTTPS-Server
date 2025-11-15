// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Ignacio Castro Centeno
 * This file is part of HTTPS Server.
 * See the LICENSE file in the project root for more information.
 */

#include "handler.h"

/* Handle a single client connection (child process or thread context). */
void handle_client_connection(int client_fd, SSL_CTX *ctx, struct sockaddr_in *peer) {
    SSL *ssl = NULL;
    char peer_addr[INET_ADDRSTRLEN] = {0};

    if (peer) {
        inet_ntop(AF_INET, &peer->sin_addr, peer_addr, sizeof(peer_addr));
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "ERROR: SSL_new failed\n");
        close(client_fd);
        return;
    }

    if (SSL_set_fd(ssl, client_fd) != 1) {
        fprintf(stderr, "ERROR: SSL_set_fd failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "WARNING: TLS handshake failed (peer=%s)\n", peer_addr[0] ? peer_addr : "unknown");
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    /* Read a single request into a fixed buffer */
    {
        char buf[READ_BUF_SIZE];
        int n = SSL_read(ssl, buf, (int)sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\\0';
            size_t to_print = (size_t)n;
            if (to_print > 512) to_print = 512;
            fprintf(stdout, "INFO: Received request from %s: %.512s\\n", peer_addr[0] ? peer_addr : "unknown", buf);
        } else {
            int ssl_err = SSL_get_error(ssl, n);
            fprintf(stderr, "INFO: SSL_read returned %d (peer=%s) ssl_err=%d\\n", n, peer_addr[0] ? peer_addr : "unknown", ssl_err);
            ERR_clear_error();
        }
    }

    const char *body = "<html><head><title>Minimal HTTPS Server</title></head>"
                       "<body><h1>It works!</h1><p>Secure connection established.</p></body></html>";
    char header[512];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 200 OK\\r\\n"
                              "Content-Type: text/html; charset=utf-8\\r\\n"
                              "Content-Length: %zu\\r\\n"
                              "Connection: close\\r\\n"
                              "\\r\\n",
                              strlen(body));
    if (header_len < 0 || header_len >= (int)sizeof(header)) {
        strcpy(header, "HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\nConnection: close\\r\\n\\r\\n");
        header_len = (int)strlen(header);
    }

    if (SSL_write(ssl, header, header_len) > 0) {
        SSL_write(ssl, body, (int)strlen(body));
    } else {
        ERR_print_errors_fp(stderr);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
}
