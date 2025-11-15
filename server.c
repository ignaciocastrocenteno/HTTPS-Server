// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Ignacio Castro Centeno
 * This file is part of HTTPS Server.
 * See the LICENSE file in the project root for more information.
 */

// Standard C Library
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// POSIX Networking Library
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// OpenSSL Library
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Constants */
#define DEFAULT_PORT 8080
#define BACKLOG 10
#define READ_BUF_SIZE 8192
#define DEFAULT_CERT_FILE "server.crt"
#define DEFAULT_KEY_FILE  "server.key"

/* Globals for signal handlers */
static volatile sig_atomic_t stop_flag = 0;
static int listen_fd = -1;      /* main listening socket */
static SSL_CTX *global_ctx = NULL;

/* Forward declarations */
static void cleanup(void);
static void handle_sigint(int signo);
static void handle_sigchld(int signo);
static SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file);
static void configure_socket(int sockfd);
static void serve_forever(int sockfd, SSL_CTX *ctx);
static void handle_client_connection(int client_fd, SSL_CTX *ctx, struct sockaddr_in *peer);

/* Resource cleanup */
static void cleanup(void) {
    if (listen_fd != -1) {
        close(listen_fd);
        listen_fd = -1;
    }
    if (global_ctx) {
        SSL_CTX_free(global_ctx);
        global_ctx = NULL;
    }
    /* Cleanup OpenSSL algorithms/strings (harmless if already cleaned) */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    ERR_free_strings();
#endif
}

/* SIGINT / SIGTERM handler to stop the server loop */
static void handle_sigint(int signo) {
    (void)signo;
    stop_flag = 1;
    /* close listening socket to wake accept() */
    if (listen_fd != -1) {
        close(listen_fd);
        listen_fd = -1;
    }
}

/* SIGCHLD handler to reap children and avoid zombies */
static void handle_sigchld(int signo) {
    (void)signo;
    /* Reap all dead children without blocking */
    while (1) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid <= 0) break;
        /* optional: log child exit (omitted to keep output minimal) */
    }
}

/* Initialize SSL_CTX for server with provided certificate and key */
static SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file) {
    SSL_CTX *ctx = NULL;

    /* Initialize OpenSSL (for <1.1.0 it's required explicitly) */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
#endif

    /* Use TLS_server_method for highest compatibility and security negotiation */
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "ERROR: Unable to create SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Recommended SSL options: disable SSLv2/SSLv3 and use secure defaults */
    long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, opts);

    /* Set certificate and private key */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "ERROR: Failed to load certificate from '%s'\n", cert_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "ERROR: Failed to load private key from '%s'\n", key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    /* Verify private key matches certificate */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "ERROR: Private key does not match the certificate public key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* (Optional) Set preferred cipher list - rely on system defaults for simplicity */
    /* SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5"); */

    return ctx;
}

/* Configure socket options for reuse and nonblocking if needed */
static void configure_socket(int sockfd) {
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        perror("setsockopt(SO_REUSEADDR)");
        /* non-fatal: continue */
    }

#ifdef SO_REUSEPORT
    /* Try to set SO_REUSEPORT when available (helps restartability) */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) == -1) {
        /* Not fatal, continue */
    }
#endif
}

/* Main server accept loop - forks for each client for simplicity and isolation */
static void serve_forever(int sockfd, SSL_CTX *ctx) {
    while (!stop_flag) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd = accept(sockfd, (struct sockaddr *)&peer, &peer_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                /* interrupted by signal; check stop flag */
                continue;
            }
            perror("accept");
            break;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        } else if (pid == 0) {
            /* child process: close listening socket copy and handle client */
            if (sockfd != -1) close(sockfd);
            handle_client_connection(client_fd, ctx, &peer);
            /* ensure child exits after handling */
            _exit(EXIT_SUCCESS);
        } else {
            /* parent process: close client fd (child has its own copy) and continue */
            close(client_fd);
        }
    }
}

/* Handle a single client: perform TLS handshake, read request, send minimal response */
static void handle_client_connection(int client_fd, SSL_CTX *ctx, struct sockaddr_in *peer) {
    SSL *ssl = NULL;
    char peer_addr[INET_ADDRSTRLEN] = {0};

    /* Convert peer address to string for light logging */
    if (peer) {
        inet_ntop(AF_INET, &peer->sin_addr, peer_addr, sizeof(peer_addr));
    }

    /* Create SSL object */
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "ERROR: SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        close(client_fd);
        return;
    }

    /* Attach socket to SSL */
    if (SSL_set_fd(ssl, client_fd) != 1) {
        fprintf(stderr, "ERROR: SSL_set_fd failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    /* Perform TLS/SSL handshake with client */
    if (SSL_accept(ssl) <= 0) {
        /* Handshake failed: print error and close */
        int err = SSL_get_error(ssl, -1);
        fprintf(stderr, "WARNING: TLS handshake failed (peer=%s), SSL_get_error=%d\n", peer_addr[0] ? peer_addr : "unknown", err);
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    /* Read HTTP request with a fixed-size buffer (avoid dynamic alloc) */
    {
        char buf[READ_BUF_SIZE];
        ssize_t total_read = 0;

        /* Do a single read attempt - this server is intentionally simple:
           read up to READ_BUF_SIZE-1 and treat it as a whole HTTP request.
           For production-grade servers implement robust request parsing + chunked reading. */
        int n = SSL_read(ssl, buf, (int)sizeof(buf) - 1);
        if (n <= 0) {
            int ssl_err = SSL_get_error(ssl, n);
            /* Non-fatal - client may have closed connection */
            fprintf(stderr, "INFO: SSL_read returned %d (peer=%s) ssl_err=%d\n", n, peer_addr[0] ? peer_addr : "unknown", ssl_err);
            ERR_clear_error();
        } else {
            buf[n] = '\0';
            total_read = n;
            /* For debug: print a short prefix of request - keep limited to avoid noisy logs */
            size_t to_print = (size_t)total_read;
            if (to_print > 512) to_print = 512;
            fprintf(stdout, "INFO: Received request from %s: %.512s\n", peer_addr[0] ? peer_addr : "unknown", buf);
            /* In a real server parse the HTTP method, path, headers, etc. */
        }
    }

    /* Prepare a small HTTP/1.1 response body */
    const char *body = "<html><head><title>Minimal HTTPS Server</title></head>"
                       "<body><h1>It works!</h1><p>Secure connection established.</p></body></html>";
    char header[512];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: text/html; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              strlen(body));
    if (header_len < 0 || header_len >= (int)sizeof(header)) {
        /* Fallback to a safe, small header if snprintf failed/truncated */
        strcpy(header, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n");
        header_len = (int)strlen(header);
    }

    /* Send header */
    if (SSL_write(ssl, header, header_len) <= 0) {
        fprintf(stderr, "WARNING: SSL_write(header) failed for peer=%s\n", peer_addr[0] ? peer_addr : "unknown");
        ERR_print_errors_fp(stderr);
        /* continue to try to shutdown gracefully */
    } else {
        /* Send body */
        if (SSL_write(ssl, body, (int)strlen(body)) <= 0) {
            fprintf(stderr, "WARNING: SSL_write(body) failed for peer=%s\n", peer_addr[0] ? peer_addr : "unknown");
            ERR_print_errors_fp(stderr);
        }
    }

    /* Initiate orderly shutdown of TLS connection */
    SSL_shutdown(ssl);
    /* Free SSL object */
    SSL_free(ssl);

    /* Close underlying socket */
    close(client_fd);
}

/* Main entrypoint */
int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    const char *cert_file = NULL;
    const char *key_file = NULL;

    /* Allow certificate/key override via environment variables */
    cert_file = getenv("SSL_CERT_FILE");
    key_file  = getenv("SSL_KEY_FILE");

    /* Allow CLI args: optional cert and key paths and port:
       usage: server [port] [cert_file] [key_file]
       (keeps interface minimal and predictable) */
    if (argc >= 2) {
        /* parse port */
        int p = atoi(argv[1]);
        if (p > 0 && p <= 65535) port = p;
    }
    if (argc >= 3) cert_file = argv[2];
    if (argc >= 4) key_file = argv[3];

    /* Fallback defaults if not provided */
    if (!cert_file) cert_file = DEFAULT_CERT_FILE;
    if (!key_file)  key_file  = DEFAULT_KEY_FILE;

    /* Register signal handlers */
    struct sigaction sa_int = {0};
    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    if (sigaction(SIGINT, &sa_int, NULL) == -1) {
        perror("sigaction(SIGINT)");
        /* not fatal */
    }
    if (sigaction(SIGTERM, &sa_int, NULL) == -1) {
        perror("sigaction(SIGTERM)");
        /* not fatal */
    }

    struct sigaction sa_chld = {0};
    sa_chld.sa_handler = handle_sigchld;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa_chld, NULL) == -1) {
        perror("sigaction(SIGCHLD)");
        /* not fatal */
    }

    /* Create and configure listening socket */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    configure_socket(listen_fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY; /* listen on all interfaces */

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    /* Initialize TLS context with certificate and key */
    SSL_CTX *ctx = create_server_ctx(cert_file, key_file);
    if (!ctx) {
        fprintf(stderr, "ERROR: Failed to initialize TLS context. Exiting.\n");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    /* Store globally for cleanup in signal handler if needed */
    global_ctx = ctx;

    fprintf(stdout, "INFO: HTTPS server listening on 0.0.0.0:%d\n", port);
    fprintf(stdout, "INFO: Using cert='%s' key='%s'\n", cert_file, key_file);

    /* Serve clients until stop_flag is set by SIGINT/SIGTERM */
    serve_forever(listen_fd, ctx);

    /* Clean shutdown */
    cleanup();

    fprintf(stdout, "INFO: Server shutdown complete.\n");
    return EXIT_SUCCESS;
}
