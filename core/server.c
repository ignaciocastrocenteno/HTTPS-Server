#include "common.h"
#include "net.h"
#include "tls.h"
#include "handler.h"

static volatile sig_atomic_t stop_flag = 0;
static int listen_fd_global = -1;
static SSL_CTX *global_ctx = NULL;

/* Signal handlers */
static void handle_sigint(int signo) {
    (void)signo;
    stop_flag = 1;
    if (listen_fd_global != -1) {
        close(listen_fd_global);
        listen_fd_global = -1;
    }
}

static void handle_sigchld(int signo) {
    (void)signo;
    while (1) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid <= 0) break;
    }
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    const char *cert_file = NULL;
    const char *key_file = NULL;

    if (argc >= 2) {
        int p = atoi(argv[1]);
        if (p > 0 && p <= 65535) port = p;
    }
    if (argc >= 3) cert_file = argv[2];
    if (argc >= 4) key_file = argv[3];

    if (!cert_file) cert_file = DEFAULT_CERT_FILE;
    if (!key_file) key_file = DEFAULT_KEY_FILE;

    struct sigaction sa_int;
    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);
    sigaction(SIGTERM, &sa_int, NULL);

    struct sigaction sa_chld;
    sa_chld.sa_handler = handle_sigchld;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa_chld, NULL);

    int listen_fd = create_listen_socket(port);
    if (listen_fd < 0) {
        fprintf(stderr, "ERROR: Failed to create listening socket\\n");
        return EXIT_FAILURE;
    }
    listen_fd_global = listen_fd;

    SSL_CTX *ctx = create_server_ctx(cert_file, key_file);
    if (!ctx) {
        close(listen_fd);
        return EXIT_FAILURE;
    }
    global_ctx = ctx;

    fprintf(stdout, "INFO: HTTPS server listening on 0.0.0.0:%d\\n", port);
    fprintf(stdout, "INFO: Using cert='%s' key='%s'\\n", cert_file, key_file);

    while (!stop_flag) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int client_fd = accept(listen_fd, (struct sockaddr *)&peer, &plen);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        } else if (pid == 0) {
            close(listen_fd);
            handle_client_connection(client_fd, ctx, &peer);
            _exit(EXIT_SUCCESS);
        } else {
            close(client_fd);
        }
    }

    /* Cleanup */
    cleanup_ssl_ctx(ctx);
    if (listen_fd != -1) close(listen_fd);

    fprintf(stdout, "INFO: Server shutdown complete.\\n");
    return EXIT_SUCCESS;
}
