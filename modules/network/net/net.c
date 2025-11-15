// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Ignacio Castro Centeno
 * This file is part of HTTPS Server.
 * See the LICENSE file in the project root for more information.
 */

#include "net.h"

/* Configure socket options for reuse and restartability */
void configure_socket(int sockfd) {
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        perror("setsockopt(SO_REUSEADDR)");
        /* non-fatal */
    }
#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) == -1) {
        /* non-fatal */
    }
#endif
}

/* Create, bind and listen. Returns listening fd or -1. */
int create_listen_socket(int port) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return -1;
    }

    configure_socket(listen_fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    return listen_fd;
}
