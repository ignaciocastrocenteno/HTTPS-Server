// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Ignacio Castro Centeno
 * This file is part of HTTPS Server.
 * See the LICENSE file in the project root for more information.
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

/* POSIX & sockets */
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* OpenSSL */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Constants */
#define DEFAULT_PORT 8080
#define BACKLOG 10
#define READ_BUF_SIZE 8192
#define DEFAULT_CERT_FILE "server.crt"
#define DEFAULT_KEY_FILE  "server.key"

#endif
