// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Ignacio Castro Centeno
 * This file is part of HTTPS Server.
 * See the LICENSE file in the project root for more information.
 */

#ifndef HANDLER_H
#define HANDLER_H

#include "common.h"
#include <netinet/in.h>

/* Handle a single client: TLS handshake, read request, write response, cleanup. */
void handle_client_connection(int client_fd, SSL_CTX *ctx, struct sockaddr_in *peer);

#endif
