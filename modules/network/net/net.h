// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Ignacio Castro Centeno
 * This file is part of HTTPS Server.
 * See the LICENSE file in the project root for more information.
 */

#ifndef NET_H
#define NET_H

#include "common.h"

/* Create, bind and listen on a TCP socket at given port. Returns fd or -1 on error. */
int create_listen_socket(int port);

/* Configure socket options (reuse, reuseport if available) */
void configure_socket(int sockfd);

#endif
