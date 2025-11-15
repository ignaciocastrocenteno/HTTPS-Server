// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Ignacio Castro Centeno
 * This file is part of HTTPS Server.
 * See the LICENSE file in the project root for more information.
 */

#ifndef TLS_H
#define TLS_H

#include "common.h"

/* Create and configure SSL_CTX for server using cert_file and key_file.
   Returns pointer or NULL on error. */
SSL_CTX *create_server_ctx(const char *cert_file, const char *key_file);

/* Free SSL_CTX and perform OpenSSL cleanup as needed. */
void cleanup_ssl_ctx(SSL_CTX *ctx);

#endif
