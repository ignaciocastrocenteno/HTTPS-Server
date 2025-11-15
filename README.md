# HTTPS-Server
A minimal, production-oriented HTTPS server built entirely in C using POSIX sockets and OpenSSL, following Clean Code principles, KISS philosophy, and modular architecture.

This project demonstrates how a secure HTTP server can be implemented from scratch—handling client connections, performing TLS handshakes, parsing HTTP requests, routing them to handlers, and returning encrypted HTTPS responses.

## Project Overview
This project implements a HTTPS server written in C, featuring:

* TLS encryption using OpenSSL
* Secure TCP socket listening
* Modular architecture across multiple `.c` modules
* Routing system for handling different endpoints
* Safe buffer usage
* Minimal dependencies
* Clean error handling
* Logging module
* Graceful shutdown of TLS structures and sockets

It demonstrates how to:
1) Create a TCP server socket
2) Initialize OpenSSL and build a TLS server context
3) Load an X.509 certificate + private key
4) Accept client connections
5) Upgrade each connection to TLS
6) Parse HTTP/1.1 requests manually
7) Route each request to the corresponding handler
8) Send HTTPS responses
9) Cleanly release all session and socket resources

The project exists to understand deeply:
* Low-level IO on POSIX systems
* TLS server-side handshake and session life cycle
* HTTP request parsing
* C memory safety patterns
* Clean Architecture applied to a low-level system
* Production-grade modularization in C (separation of concerns)

## Learnings From the Project
Completing this server provides a strong understanding of:

### Networking & Operating Systems
* How TCP servers listen, bind, accept and manage clients
* How concurrent client handling works (single-threaded or via fork/thread extensions)
* How to design a deterministic server loop

### TLS & Security
* How TLS is layered under HTTP responses
* The need for certificates, private keys, and trust
* How OpenSSL contexts, sessions, and BIOs operate
* Correct shutdown procedures to avoid leaks or undefined behavior

### HTTP Protocol
* Manually parsing HTTP/1.1 request lines & headers
* How routing and handlers can be implemented in C
* How to form valid HTTP responses

### Software Engineering
* Modularization of a large .c file into maintainable units
* Use of KISS, SOLID, YAGNI, Clean Architecture ideas in C
* Reduced cyclomatic complexity
* Separation of concerns:
    * TLS layer
    * Routing layer
    * HTTP utilities
    * Logging utilities
    * Server core
* Memory-safe fixed-size buffers
* Error handling that prevents undefined behavior

### Memory Safety
* Minimal use of dynamic allocations
* No heap fragmentation
* Safe cleanup of all OpenSSL structures
* All failures handled gracefully

## Good Practices Implemented
### ✔️ Clean Code
* Each module has a single responsibility (`tls.c`, `logger.c`, `http_utils.c`, etc.).
* Variable names are descriptive and consistent.
* Comments in English that explain why, not only what.
* Header files clearly define the interface of each module.

### ✔️ KISS (Keep It Simple, Stupid)
* The server avoids unnecessary abstractions.
* Straightforward request-processing flow.
* The TLS layer is thin and explicit.
* Routing is implemented using simple string matching.

### ✔️ SOLID Principles (adapted for C)
* S — Single Responsibility: clear module separation.
* O — Open/Closed: new routes can be added without modifying core server logic.
* L — Liskov Substitution: handler abstractions behave consistently.
* I — Interface Segregation: minimized header exposure.
* D — Dependency Inversion: high-level routing does not depend on low-level TLS details.

### ✔️ YAGNI
No dynamic routing table allocation.
No unnecessary data structures.
Only the essential HTTPS features were implemented.

### ✔️ Efficient Memory Usage
* Minimal calls to malloc().
* Most structures are stack-allocated.
* All allocated OpenSSL objects are freed:
    * `SSL_free()`
    * `SSL_CTX_free()`
    * `EVP_cleanup()`
    * `close()`

### ✔️ Pointer Safety
* Pointers never dereferenced before null-checks.
* No pointer arithmetic.
* Buffer indexing kept strictly within bounds.

### ✔️ Robust Error Handling
* Full error handling exists for:
* `socket()`, `bind()`, `listen()`, `accept()`
* `SSL_CTX_new()`, `SSL_new()`, `SSL_accept()`
* Certificate/key loading
* `SSL_write()`, `SSL_read()`
* Invalid HTTP requests
* Handler exceptions
* I/O failures

This ensures the server never crashes due to undefined behavior.

## Time Complexity
Although this is primarily a network-bound program, we can express complexity:

1) Connection handling
    ```bash
    O(1)
    ```
    Each iteration handles a single client sequentially.

2) TLS handshake
    ```bash
    O(k)
    ```
    Where `k` is a constant number of handshake operations.

3) HTTP request parsing
    If request size = `N`:
    ```bash
    O(N)
    ```

4) Response sending
    If response body = `M` bytes:
    ```bash
    O(M)
    ```

5) Overall
    ```bash
    O(n)
    ```
    Where n = total size of data processed.

## Libraries Used In The Project

### Standard C Library
* `stdio.h` – I/O and debugging
* `stdlib.h` – memory management, exit codes
* `string.h` – string functions
* `unistd.h` – POSIX close(), read(), write()
* `errno.h` – error diagnostics

### POSIX Networking
* `sys/socket.h` – socket(), bind(), listen(), accept()
* `arpa/inet.h` – IP manipulation
* `netinet/in.h` – IPv4 structures
* `fcntl.h` – file descriptor configuration

### OpenSSL
Used for all TLS operations:
* `SSL_CTX_new`
* `SSL_CTX_use_certificate_file`
* `SSL_CTX_use_PrivateKey_file`
* `SSL_new`
* `SSL_accept`
* `SSL_write`, `SSL_read`
* Proper cleanup of SSL objects

## How to compile the server

### Using gcc
```bash
gcc -Wall -Wextra -std=c11 \
    server.c \
    tls.c \
    route_handlers.c \
    http_utils.c \
    server_utils.c \
    logger.c \
    -lssl -lcrypto -o https_server

```

### Or using a Makefile
```bash
make
```

## How to run the server
```bash
./https_server 443
```
OR specify certificate + key:
```bash
./https_server 443 cert.pem key.pem
```

## How to check for memory leaks (valgrind)
```bash
valgrind --leak-check=full --show-leak-kinds=all ./https_server 443
```

## License
This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

By using, modifying, or distributing this software, you agree to the terms defined in the GPL-3.0 license. In summary:

You are free to run, study, modify, and share the software.

If you distribute modified versions of the program, the result must also be licensed under GPL-3.0, ensuring the same freedoms for users.

Any redistributed version—modified or unmodified—must include a copy of the license and appropriate copyright notices.

No warranty is provided, as explicitly described in the license.

For the full legal text, refer to the official GPL-3.0 license:

https://www.gnu.org/licenses/gpl-3.0.en.html
