#pragma once

#include <winsock2.h>

/**
 * Ensures that exactly len bytes are read from the given socket.
 * @param s The socket to read from.
 * @param buf The buffer to read into.
 * @param len The number of bytes to read. The buffer must be at least that size.
 * @return true on success, false on read error (use WSAGetLastError).
 */
bool recv_fixed(SOCKET s, char* buf, size_t len);

/**
 * Ensures that exactly len bytes are written to the given socket.
 * @param s The socket to write to.
 * @param buf The buffer to write.
 * @param len The number of bytes to write. The buffer must be at least that size.
 * @return true on success, false on read error (use WSAGetLastError).
 */
bool send_fixed(SOCKET s, const char* buf, size_t len);