#include <winsock2.h>

#include "netutil.h"

static bool recv_fixed(SOCKET s, char* buf, size_t len) {
    size_t pos = 0;
    do {
        int recvd = recv(s, buf + pos, len - pos, 0);

        if (recvd <= 0) {
            return false;
        }

        pos += recvd;
    } while (pos < len);
    return true;
}

static bool send_fixed(SOCKET s, const char* buf, size_t len) {
    size_t pos = 0;
    do {
        int sent = send(s, buf + pos, len - pos, 0);

        if (sent <= 0) {
            return false;
        }

        pos += sent;
    } while (pos < len);
    return true;
}