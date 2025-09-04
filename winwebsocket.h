#pragma once

#include <stdint.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

enum wws_connection_mode {
    HTTP = 0,
    WS = 1
};

struct wws_connection {
    SOCKET conn_handle;
    HANDLE thread_handle;
    uint32_t ip;
    uint16_t port;
    char ip_str[INET_ADDRSTRLEN];
    bool is_connected;

    enum wws_connection_mode mode;
};

void wws_set_callbacks(
    void (*onopen)(struct wws_connection* conn),
    void (*onclose)(struct wws_connection* conn),
    void (*onmessage)(struct wws_connection* conn, const char* msg, size_t len),
    void (*log)(const char* msg, ...)
);
HRESULT wws_start(int port);
bool wws_is_running();
void wws_set_verbose(bool verbose);
HRESULT wws_send(struct wws_connection* client, const char* msg, size_t size);
HRESULT wws_stop();