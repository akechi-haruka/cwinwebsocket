#include "winwebsocket.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/base64.h"
#include "lib/http_parser.h"
#include "lib/sha1.h"

#define MAX_CONNECTIONS 16
#define HEADER_BUF_MAX 2048
#define WEBSOCKET_VERSION "13"

static DWORD __stdcall wws_proc(LPVOID ctx);
static DWORD __stdcall wws_client_proc(LPVOID ctx);
static void wss_handle_http_handshake(struct wws_connection* conn);
static void wss_handle_ws_frame(struct wws_connection* conn);

static void (*cb_onopen)(struct wws_connection*) = NULL;
static void (*cb_onclose)(struct wws_connection*) = NULL;
static void (*cb_onmessage)(struct wws_connection*, const char*, size_t) = NULL;
static void (*cb_log)(const char*, ...) = NULL;

static bool is_running = false;
static SOCKET server_socket = INVALID_SOCKET;
static HANDLE server_thread = INVALID_HANDLE_VALUE;
static long volatile connection_counter = 0;

void wws_set_callbacks(
    void (*onopen)(struct wws_connection* conn),
    void (*onclose)(struct wws_connection* conn),
    void (*onmessage)(struct wws_connection* conn, const char* msg, size_t len),
    void (*log)(const char* msg, ...)
) {
    cb_onopen = onopen;
    cb_onclose = onclose;
    cb_onmessage = onmessage;
    cb_log = log;
}

#define log(...) if (cb_log != NULL) { cb_log(__VA_ARGS__); }

HRESULT wws_start(int port) {
    if (is_running) {
        return S_FALSE;
    }

    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        log("WSAStartup failed with error: %d\n", ret);
        return HRESULT_FROM_WIN32(ret);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        log("socket failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return HRESULT_FROM_WIN32(ret);
    }

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = port;
    ret = bind(server_socket, (struct sockaddr*)&bind_addr, sizeof(bind_addr));
    if (ret == SOCKET_ERROR) {
        log("bind failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return HRESULT_FROM_WIN32(ret);
    }

    ret = listen(server_socket, SOMAXCONN);
    if (ret == SOCKET_ERROR) {
        log("listen failed with error: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return HRESULT_FROM_WIN32(ret);
    }

    is_running = true;
    server_thread = CreateThread(NULL, 0, wws_proc, NULL, 0, NULL);

    log("Server has successfully started on port %d\n", port);

    return S_OK;
}

DWORD __stdcall wws_proc([[maybe_unused]] LPVOID ctx) {

    while (is_running) {
        struct sockaddr_in remote_addr = {0};
        int remote_addr_len = sizeof(remote_addr);
        SOCKET client = accept(server_socket, (struct sockaddr*)&remote_addr, &remote_addr_len);
        if (client == INVALID_SOCKET) {
            int error = WSAGetLastError();
            if (error == WSAEINTR) {
                continue;
            } else {
                log("Error while listening on socket: %d", error);
                break;
            }
        }

        if (connection_counter < MAX_CONNECTIONS) {
            struct wws_connection* conn = malloc(sizeof(struct wws_connection));
            memset(conn, 0, sizeof(struct wws_connection));
            conn->conn_handle = client;
            conn->is_connected = true;
            conn->ip = remote_addr.sin_addr.S_un.S_addr;
            conn->port = remote_addr.sin_port;
            inet_ntop(AF_INET, &(remote_addr.sin_addr), conn->ip_str, INET_ADDRSTRLEN);
            log("Incoming connection from %s:%d\n", conn->ip_str, conn->port);
            InterlockedIncrement(&connection_counter);
            conn->thread_handle = CreateThread(NULL, 0, wws_client_proc, conn, 0, NULL);
            if (conn->thread_handle == NULL) {
                log("Failed to start client proc thread (%ld)\n", GetLastError());
                free(conn);
            }
        } else {
            log("Too many open connections (%d)\n", connection_counter);
            closesocket(client);
        }
    }

    return 0;
}



DWORD __stdcall wws_client_proc(LPVOID ctx) {
    struct wws_connection* conn = ctx;

    while (is_running && conn->is_connected) {
        if (conn->mode == HTTP) {
            wss_handle_http_handshake(conn);
        } else if (conn->mode == WS) {
            wss_handle_ws_frame(conn);
        } else {
            log("Connection is in unknown state: %d\n", conn->mode);
            break;
        }
    }

    log("Lost connection of %s:%d\n", conn->ip_str, conn->port);
    closesocket(conn->conn_handle);
    InterlockedDecrement(&connection_counter);
    free(conn);
    return 0;
}

void wss_send(struct wws_connection* conn, const char* data, int len) {
    if (!conn->is_connected) {
        return;
    }

    int pos = 0;
    do {
        int written = send(conn->conn_handle, data + pos, len - pos, 0);
        if (written == SOCKET_ERROR) {
            log("Socket write error: %ld\n", GetLastError());
            conn->is_connected = false;
        }

        pos += written;
    } while (pos < len);
}

void wss_send_http_response(struct wws_connection* conn, uint16_t http_code, const char* http_message, const char* extra_headers) {
    if (!conn->is_connected) {
        return;
    }

    char output[2048];
    snprintf(output, 2048, "HTTP/1.1 %d %s\r\nConnection: close\r\n%s\r\n\r\n", http_code, http_message, extra_headers);

    log("HTTP Response: %d %s\n", http_code, http_message);

    wss_send(conn, output, (int)strlen(output) - 1);
}

void wss_handle_http_handshake(struct wws_connection* conn) {
    char header_buf[HEADER_BUF_MAX];
    int pos = 0;

    do {
        int len = recv(conn->conn_handle, header_buf + pos, HEADER_BUF_MAX - pos, 0);
        if (len == SOCKET_ERROR) {
            log("Error reading during handshake phase: %ld\n", GetLastError());
            conn->is_connected = false;
            return;
        }

        if (pos + len > HEADER_BUF_MAX) {
            log("Error reading during handshake phase: Request too large\n");
            wss_send_http_response(conn, 431, "Request Header Fields Too Large", NULL);
            conn->is_connected = false;
            return;
        }

        pos += len;

    } while (strstr(header_buf, "\r\n\r\n") == NULL);

    header_buf[pos + 1] = 0;

    http_request_t request;
    httpParseRequest(header_buf, &request);

    headers_kv_t* connection = httpFindHeader(request.headers, request.num_headers, "Connection");
    if (connection == NULL || strcasecmp(connection->value, "Upgrade") != 0) {
        log("Error reading HTTP request: Connection header not present or value invalid\n");
        wss_send_http_response(conn, 426, "Upgrade Required", "Upgrade: Websocket");
        conn->is_connected = false;
        return;
    }

    headers_kv_t* upgrade = httpFindHeader(request.headers, request.num_headers, "Upgrade");
    if (upgrade == NULL || strcasecmp(upgrade->value, "Websocket") != 0) {
        log("Error reading HTTP request: Upgrade header not present or value invalid\n");
        wss_send_http_response(conn, 400, "Bad Request", NULL);
        conn->is_connected = false;
        return;
    }

    headers_kv_t* wskey = httpFindHeader(request.headers, request.num_headers, "Sec-WebSocket-Key");
    if (wskey == NULL) {
        log("Error reading HTTP request: Sec-WebSocket-Key header not present\n");
        wss_send_http_response(conn, 400, "Bad Request", NULL);
        conn->is_connected = false;
        return;
    }

    headers_kv_t* wsver = httpFindHeader(request.headers, request.num_headers, "Sec-WebSocket-Version");
    if (wsver == NULL) {
        log("Error reading HTTP request: Sec-WebSocket-Version header not present or invalid value\n");
        wss_send_http_response(conn, 400, "Bad Request", "Sec-WebSocket-Version: " WEBSOCKET_VERSION);
        conn->is_connected = false;
        return;
    }

    char ws_accept[64];
    int ws_accept_len = snprintf(ws_accept, 64, "%s%s", "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", wskey->value); // magic number
    uint8_t digest[20];

    SHA1_CTX sha;
    SHA1Init (&sha);
    SHA1Update(&sha, (uint8_t*) ws_accept, ws_accept_len);
    SHA1Final(digest, &sha);

    size_t _;
    char* base64_str = base64_encode(digest, 20, &_);

    char response_header[512];
    sprintf(response_header, "Connection: Upgrade\r\nUpgrade: Websocket\r\nSec-WebSocket-Version: " WEBSOCKET_VERSION "\r\nSec-WebSocket-Accept: %s", base64_str);

    free(base64_str);

    wss_send_http_response(conn, 101, "Switching Protocols", response_header);
    log("Connection successfully upgraded to websockets\n");
    conn->mode = WS;
}

static void wss_handle_ws_frame(struct wws_connection* conn) {
    log("THIS NEEDS IMPLEMENTATION!\n"); // TODO
    conn->is_connected = false;
}

bool wws_is_running() {
    return is_running;
}

HRESULT wws_send(struct wws_connection* conn, const char* msg, size_t size) {
    log("THIS NEEDS IMPLEMENTATION!\n"); // TODO
    conn->is_connected = false;
    return E_FAIL;
}

HRESULT wws_stop() {
    if (!is_running) {
        return S_FALSE;
    }

    is_running = false;

    log("Stopping server...\n");

    if (server_socket != INVALID_SOCKET) {
        closesocket(server_socket);
    }
    server_socket = INVALID_SOCKET;

    if (server_thread != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(server_thread, INFINITE);
    }
    server_thread = NULL;

    log("Stopped server\n");

    return S_OK;
}
