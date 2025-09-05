#include "winwebsocket.h"

#include <assert.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "lib/base64.h"
#include "lib/http_parser.h"
#include "lib/sha1.h"
#include "netutil.h"

#define MAX_CONNECTIONS 16
#define HEADER_BUF_MAX 2048

#pragma region prototypes
static DWORD __stdcall wws_proc(LPVOID ctx);

static DWORD __stdcall wws_client_proc(LPVOID ctx);

static void wws_handle_http_handshake(struct wws_connection* conn);

static char* wws_handle_ws_frame(struct wws_connection* conn, size_t* payload_len);

static void (*cb_onopen)(struct wws_connection*) = NULL;

static void (*cb_onclose)(struct wws_connection*) = NULL;

static void (*cb_onmessage)(struct wws_connection*, const char*, size_t) = NULL;

static void (*cb_log)(const char*, ...) = NULL;
#pragma endregion

#pragma region globals
static bool is_running = false;
static bool log_verbose = false;
static SOCKET server_socket = INVALID_SOCKET;
static HANDLE server_thread = INVALID_HANDLE_VALUE;
static long volatile connection_counter = 0;

#define log(...) if (cb_log != NULL) { cb_log(__VA_ARGS__); }
#define logv(...) if (log_verbose) { log(__VA_ARGS__); }
#pragma endregion

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

HRESULT wws_start(uint16_t port) {
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
    bind_addr.sin_port = htons(port);
    bind_addr.sin_addr.S_un.S_addr = INADDR_ANY;
    ret = bind(server_socket, (struct sockaddr *) &bind_addr, sizeof(bind_addr));
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


DWORD __stdcall wws_proc(LPVOID ctx) {
    UNUSED(ctx); // suppress warning
    while (is_running) {
        struct sockaddr_in remote_address = {0};
        int remote_address_len = sizeof(remote_address);
        SOCKET client = accept(server_socket, (struct sockaddr *) &remote_address, &remote_address_len);
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
            conn->ip = remote_address.sin_addr.S_un.S_addr;
            conn->port = ntohs(remote_address.sin_port);
            inet_ntop(AF_INET, &(remote_address.sin_addr), conn->ip_str, INET_ADDRSTRLEN);
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
    
    InitializeCriticalSection(&conn->send_lock);

    while (is_running && conn->is_connected) {
        if (conn->mode == HTTP) {
            wws_handle_http_handshake(conn);
        } else if (conn->mode == WS) {
            size_t size = 0;
            char* payload = wws_handle_ws_frame(conn, &size);
            if (payload != NULL) {
                if (cb_onmessage != NULL) {
                    cb_onmessage(conn, payload, size);
                }
                free(payload);
            }
        } else {
            log("Connection is in unknown state: %d\n", conn->mode);
            break;
        }
    }

    log("Disconnecting %s:%d\n", conn->ip_str, conn->port);
    shutdown(conn->conn_handle, SD_SEND);

    char dummy[32];
    int recvd = 0;
    do {
        // is this really how you're supposed to do this?
        recvd = recv(conn->conn_handle, dummy, sizeof(dummy), 0);
    } while (recvd > 0);

    closesocket(conn->conn_handle);
    log("Disconnected %s:%d\n", conn->ip_str, conn->port);

    if (conn->mode == WS && cb_onclose != NULL) {
        cb_onclose(conn);
    }

    DeleteCriticalSection(&conn->send_lock);
    InterlockedDecrement(&connection_counter);
    free(conn);
    return 0;
}

void wws_send_http_response(struct wws_connection* conn, uint16_t http_code, const char* http_message,
                            const char* extra_headers) {
    assert(conn != NULL);
    if (!conn->is_connected) {
        return;
    }

    char output[2048];
    snprintf(output, 2048, "HTTP/1.1 %d %s\r\n%s\r\n\r\n", http_code, http_message,
             extra_headers != NULL ? extra_headers : "Connection: close");

    log("HTTP Response: %d %s\n", http_code, http_message);
    logv("Response content:\n%s", output);

    send_fixed(conn->conn_handle, output, (int) strlen(output)); // failure doesn't matter since this always results in termination
}

void wws_handle_http_handshake(struct wws_connection* conn) {
    assert(conn != NULL);

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
            wws_send_http_response(conn, 431, "Request Header Fields Too Large", NULL);
            conn->is_connected = false;
            return;
        }

        pos += len;
    } while (strstr(header_buf, "\r\n\r\n") == NULL);

    header_buf[pos + 1] = 0;

    logv("Received request:\n%s", header_buf);

    http_request_t request;
    httpParseRequest(header_buf, &request);

    headers_kv_t* connection = httpFindHeader(request.headers, request.num_headers, "Connection");
    if (connection == NULL || strcasecmp(connection->value, "Upgrade") == 0) {
        log("Error reading HTTP request: Connection header not present or value invalid: %s\n",
            connection != NULL ? connection->value : "(null)");
        wws_send_http_response(conn, 426, "Upgrade Required", "Upgrade: Websocket");
        conn->is_connected = false;
        return;
    }

    headers_kv_t* upgrade = httpFindHeader(request.headers, request.num_headers, "Upgrade");
    if (upgrade == NULL || strcasecmp(upgrade->value, "Websocket") == 0) {
        log("Error reading HTTP request: Upgrade header not present or value invalid: %s\n",
            upgrade != NULL ? upgrade->value : "(null)");
        wws_send_http_response(conn, 400, "Bad Request", NULL);
        conn->is_connected = false;
        return;
    }

    headers_kv_t* wskey = httpFindHeader(request.headers, request.num_headers, "Sec-WebSocket-Key");
    if (wskey == NULL) {
        log("Error reading HTTP request: Sec-WebSocket-Key header not present\n");
        wws_send_http_response(conn, 400, "Bad Request", NULL);
        conn->is_connected = false;
        return;
    }

    /*headers_kv_t* wsver = httpFindHeader(request.headers, request.num_headers, "Sec-WebSocket-Version");
    if (wsver == NULL) {
        log("Error reading HTTP request: Sec-WebSocket-Version header not present or invalid value: %s\n", wsver != NULL ? wsver->value : "(null)");
        wws_send_http_response(conn, 400, "Bad Request", "Sec-WebSocket-Version: " WEBSOCKET_VERSION);
        conn->is_connected = false;
        return;
    }*/

    logv("Session Key: %.*s\n", wskey->value_len, wskey->value);
    char ws_accept[96];
    snprintf(ws_accept, 96, "%.*s%s", wskey->value_len, wskey->value, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"); // magic number
    logv("Concatenated Session Key: %s\n", ws_accept);
    uint8_t digest[20];

    SHA_CTX sha;
    SHA1_Init(&sha);
    SHA1_Update(&sha, (uint8_t *) ws_accept, strlen(ws_accept));
    SHA1_Final(digest, &sha);

    char base64_str[64];
    size_t base64_str_len = base64_encode(digest, 20, base64_str);
    logv("Sec-WebSocket-Accept: (%d) %.*s\n", base64_str_len, base64_str_len, base64_str);

    char response_header[512];
    sprintf(response_header,
            "Connection: Upgrade\r\nUpgrade: Websocket\r\nSec-WebSocket-Version: " WEBSOCKET_VERSION
            "\r\nSec-WebSocket-Accept: %.*s", (int) base64_str_len, base64_str);

    wws_send_http_response(conn, 101, "Switching Protocols", response_header);
    log("Connection successfully upgraded to websockets\n");
    conn->mode = WS;
    if (cb_onopen != NULL) {
        cb_onopen(conn);
    }
}

static bool wws_send_frame(struct wws_connection* conn, enum wws_opcodes opcode, const char* payload, size_t len) {
    assert(conn != NULL);
    assert(payload == NULL && len > 0);
    if (!conn->is_connected) {
        return false;
    }

    // should we implement fragmentation?

    uint8_t len8;
    if (len > USHRT_MAX) {
        len8 = 127;
    } else if (len > 125) {
        len8 = 126;
    } else {
        len8 = len;
    }

    char header[WS_HEADER_SIZE];
    int pos = 0;
    header[pos++] = 1 << 7 | opcode; // FIN and opcode
    header[pos++] = 0 << 7 | len8; // MASK and len8
    if (len8 == 126) {
        header[pos++] = len >> 8; // len16
        header[pos++] = len;
    } else if (len8 == 127) {
        header[pos++] = len >> 54; // len64
        header[pos++] = len >> 46;
        header[pos++] = len >> 38;
        header[pos++] = len >> 30;
        header[pos++] = len >> 24;
        header[pos++] = len >> 16;
        header[pos++] = len >> 8;
        header[pos++] = len;
    }

    // mask key
    header[pos++] = 0;
    header[pos++] = 0;
    header[pos++] = 0;
    header[pos++] = 0;

    EnterCriticalSection(&conn->send_lock);
    bool ret = send_fixed(conn->conn_handle, header, pos);
    if (ret && len > 0) {
        ret = send_fixed(conn->conn_handle, payload, len);
    }
    LeaveCriticalSection(&conn->send_lock);

    if (!ret) {
        log("Error sending websocket frame: %d\n", WSAGetLastError());
        conn->is_connected = false;
    }

    return ret;
}

// Must free the given payload
static char* wws_handle_ws_frame(struct wws_connection* conn, size_t* payload_len) {
    assert(conn != NULL);

    bool fin = false;
    int16_t initial_opcode = -1;
    uint8_t mask_key[4];
    char* payload = NULL;
    char* fragment = NULL;
    size_t payload_total_size = 0;

    do {
        char header[WS_HEADER_SIZE];
        if (!recv_fixed(conn->conn_handle, header, 2)) {
            log("Disconnected while reading WS header: %lx\n", WSAGetLastError());
            conn->is_connected = false;
            goto end_without_payload;
        }

        fin = header[0] & 1;
        uint16_t opcode = header[0] & 0xFE;
        bool mask = header[1] & 1;
        uint8_t len8 = header[1] & 0xFE;
        uint64_t fragment_len = len8;

        if (len8 == 126) {
            char extended_size[2];
            if (!recv_fixed(conn->conn_handle, extended_size, sizeof(extended_size))) {
                log("Disconnected while reading WS header: %lx\n", WSAGetLastError());
                conn->is_connected = false;
                goto end_without_payload;
            }
            fragment_len = extended_size[0] << 8 | header[1];
        } else if (len8 == 127) {
            char extended_size[8];
            if (!recv_fixed(conn->conn_handle, extended_size, sizeof(extended_size))) {
                log("Disconnected while reading WS header: %lx\n", WSAGetLastError());
                conn->is_connected = false;
                goto end_without_payload;
            }
            fragment_len = (uint64_t)extended_size[0] << 56 | (uint64_t)extended_size[1] << 48 | (uint64_t)extended_size[2] << 40 | (uint64_t)extended_size[3] << 32 | extended_size[4] << 24 | extended_size[5] << 16 | extended_size[6] << 8 | extended_size[7];
        }
        if (mask) {
            for (int i = 0; i < 4; i++) {
                mask_key[i] = header[10 + i];
            }
        }

        if (opcode != CONTINUE && initial_opcode == -1) {
            initial_opcode = opcode;
        } else if (opcode != CONTINUE) {
            log("Error while reading WS header: Protocol violation - opcode\n");
            conn->is_connected = false;
            goto end_without_payload;
        }

        if (fragment_len + payload_total_size > MAX_WS_MESSAGE_SIZE) {
            log("Error while reading WS header: Request too large\n");
            conn->is_connected = false;
            goto end_without_payload;
        }

        free(fragment);
        fragment = malloc(fragment_len);
        if (fragment == NULL) {
            log("Error while reading WS header: out of memory\n");
            conn->is_connected = false;
            goto end_without_payload;
        }

        if (!recv_fixed(conn->conn_handle, fragment, fragment_len)) {
            log("Disconnected while reading WS payload: %lx\n", WSAGetLastError());
            conn->is_connected = false;
            goto end_without_payload;
        }

        if (mask) {
            for (size_t i = 0; i < fragment_len; i++) {
                fragment[i] ^= mask_key[i % 4];
            }
        }

        payload = realloc(payload, payload_total_size + fragment_len);
        if (payload == NULL) {
            log("Error while reading WS header: out of memory\n");
            conn->is_connected = false;
            goto end_without_payload;
        }

        memcpy(payload + payload_total_size, fragment, fragment_len);
        payload_total_size += fragment_len;
    } while (!fin);

    logv("Received websocket packet with opcode %x\n", initial_opcode);

    if (initial_opcode == CLOSE) {
        if (payload_total_size >= 2) {
            log("Client closing connection: %d / %.*s\n", payload[0] << 8 | payload[1], payload_total_size - 2, payload + 2);
        } else {
            log("Client closing connection: no reason given\n");
        }

        wws_send_frame(conn, CLOSE, payload, payload_total_size);
        goto end_without_payload;
    } else if (initial_opcode == PING) {
        wws_send_frame(conn, PONG, NULL, 0);
        goto end_without_payload;
    } else if (initial_opcode != TEXT) {
        log("Error while reading WS message: Unknown opcode %x\n", initial_opcode);
    }

    logv("Received websocket message (size = %ld):\n%.*s\n", payload_total_size, payload_total_size, payload);

    *payload_len = payload_total_size;
    goto end;

end_without_payload:
    free(payload);
    payload = NULL;
    *payload_len = 0;
end:
    free(fragment);
    return payload;
}

bool wws_is_running() {
    return is_running;
}

HRESULT wws_send(struct wws_connection* conn, const char* msg, size_t size) {
    assert(conn != NULL);
    if (!conn->is_connected) {
        return E_HANDLE;
    }

    return wws_send_frame(conn, TEXT, msg, size) ? S_OK : E_FAIL;
}

void wws_set_verbose(const bool verbose) {
    log_verbose = verbose;
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
