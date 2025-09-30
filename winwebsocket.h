#pragma once

#include <stdint.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdbool.h>

#define WEBSOCKET_VERSION "13"
#define WS_HEADER_SIZE 14
#define MAX_WS_MESSAGE_SIZE 8192
#define UNUSED(x) (void)(x)

enum wws_connection_mode {
    HTTP = 0,
    WS = 1
};

enum wws_opcodes {
    CONTINUE = 0,
    TEXT = 1,
    BINARY = 2,
    CLOSE = 8,
    PING = 9,
    PONG = 10
};

/**
 * Main object holding connection information.
 */
struct wws_connection {
    /**
     * The handle to the socket for this connection.
     */
    SOCKET conn_handle;
    /**
     * The handle to the thread reading from this connection.
     */
    HANDLE thread_handle;
    /**
     * The IP of the peer.
     */
    uint32_t ip;
    /**
     * The port of the peer.
     */
    uint16_t port;
    /**
     * The IP of the peer in string form.
     */
    char ip_str[INET_ADDRSTRLEN];
    /**
     * Whether this client is connected or not.
     * This does not equal to the client actually being connected, rather it will be set to false as soon any connection, protocol or other error occurs.
     */
    bool is_connected;
    /**
     * The mode this connection is currently in (HTTP or WS).
     */
    enum wws_connection_mode mode;
    /**
     * The lock to ensure thread safety on send operations.
     */
    CRITICAL_SECTION send_lock;
};

/**
 * Sets the event callbacks for the websocket server.
 * @param onopen the function to be called when a new websocket connection is established
 * @param onclose the function to be called when a websocket connection is disconnected
 * @param onmessage the function to be called when a websocket message is received
 * @param log the function to be called for log messages
 */
void wws_set_callbacks(
    void (*onopen)(struct wws_connection* conn),
    void (*onclose)(struct wws_connection* conn),
    void (*onmessage)(struct wws_connection* conn, const char* msg, size_t len),
    void (*log)(const char* msg, ...)
);

/**
 * Starts the websocket server.
 * @param port The network port to listen on.
 * @return success if the server was started or is already running, fail on any error.
 */
HRESULT wws_start(uint16_t port);

/**
 * Checks if the websocket server is running.
 * @return true if the server is running, false if not.
 */
bool wws_is_running();

/**
 * Makes verbose messages being sent to the log callback (protocol details, handshake, sent/received payloads, etc.)
 * @param verbose true for verbose logs, false otherwise.
 */
void wws_set_verbose(bool verbose);

/**
 * Sends a text message to a given connection. This is thread safe.
 * @param client The client to send the message to. may not be NULL.
 * @param msg The message content to send (this should not include a terminating zero).
 * @param size The message length.
 * @return success on success, fail on failure.
 */
HRESULT wws_send(struct wws_connection* client, const char* msg, size_t size);

/**
 *
 * @return always success.
 */
HRESULT wws_stop();