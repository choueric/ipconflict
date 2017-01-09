/*
 * Event loop
 * modified from wpa_supplicant 5.0.1
 */

#ifndef ELOOP_H
#define ELOOP_H

#include <time.h>
#include <sys/time.h>

/**
 * ELOOP_ALL_CTX - eloop_cancel_timeout() magic number to match all timeouts
 */
#define ELOOP_ALL_CTX (void *) -1

/**
 * eloop_sock_handler - eloop socket event callback type
 * @sock: File descriptor number for the socket
 * @eloop_ctx: Registered callback context data (eloop_data)
 * @sock_ctx: Registered callback context data (user_data)
 */
typedef void (*eloop_sock_handler)(int sock, void *eloop_ctx, void *sock_ctx);

/**
 * eloop_timeout_handler - eloop timeout event callback type
 * @eloop_ctx: Registered callback context data (eloop_data)
 * @sock_ctx: Registered callback context data (user_data)
 */
typedef void (*eloop_timeout_handler)(void *eloop_data, void *user_ctx);

struct eloop_timeout {
	struct timeval time;
	void *eloop_data;
	void *user_data;
	eloop_timeout_handler handler;
	struct eloop_timeout *next;
};

/**
 * eloop_init() - Initialize global event loop data
 * @user_data: Pointer to global data passed as eloop_ctx to signal handlers
 * Returns: 0 on success, -1 on failure
 *
 * This function must be called before any other eloop_* function. user_data
 * can be used to configure a global (to the process) pointer that will be
 * passed as eloop_ctx parameter to signal handlers.
 */
int eloop_init(void *user_data);

/**
 * eloop_register_read_sock - Register handler for read events
 * @sock: File descriptor number for the socket
 * @handler: Callback function to be called when data is available for reading
 * @eloop_data: Callback context data (eloop_ctx)
 * @user_data: Callback context data (sock_ctx)
 * Returns: 0 on success, -1 on failure
 *
 * Register a read socket notifier for the given file descriptor. The handler
 * function will be called whenever data is available for reading from the
 * socket. The handler function is responsible for clearing the event after
 * having processed it in order to avoid eloop from calling the handler again
 * for the same event.
 */
int eloop_register_read_sock(int sock, eloop_sock_handler handler,
			     void *eloop_data, void *user_data);

/**
 * eloop_unregister_read_sock - Unregister handler for read events
 * @sock: File descriptor number for the socket
 *
 * Unregister a read socket notifier that was previously registered with
 * eloop_register_read_sock().
 */
void eloop_unregister_read_sock(int sock);

/**
 * eloop_register_timeout - Register timeout
 * @secs: Number of seconds to the timeout
 * @usecs: Number of microseconds to the timeout
 * @handler: Callback function to be called when timeout occurs
 * @eloop_data: Callback context data (eloop_ctx)
 * @user_data: Callback context data (sock_ctx)
 * Returns: 0 on success, -1 on failure
 *
 * Register a timeout that will cause the handler function to be called after
 * given time.
 */
int eloop_register_timeout(unsigned int secs, unsigned int usecs,
			   eloop_timeout_handler handler,
			   void *eloop_data, void *user_data);

/**
 * eloop_cancel_timeout - Cancel timeouts
 * @handler: Matching callback function
 * @eloop_data: Matching eloop_data or %ELOOP_ALL_CTX to match all
 * @user_data: Matching user_data or %ELOOP_ALL_CTX to match all
 * Returns: Number of cancelled timeouts
 *
 * Cancel matching <handler,eloop_data,user_data> timeouts registered with
 * eloop_register_timeout(). ELOOP_ALL_CTX can be used as a wildcard for
 * cancelling all timeouts regardless of eloop_data/user_data.
 */
int eloop_cancel_timeout(eloop_timeout_handler handler,
			 void *eloop_data, void *user_data);

struct eloop_timeout *eloop_get_timeout_table();

/**
 * eloop_is_timeout_registered - Check if a timeout is already registered
 * @handler: Matching callback function
 * @eloop_data: Matching eloop_data
 * @user_data: Matching user_data
 * Returns: 1 if the timeout is registered, 0 if the timeout is not registered
 *
 * Determine if a matching <handler,eloop_data,user_data> timeout is registered
 * with eloop_register_timeout().
 */
int eloop_is_timeout_registered(eloop_timeout_handler handler,
				void *eloop_data, void *user_data);
/**
 * eloop_run - Start the event loop
 *
 * Start the event loop and continue running as long as there are any
 * registered event handlers. This function is run after event loop has been
 * initialized with event_init() and one or more events have been registered.
 */
void *eloop_run(void *data);

/**
 * eloop_terminate - Terminate event loop
 *
 * Terminate event loop even if there are registered events. This can be used
 * to request the program to be terminated cleanly.
 */
void eloop_terminate(void);

/**
 * eloop_destroy - Free any resources allocated for the event loop
 *
 * After calling eloop_destroy(), other eloop_* functions must not be called
 * before re-running eloop_init().
 */
void eloop_destroy(void);

/**
 * eloop_terminated - Check whether event loop has been terminated
 * Returns: 1 = event loop terminate, 0 = event loop still running
 *
 * This function can be used to check whether eloop_terminate() has been called
 * to request termination of the event loop. This is normally used to abort
 * operations that may still be queued to be run when eloop_terminate() was
 * called.
 */
int eloop_terminated(void);

/**
 * eloop_wait_for_read_sock - Wait for a single reader
 * @sock: File descriptor number for the socket
 *
 * Do a blocking wait for a single read socket.
 */
void eloop_wait_for_read_sock(int sock);

/**
 * eloop_get_user_data - Get global user data
 * Returns: user_data pointer that was registered with eloop_init()
 */
void * eloop_get_user_data(void);

#endif /* ELOOP_H */
