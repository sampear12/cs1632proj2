/*
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __TCP_CON_MAP_H__
#define __TCP_CON_MAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <pthread.h>
#include <util/ip_address.h>
#include <time.h>

/* Forward declarations */
struct socket;
struct tcp_con_map;
struct packet;

/* TCP states you will use in your project */
typedef enum {
    CLOSED      = 0,
    LISTEN      = 1,
    SYN_RCVD    = 2,
    SYN_SENT    = 3,
    ESTABLISHED = 4,
    CLOSE_WAIT  = 5,
    FIN_WAIT1   = 6,
    CLOSING     = 7,
    LAST_ACK    = 8,
    FIN_WAIT2   = 9,
    TIME_WAIT   = 10
} tcp_con_state_t;

/*
 * IP tuple definition
 */
struct tcp_con_ipv4_tuple {
    struct ipv4_addr * local_ip;
    struct ipv4_addr * remote_ip;
    uint16_t           local_port;
    uint16_t           remote_port;
};

/*
 * The core TCP connection structure
 */
struct tcp_connection {
    ip_net_type_t net_type;

    union {
        struct tcp_con_ipv4_tuple ipv4_tuple;
        /* If IPv6 were supported, add an ipv6_tuple here */
    };

    int              ref_cnt;       /* Reference count for concurrency control */
    pthread_mutex_t  con_lock;      /* Mutex lock for this connection */
    struct socket   *sock;          /* Associated Petnet socket */

    /* **********************
     * Students fill in below 
     * **********************/
    tcp_con_state_t  con_state;

    /* 
     * TCP Sequence Numbers and Related Fields
     */
    uint32_t snd_iss;  /* Initial send sequence number */
    uint32_t snd_una;  /* Oldest unacknowledged sequence number */
    uint32_t snd_nxt;  /* Next sequence number to send */
    uint32_t rcv_nxt;  /* Next sequence number expected from remote side */
    uint32_t rcv_irs;  /* Initial receive sequence number */

    /* Window Management */
    uint32_t snd_wnd;  /* Send window size */
    uint32_t rcv_wnd;  /* Receive window size */
    uint32_t snd_mss;  /* Maximum segment size for sending */
    uint32_t rcv_mss;  /* Maximum segment size for receiving */

    /* Stop-and-Wait Protocol State */
    struct packet *unacked_pkt;  /* Currently unacknowledged packet */
    uint32_t retransmit_count;   /* Number of retransmissions for current packet */
    uint8_t waiting_for_ack;     /* Flag indicating if waiting for ACK */

    /* Timers and Timeouts */
    uint32_t rto;                /* Current retransmission timeout value (ms) */
    uint32_t srtt;              /* Smoothed round-trip time */
    uint32_t rttvar;            /* Round-trip time variation */
    struct timespec last_tx;     /* Timestamp of last transmission */
    struct timespec last_rx;     /* Timestamp of last receive */

    /* Buffer Management */
    char *send_buf;             /* Buffer for outgoing data */
    size_t send_buf_size;       /* Total size of send buffer */
    size_t send_buf_used;       /* Amount of data currently in send buffer */
    char *recv_buf;             /* Buffer for incoming data */
    size_t recv_buf_size;       /* Total size of receive buffer */
    size_t recv_buf_used;       /* Amount of data currently in receive buffer */

    /* Connection State Flags */
    int      syn_sent;          /* SYN has been sent */
    int      syn_ack_recv;      /* SYN-ACK has been received */
    int      fin_sent;          /* FIN has been sent */
    int      fin_recv;          /* FIN has been received */
    int      rst_sent;          /* RST has been sent */
    int      rst_recv;          /* RST has been received */

    /* Statistics and Debugging */
    uint32_t pkts_sent;         /* Total packets sent */
    uint32_t pkts_received;     /* Total packets received */
    uint32_t retransmissions;   /* Total retransmissions */
    uint32_t dup_acks_rcvd;     /* Duplicate ACKs received */
};

/*
 * Returns a locked reference to a TCP connection object corresponding to a socket.
 * The pointer behaves like a normal pointer, but you cannot free it. 
 * You must unlock and release the reference before returning.
 * 
 * Returns NULL on error
 */
struct tcp_connection * 
get_and_lock_tcp_con_from_sock(struct tcp_con_map * map,
                               struct socket       * socket);

/*
 * Returns a locked reference to a TCP connection object corresponding to an IPv4 tuple.
 * The pointer behaves like a normal pointer, but you cannot free it. 
 * You must unlock and release the reference before returning.
 * 
 * Returns NULL on error
 */
struct tcp_connection *
get_and_lock_tcp_con_from_ipv4(struct tcp_con_map * map,
                               struct ipv4_addr    * local_ip, 
                               struct ipv4_addr    * remote_ip,
                               uint16_t              local_port,
                               uint16_t              remote_port);

/*
 * Unlocks and releases the reference to a tcp_connection object after you are done using it
 */
void 
put_and_unlock_tcp_con(struct tcp_connection * con);

/*
 * Creates a TCP connection object and returns a locked reference to it.
 * 
 * NOTE: The object returned must be released with put_and_unlock_tcp_con() before returning
 * Returns NULL on error
 */
struct tcp_connection *
create_ipv4_tcp_con(struct tcp_con_map * map,
                    struct ipv4_addr   * local_ip, 
                    struct ipv4_addr   * remote_ip,
                    uint16_t             local_port,
                    uint16_t             remote_port);

/*
 * Associate a Socket with a TCP Connection.
 * This also allows searching for a TCP Connection object using its socket pointer.
 * 
 * Returns 0 on success, -1 on error
 */
int 
add_sock_to_tcp_con(struct tcp_con_map    * map,
                    struct tcp_connection * con, 
                    struct socket         * new_sock);

/*
 * Unregister a TCP Connection.
 * After this returns, the TCP connection will no longer be accessible via the get_* functions.
 */
void
remove_tcp_con(struct tcp_con_map    * map,
               struct tcp_connection * con);

/*
 * Acquire a mutex lock on a TCP connection.
 * 
 * Returns 0 on success, negative number on error
 */
int lock_tcp_con(struct tcp_connection * con);

/*
 * Release a mutex lock on a TCP connection.
 * 
 * Returns 0 on success, negative number on error
 */
int unlock_tcp_con(struct tcp_connection * con);

/*
 * Obtains a new reference to a TCP connection.
 * Returns the pointer passed as an argument, allowing for assignment like:
 *     my_conn = get_tcp_con(my_conn);
 */
struct tcp_connection *
get_tcp_con(struct tcp_connection * con);

/*
 * Releases a reference to a TCP connection.
 */
void
put_tcp_con(struct tcp_connection * con);

/*
 * Initializes a TCP Connection Map
 */
struct tcp_con_map * create_tcp_con_map();

#if 0
/*
 * Example for IPv6 if needed:
struct tcp_connection *
get_and_lock_tcp_con_from_ipv6(struct tcp_con_map * map,
                               struct ipv6_addr   * src_ip, 
                               struct ipv6_addr   * dst_ip,
                               uint16_t             src_port,
                               uint16_t             dst_port);
*/
#endif

#ifdef __cplusplus
}
#endif

#endif /* __TCP_CON_MAP_H__ */
