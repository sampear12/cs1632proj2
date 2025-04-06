/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include <petnet.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_hashtable.h>
#include <petlib/pet_json.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"


extern int petnet_errno;

// Forward declarations
static void __setup_new_connection(struct tcp_connection *);
static void __update_rtt_estimate(struct tcp_connection *, uint32_t);
static void __handle_packet_timeout(struct tcp_connection *);

struct tcp_state {
    struct tcp_con_map * con_map;
};

static void __print_debug_msg(const char *fmt, ...);
static struct packet *__construct_pkt(struct tcp_connection *);
static int __send_flagged_pkt(struct tcp_connection *, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t);
static int __close_connection(struct tcp_connection *);
static int __tcp_pkt_rx_ipv4(struct packet *);

static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet * pkt)
{
    struct tcp_raw_hdr * tcp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = tcp_hdr;
    pkt->layer_4_hdr_len = tcp_hdr->header_len * 4;

    return tcp_hdr;
}


static inline struct tcp_raw_hdr *
__make_tcp_hdr(struct packet * pkt, 
               uint32_t        option_len)
{
    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = pet_malloc(sizeof(struct tcp_raw_hdr) + option_len);
    pkt->layer_4_hdr_len = sizeof(struct tcp_raw_hdr) + option_len;

    return (struct tcp_raw_hdr *)(pkt->layer_4_hdr);
}

static inline void *
__get_payload(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return NULL;
    }

}

pet_json_obj_t
tcp_hdr_to_json(struct tcp_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    hdr_json = pet_json_new_obj("TCP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create TCP Header JSON\n");
        goto err;
    }

    pet_json_add_u16 (hdr_json, "src port",    ntohs(hdr->src_port));
    pet_json_add_u16 (hdr_json, "dst port",    ntohs(hdr->dst_port));
    pet_json_add_u32 (hdr_json, "seq num",     ntohl(hdr->seq_num));
    pet_json_add_u32 (hdr_json, "ack num",     ntohl(hdr->ack_num));
    pet_json_add_u8  (hdr_json, "header len",  hdr->header_len * 4);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "ACK flag",    hdr->flags.ACK);
    pet_json_add_bool(hdr_json, "PSH flag",    hdr->flags.PSH);
    pet_json_add_bool(hdr_json, "RST flag",    hdr->flags.RST);
    pet_json_add_bool(hdr_json, "SYN flag",    hdr->flags.SYN);
    pet_json_add_bool(hdr_json, "FIN flag",    hdr->flags.FIN);
    pet_json_add_u16 (hdr_json, "recv win",    ntohs(hdr->recv_win));
    pet_json_add_u16 (hdr_json, "checksum",    ntohs(hdr->checksum));
    pet_json_add_u16 (hdr_json, "urgent ptr",  ntohs(hdr->urgent_ptr));


    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}


void
print_tcp_header(struct tcp_raw_hdr * tcp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = tcp_hdr_to_json(tcp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize TCP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"TCP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;

}





int 
tcp_listen(struct socket    * sock, 
           struct ipv4_addr * local_addr,
           uint16_t           local_port)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con = NULL;
    uint8_t remote_ip_octets[] = {0, 0, 0, 0};
    struct ipv4_addr *remote_ip = ipv4_addr_from_octets(remote_ip_octets);

    con = create_ipv4_tcp_con(tcp_state->con_map, local_addr, remote_ip, local_port, 0);
    if (!con) {
        return -1;
    }

    __setup_new_connection(con);
    con->con_state = LISTEN;
    
    // Associate socket with connection
    if (add_sock_to_tcp_con(tcp_state->con_map, con, sock) != 0) {
        remove_tcp_con(tcp_state->con_map, con);
        return -1;
    }

    put_and_unlock_tcp_con(con);
    __print_debug_msg("Listening...\n");
    return 0;
}

int 
tcp_connect_ipv4(struct socket    * sock, 
                 struct ipv4_addr * local_addr, 
                 uint16_t           local_port,
                 struct ipv4_addr * remote_addr,
                 uint16_t           remote_port)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con = NULL;

    con = create_ipv4_tcp_con(tcp_state->con_map, local_addr, remote_addr, local_port, remote_port);
    if (!con) {
        return -1;
    }

    __setup_new_connection(con);
    
    // Associate socket with connection
    if (add_sock_to_tcp_con(tcp_state->con_map, con, sock) != 0) {
        remove_tcp_con(tcp_state->con_map, con);
        return -1;
    }

    // Send SYN
    __send_flagged_pkt(con, 0, 1, 0, 0, 0, 0);
    con->con_state = SYN_SENT;
    con->syn_sent = 1;
    
    // Record transmission time for potential retransmission
    clock_gettime(CLOCK_MONOTONIC, &con->last_tx);
    con->pkts_sent++;

    put_and_unlock_tcp_con(con);
    return 0;
}

static void __print_debug_msg(const char *fmt, ...) {
    if (!petnet_state->debug_enable) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    pet_vprintf(fmt, args);
    va_end(args);
}

// constructs a new packet for the specified tcp_connection
// payload is NULL by default
static struct packet *__construct_pkt(struct tcp_connection *con) {

    struct packet *pkt;
    struct tcp_raw_hdr *tcp_hdr;

    if (con == NULL) {
        return NULL;
    }

    pkt = create_empty_packet();
    tcp_hdr = __make_tcp_hdr(pkt, 0);

    tcp_hdr->src_port = htons(con->ipv4_tuple.local_port);
    tcp_hdr->dst_port = htons(con->ipv4_tuple.remote_port);
    tcp_hdr->header_len = pkt->layer_4_hdr_len / 4;
    tcp_hdr->checksum = 0;
    pkt->payload = NULL;
    pkt->payload_len = 0;

    return pkt;

}

static int __send_flagged_pkt(struct tcp_connection * con, uint8_t ack, uint8_t syn, uint8_t fin, uint8_t rst, uint8_t urg, uint8_t psh) {

    struct packet *pkt;
    struct tcp_raw_hdr *hdr;

    pkt = __construct_pkt(con);
    hdr = (struct tcp_raw_hdr *) pkt->layer_4_hdr;
    hdr->flags.ACK = ack;
    hdr->flags.FIN = fin;
    hdr->flags.PSH = psh;
    hdr->flags.RST = rst;
    hdr->flags.SYN = syn;
    hdr->flags.URG = urg;
    if (petnet_state->debug_enable) {
        pet_printf("About to send TCP packet...\n");
        print_tcp_header(hdr);
    }

    if (ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip) != 0) {
        return -1;
    }
    __print_debug_msg("Flagged packet transmitted\n");

    return 0;

}

// Implements the sending of data packets using stop-and-wait protocol
// Returns: 0 on success, -1 on error
static int __tcp_send_data(struct tcp_connection * tcp_conn) {
    // Variables to keep track of everything
    struct packet *my_packet;        // The packet we'll send
    struct socket *my_socket;        // Socket to get data from
    struct tcp_raw_hdr *tcp_hdr;    // TCP header we'll fill in
    uint32_t bytes_to_send = 0;     // How much data we can send
    void *temp_buffer = NULL;        // Temporary buffer for data
    
    // Get the socket from our connection
    my_socket = tcp_conn->sock;

    // Make sure everything is okay to send!
    // Prof said we need to check these things
    if (!tcp_conn) {
        __print_debug_msg("Oops - no connection!\n");
        return -1;
    }
    if (tcp_conn->waiting_for_ack) {
        // Stop-and-wait means we can only send one at a time
        __print_debug_msg("Still waiting for ACK from last packet\n");
        return -1;
    }
    if (tcp_conn->con_state != ESTABLISHED) {
        __print_debug_msg("Connection not established yet!\n");
        return -1;
    }

    // Figure out how much data we can send
    // The socket tells us how much data it has
    bytes_to_send = pet_socket_send_capacity(my_socket);
    if (bytes_to_send == 0) {
        __print_debug_msg("No data to send right now\n");
        return 0;  // Not an error, just nothing to do
    }

    // Make sure we don't send too much!
    // MSS = Maximum Segment Size (learned this in class)
    if (bytes_to_send > tcp_conn->snd_mss) {
        __print_debug_msg("Too much data! Limiting to MSS=%d\n", tcp_conn->snd_mss);
        bytes_to_send = tcp_conn->snd_mss;
    }

    // Create our packet - this is from the helper functions
    my_packet = __construct_pkt(tcp_conn);
    if (!my_packet) {
        // Always check for NULL! (learned this the hard way...)
        __print_debug_msg("Couldn't create packet :(\n");
        return -1;
    }

    // Now we need to set up the TCP header
    // This part is tricky - have to convert to network byte order!
    tcp_hdr = (struct tcp_raw_hdr *)my_packet->layer_4_hdr;
    tcp_hdr->seq_num = htonl(tcp_conn->snd_nxt);     // Next byte we'll send
    tcp_hdr->ack_num = htonl(tcp_conn->rcv_nxt);     // Next byte we expect
    tcp_hdr->flags.ACK = 1;  // Always ACK in established state (from lecture)
    
    // Now for the actual data
    // We need a temp buffer because the socket API works that way
    temp_buffer = pet_malloc(bytes_to_send);
    if (!temp_buffer) {
        // Uh oh, out of memory!
        __print_debug_msg("Out of memory for temp buffer!\n");
        pet_free(my_packet);
        return -1;
    }

    // Get the data from our socket
    pet_socket_sending_data(my_socket, temp_buffer, bytes_to_send);
    
    // Set up the packet payload
    my_packet->payload_len = bytes_to_send;
    my_packet->payload = pet_malloc(bytes_to_send);
    if (!my_packet->payload) {
        // More memory problems :(
        __print_debug_msg("Out of memory for packet payload!\n");
        pet_free(temp_buffer);
        pet_free(my_packet);
        return -1;
    }
    
    // Copy the data into our packet
    memcpy(my_packet->payload, temp_buffer, bytes_to_send);
    pet_free(temp_buffer);  // Don't need this anymore
    
    // For stop-and-wait protocol:
    // We need to save this packet in case we need to send it again
    // (This was confusing until I drew it out in my notes)
    if (tcp_conn->unacked_pkt != NULL) {
        // Clean up old packet first
        __print_debug_msg("Cleaning up old unacked packet\n");
        pet_free(tcp_conn->unacked_pkt->payload);
        pet_free(tcp_conn->unacked_pkt);
    }
    tcp_conn->unacked_pkt = my_packet;
    tcp_conn->waiting_for_ack = 1;     // Now we wait!
    tcp_conn->retransmit_count = 0;    // Haven't tried sending yet
    
    // Update our sequence number
    // Add the number of bytes we're sending
    // (This is how TCP keeps track of data)
    tcp_conn->snd_nxt += bytes_to_send;
    
    // Finally, send the packet!
    __print_debug_msg("Trying to send packet...\n");
    if (ipv4_pkt_tx(my_packet, tcp_conn->ipv4_tuple.remote_ip) < 0) {
        __print_debug_msg("Failed to send :(\n");
        // Clean up everything if we failed
        tcp_conn->waiting_for_ack = 0;
        tcp_conn->unacked_pkt = NULL;
        pet_free(my_packet->payload);
        pet_free(my_packet);
        return -1;
    }

    // Keep track of when we sent it
    // We need this for timeout calculations
    clock_gettime(CLOCK_MONOTONIC, &tcp_conn->last_tx);
    tcp_conn->pkts_sent++;
    
    __print_debug_msg("Woohoo! Sent %d bytes, now waiting for ACK\n", bytes_to_send);
    return 0;  // Success!
}

static int __tcp_pkt_rx_ipv4(struct packet *pkt) {
    struct tcp_state *tcp_state = petnet_state->tcp_state;
    struct tcp_connection *con = NULL;
    struct socket *sock = NULL;
    struct ipv4_raw_hdr *ipv4_hdr = (struct ipv4_raw_hdr *)pkt->layer_3_hdr;
    struct tcp_raw_hdr *tcp_hdr = __get_tcp_hdr(pkt);
    struct timespec now;
    uint32_t rtt_ms;
    struct ipv4_addr *src_ip = ipv4_addr_from_octets(ipv4_hdr->src_ip);
    struct ipv4_addr *dst_ip = ipv4_addr_from_octets(ipv4_hdr->dst_ip);
    uint16_t src_port = ntohs(tcp_hdr->src_port);
    uint16_t dst_port = ntohs(tcp_hdr->dst_port);

    if (petnet_state->debug_enable) {
        pet_printf("Received TCP packet\n");
        print_tcp_header(tcp_hdr);
    }

    con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, src_ip, dst_port, src_port);
    if (con == NULL) {
        // Try to find listening socket
        uint8_t octets[] = {0, 0, 0, 0};
        struct ipv4_addr *empty_src_ip = ipv4_addr_from_octets(octets);
        con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, empty_src_ip, dst_port, 0);
        if (con == NULL || con->con_state != LISTEN) {
            __print_debug_msg("No listening socket found\n");
            return -1;
        }
        
        // Create new connection for incoming SYN
        if (tcp_hdr->flags.SYN) {
            remove_tcp_con(tcp_state->con_map, con);
            con = create_ipv4_tcp_con(tcp_state->con_map, dst_ip, src_ip, dst_port, src_port);
            __setup_new_connection(con);
            con->con_state = LISTEN;
        } else {
            put_and_unlock_tcp_con(con);
            return -1;
        }
    }

    sock = con->sock;
    con->pkts_received++;

    // Handle ACKs for stop-and-wait
    if (tcp_hdr->flags.ACK && con->waiting_for_ack) {
        uint32_t ack_num = ntohl(tcp_hdr->ack_num);
        if (ack_num > con->snd_una) {
            // Valid new ACK
            clock_gettime(CLOCK_MONOTONIC, &now);
            rtt_ms = (now.tv_sec - con->last_tx.tv_sec) * 1000 + 
                    (now.tv_nsec - con->last_tx.tv_nsec) / 1000000;
            __update_rtt_estimate(con, rtt_ms);
            
            con->snd_una = ack_num;
            con->waiting_for_ack = 0;
            if (con->unacked_pkt) {
                pet_free(con->unacked_pkt->payload);
                pet_free(con->unacked_pkt);
                con->unacked_pkt = NULL;
            }
        } else if (ack_num == con->snd_una) {
            con->dup_acks_rcvd++;
        }
    }

    // State machine
    switch (con->con_state) {
        case ESTABLISHED:
            if (tcp_hdr->flags.RST) {
                __print_debug_msg("Received RST\n");
                __close_connection(con);
                pet_socket_closed(sock);
                
            } else if (tcp_hdr->flags.FIN) {
                __print_debug_msg("Received FIN\n");
                __send_flagged_pkt(con, 1, 0, 0, 0, 0, 0);  // ACK the FIN
                con->con_state = CLOSE_WAIT;
                __print_debug_msg("State changed to CLOSE_WAIT\n");
                __send_flagged_pkt(con, 0, 0, 1, 0, 0, 0);  // Send our FIN
                con->con_state = LAST_ACK;
                __print_debug_msg("State changed to LAST_ACK\n");
                
            } else if (pkt->payload_len > 0) {
                // Handle incoming data
                void *buf = pet_malloc(pkt->payload_len);
                memcpy(buf, pkt->payload, pkt->payload_len);
                pet_socket_received_data(sock, buf, pkt->payload_len);
                pet_free(buf);
                
                // Update receive next and send ACK
                con->rcv_nxt += pkt->payload_len;
                __send_flagged_pkt(con, 1, 0, 0, 0, 0, 0);
            }
            break;

        case LISTEN:
            if (tcp_hdr->flags.SYN) {
                __print_debug_msg("Received SYN\n");
                con->rcv_irs = ntohl(tcp_hdr->seq_num);
                con->rcv_nxt = con->rcv_irs + 1;
                __send_flagged_pkt(con, 1, 1, 0, 0, 0, 0);  // Send SYN-ACK
                con->con_state = SYN_RCVD;
                __print_debug_msg("State changed to SYN_RCVD\n");
            }
            break;

        case SYN_SENT:
            if (tcp_hdr->flags.SYN && tcp_hdr->flags.ACK) {
                __print_debug_msg("Received SYN-ACK\n");
                con->rcv_irs = ntohl(tcp_hdr->seq_num);
                con->rcv_nxt = con->rcv_irs + 1;
                __send_flagged_pkt(con, 1, 0, 0, 0, 0, 0);  // Send ACK
                con->con_state = ESTABLISHED;
                __print_debug_msg("State changed to ESTABLISHED\n");
                pet_socket_connected(sock);
            }
            break;

        case SYN_RCVD:
            if (tcp_hdr->flags.ACK) {
                __print_debug_msg("Received ACK\n");
                con->con_state = ESTABLISHED;
                __print_debug_msg("State changed to ESTABLISHED\n");
                pet_socket_accepted(sock, src_ip, src_port);
            }
            break;

        case FIN_WAIT1:
            if (tcp_hdr->flags.ACK) {
                if (tcp_hdr->flags.FIN) {
                    // Simultaneous close
                    con->con_state = CLOSING;
                    __print_debug_msg("State changed to CLOSING\n");
                } else {
                    con->con_state = FIN_WAIT2;
                    __print_debug_msg("State changed to FIN_WAIT2\n");
                }
            } else if (tcp_hdr->flags.FIN) {
                con->con_state = CLOSING;
                __print_debug_msg("State changed to CLOSING\n");
            }
            break;

        case FIN_WAIT2:
            if (tcp_hdr->flags.FIN) {
                __send_flagged_pkt(con, 1, 0, 0, 0, 0, 0);  // ACK the FIN
                con->con_state = TIME_WAIT;
                __print_debug_msg("State changed to TIME_WAIT\n");
                // Should start 2MSL timer here
            }
            break;

        case CLOSING:
            if (tcp_hdr->flags.ACK) {
                con->con_state = TIME_WAIT;
                __print_debug_msg("State changed to TIME_WAIT\n");
                // Should start 2MSL timer here
            }
            break;

        case LAST_ACK:
            if (tcp_hdr->flags.ACK) {
                __print_debug_msg("Received ACK in LAST_ACK\n");
                __close_connection(con);
                pet_socket_closed(sock);
            }
            break;

        default:
            break;
    }

    put_and_unlock_tcp_con(con);
    return 0;
}

int 
tcp_send(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);

    if (con->con_state != ESTABLISHED) {
        log_error("TCP connection is not established\n");
        if (con != NULL) put_and_unlock_tcp_con(con);
        return -1;
    }
    
    __tcp_send_data(con);
    put_and_unlock_tcp_con(con);
    return 0;

}

static int __close_connection(struct tcp_connection *con) {

    struct tcp_state *tcp_state = petnet_state->tcp_state;

    remove_tcp_con(tcp_state->con_map, con);
    return 0;

}

/* Petnet assumes SO_LINGER semantics, so if we'ere here there is no pending write data */
int
tcp_close(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);

    if (con->con_state != ESTABLISHED) {
        log_error("TCP connection is not established\n");
        if (con != NULL) put_and_unlock_tcp_con(con);
        return -1;
    }

    __send_flagged_pkt(con, 0, 0, 1, 0, 0, 0);
    con->con_state = FIN_WAIT1;
    __print_debug_msg("State changed to FIN_WAIT1\n");
    put_and_unlock_tcp_con(con);
    return 0;
}

int 
tcp_pkt_rx(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
		return __tcp_pkt_rx_ipv4(pkt);
    }

    return -1;
}

int 
tcp_init(struct petnet * petnet)
{
    struct tcp_state * tcp_state = NULL;

    tcp_state = pet_malloc(sizeof(struct tcp_state));
    if (!tcp_state) {
        log_error("Could not allocate TCP state\n");
        return -1;
    }

    tcp_state->con_map = create_tcp_con_map();
    if (!tcp_state->con_map) {
        log_error("Could not create TCP connection map\n");
        pet_free(tcp_state);
        return -1;
    }

    petnet->tcp_state = tcp_state;
    
    __print_debug_msg("TCP initialized\n");
    return 0;
}

// Helper function to update RTT estimates using Jacobson's algorithm
// This helps calculate better timeout values based on network conditions
static void 
__update_rtt_estimate(struct tcp_connection * connection, uint32_t measured_rtt_ms) {
    // Using alpha = 0.125 and beta = 0.25 as recommended in TCP/IP Illustrated
    const int alpha_shift = 3;  // alpha = 1/8 = 0.125
    const int beta_shift = 2;   // beta = 1/4 = 0.25
    
    // First RTT measurement - initialize estimates
    if (connection->srtt == 0) {
        connection->srtt = measured_rtt_ms;
        connection->rttvar = measured_rtt_ms / 2;
    } else {
        // Calculate RTT variation first (as recommended in RFC)
        // |SRTT - measured_rtt|
        int32_t rtt_diff = abs((int32_t)connection->srtt - (int32_t)measured_rtt_ms);
        connection->rttvar = connection->rttvar - (connection->rttvar >> beta_shift) + 
                           (rtt_diff >> beta_shift);
        
        // Update smoothed RTT estimate
        connection->srtt = connection->srtt - (connection->srtt >> alpha_shift) + 
                         (measured_rtt_ms >> alpha_shift);
    }
    
    // RTO = srtt + 4*rttvar (RFC recommendation)
    // Adding 1 second minimum as safety factor for my implementation
    connection->rto = connection->srtt + (connection->rttvar << 2);
    if (connection->rto < 1000) {
        connection->rto = 1000;  // Min RTO = 1 second (my choice for safety)
    }
    if (connection->rto > 60000) {
        connection->rto = 60000; // Max RTO = 1 minute (reasonable upper bound)
    }
}

// Handles packet retransmission on timeout
// Returns: 0 on success, -1 on error/connection dead
static int 
__handle_packet_timeout(struct tcp_connection * tcp_conn) {
    struct packet *lost_packet;
    
    // Basic error checking
    if (!tcp_conn || !tcp_conn->unacked_pkt || !tcp_conn->waiting_for_ack) {
        // Nothing to retransmit - not necessarily an error
        return 0;  
    }

    // Keep track of retransmission attempts
    tcp_conn->retransmit_count++;
    
    // My implementation uses max 5 retries:
    // With exponential backoff this gives total wait of:
    // 1 + 2 + 4 + 8 + 16 = 31 seconds before giving up
    // This seemed reasonable for a local network
    const int MAX_RETRIES = 5;
    if (tcp_conn->retransmit_count > (uint32_t)MAX_RETRIES) {
        // Too many retries - connection is probably dead
        __print_debug_msg("Max retransmissions reached - closing connection\n");
        __close_connection(tcp_conn);
        pet_socket_closed(tcp_conn->sock);
        return -1;
    }

    // Implement exponential backoff to prevent network congestion
    // Double timeout each retry (Karn's algorithm)
    tcp_conn->rto *= 2;  
    
    // Try sending the packet again
    lost_packet = tcp_conn->unacked_pkt;
    if (ipv4_pkt_tx(lost_packet, tcp_conn->ipv4_tuple.remote_ip) < 0) {
        __print_debug_msg("Failed to retransmit packet\n");
        return -1;
    }

    // Update transmission time for next timeout calculation
    clock_gettime(CLOCK_MONOTONIC, &tcp_conn->last_tx);
    tcp_conn->pkts_sent++;
    
    return 0;
}

// Initialize a new TCP connection with default values
// This sets up all the state needed for TCP to work properly
static void 
__setup_new_connection(struct tcp_connection * new_conn) 
{
    // Generate initial sequence number
    // Using a simple time-based approach for this project
    // Real TCP would use a more sophisticated method
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    uint32_t init_seq = (current_time.tv_sec * 1000 + 
                        current_time.tv_nsec / 1000000) & 0x7FFFFFFF;
    
    // Initialize sequence numbers
    new_conn->snd_iss = init_seq;  // Initial send sequence number
    new_conn->snd_una = init_seq;  // First unacknowledged byte
    new_conn->snd_nxt = init_seq;  // Next sequence number to use
    new_conn->rcv_nxt = 0;         // Will be set when we get SYN
    new_conn->rcv_irs = 0;         // Will be set when we get SYN
    
    // Set up flow control parameters
    // Using standard Ethernet MTU (1500) - TCP header size (20) = 1480
    // Could be more sophisticated with MSS option, but keeping it simple
    new_conn->snd_mss = 1480;  
    new_conn->rcv_mss = 1480;
    
    // Window sizes - using fixed values for this project
    // Real TCP would adjust these dynamically
    new_conn->snd_wnd = 1480;  // One segment
    new_conn->rcv_wnd = 1480;  // One segment
    
    // Initialize stop-and-wait protocol state
    new_conn->unacked_pkt = NULL;
    new_conn->waiting_for_ack = 0;
    new_conn->retransmit_count = 0;
    
    // Set up initial timer values
    // Using conservative initial values:
    // RTO = 3 seconds (RFC 6298 recommends 1 second, but being cautious)
    new_conn->rto = 3000;    // milliseconds
    new_conn->srtt = 0;      // Will be calculated after first RTT measurement
    new_conn->rttvar = 0;    // Will be calculated after first RTT measurement
    
    // Initialize timestamps
    clock_gettime(CLOCK_MONOTONIC, &new_conn->last_tx);
    clock_gettime(CLOCK_MONOTONIC, &new_conn->last_rx);
    
    // Statistics for debugging/monitoring
    new_conn->pkts_sent = 0;
    new_conn->pkts_received = 0;
    new_conn->retransmissions = 0;
    new_conn->dup_acks_rcvd = 0;
    
    __print_debug_msg("New connection initialized with ISS=%u\n", init_seq);
}
