//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition of TCP header and constants.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef TCP_HEADER_H
#define TCP_HEADER_H
//------------------------------------------------------------------------------
#include <stdint.h>
#include <arpa/inet.h>  // for ntohs()/ntohl()
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace tcp
{

// Transmission Control Protocol
struct tcp_header
{
    enum Flag // bit masks for flags
    {
        FIN = 0x01,     // finished send data
        SYN = 0x02,     // synchronize sequence numbers
        RST = 0x04,     // reset the connection
        PSH = 0x08,     // push data to the app layer
        ACK = 0x10,     // acknowledge
        URG = 0x20,     // urgent
        ECE = 0x40,     // ECN-echo
        CWR = 0x80      // congestion window reduced
    };

    uint16_t tcp_sport;     // source port
    uint16_t tcp_dport;     // destination port
    uint32_t tcp_seq;       // sequence number
    uint32_t tcp_ack;       // acknowledgement number
    uint8_t  tcp_rsrvd_off; // (unused) and data offset
    uint8_t  tcp_flags;     // control flags
    uint16_t tcp_win;       // window
    uint16_t tcp_sum;       // checksum
    uint16_t tcp_urp;       // urgent pointer
} __attribute__ ((__packed__));

struct TCPHeader : private tcp_header
{
    inline uint16_t sport() const { return ntohs(tcp_sport); }
    inline uint16_t dport() const { return ntohs(tcp_dport); }
    inline uint32_t   seq() const { return ntohl(tcp_seq); }
    inline uint32_t   ack() const { return ntohl(tcp_ack); }
    inline uint8_t offset() const { return (tcp_rsrvd_off & 0xf0) >> 2; }
    inline uint8_t  flags() const { return tcp_flags; }
    inline bool is(tcp_header::Flag flag) const { return tcp_flags & flag; }
    inline uint16_t window()   const { return ntohs(tcp_win); }
    inline uint16_t checksum() const { return ntohs(tcp_sum); }
    inline uint16_t urgent()   const { return ntohs(tcp_urp); }

    inline uint16_t network_bo_sport() const { return tcp_sport; }
    inline uint16_t network_bo_dport() const { return tcp_dport; }
} __attribute__ ((__packed__));

} // namespace tcp
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//TCP_HEADER_H
//------------------------------------------------------------------------------
