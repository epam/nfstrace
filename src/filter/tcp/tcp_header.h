//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition of TCP header and constants.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef TCP_HEADER_H
#define TCP_HEADER_H
//------------------------------------------------------------------------------
#include <stdint.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
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
        PSH = 0x08,      // push data to the app layer
        ACK = 0x10,     // acknowledge
        URG = 0x20,     // urgent
        ECE = 0x40,     // ECN-echo
        CWR = 0x80,     // congestion window reduced
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

} //namespace tcp
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//TCP_HEADER_H
//------------------------------------------------------------------------------
