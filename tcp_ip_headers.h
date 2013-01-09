#ifndef _TCP_IP_HEADERS_H_
#define _TCP_IP_HEADERS_H_

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

/* Ethernet header */
struct ethhdr {
		u_char ether_dhost[ETH_ALEN]; /* Destination host address */
		u_char ether_shost[ETH_ALEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	} __attribute__((packed));

struct nfstrace_ip {
  uint8_t ip_vhl;/* header length, version */
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
  uint8_t ip_tos;/* type of service */
  uint16_t ip_len;/* total length */
  uint16_t ip_id;/* identification */
  uint16_t ip_off;/* fragment offset field */
#define IP_DF 0x4000/* dont fragment flag */
#define IP_MF 0x2000/* more fragments flag */
#define IP_OFFMASK 0x1fff/* mask for fragmenting bits */
  uint8_t ip_ttl;/* time to live */
  uint8_t ip_p;/* protocol */
  uint16_t ip_sum;/* checksum */
  struct in_addr ip_src,ip_dst;/* source and dest address */
} __attribute__ ((__packed__));

typedef uint32_t       tcp_seq;

struct nfstrace_tcp {
  uint16_t       th_sport;               /* source port */
  uint16_t       th_dport;               /* destination port */
  tcp_seq         th_seq;                 /* sequence number */
  tcp_seq         th_ack;                 /* acknowledgement number */
  uint8_t        th_offx2;               /* data offset, rsvd */
  uint8_t        th_flags;
  uint16_t       th_win;                 /* window */
  uint16_t       th_sum;                 /* checksum */
  uint16_t       th_urp;                 /* urgent pointer */
} __attribute__ ((__packed__));

#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)

/* sun rpc defines */
enum sunrpc_msg_type {
  SUNRPC_CALL=0,
        SUNRPC_REPLY=1
};

enum sunrpc_reply_stat {
  SUNRPC_MSG_ACCEPTED=0,
        SUNRPC_MSG_DENIED=1
};

enum sunrpc_accept_stat {
  SUNRPC_SUCCESS=0,
  SUNRPC_PROG_UNAVAIL=1,
  SUNRPC_PROG_MISMATCH=2,
  SUNRPC_PROC_UNAVAIL=3,
  SUNRPC_GARBAGE_ARGS=4,
        SUNRPC_SYSTEM_ERR=5
};
enum sunrpc_reject_stat {
  SUNRPC_RPC_MISMATCH=0,
        SUNRPC_AUTH_ERROR=1
};

/*
 * Reply part of an rpc exchange
 */

/*
 * Reply to an rpc request that was rejected by the server.
 */
struct sunrpc_rejected_reply {
  u_int32_t                rj_stat;       /* enum reject_stat */
  union {
    struct {
      u_int32_t low;
      u_int32_t high;
    } RJ_versions;
    u_int32_t RJ_why;  /* enum auth_stat - why authentication did not work */
  } ru;
#define rj_vers ru.RJ_versions
#define rj_why  ru.RJ_why
} __attribute__ ((__packed__));

/*
 * Body of a reply to an rpc request.
 */
struct sunrpc_reply_body {
  u_int32_t       rp_stat;                /* enum reply_stat */
  struct sunrpc_rejected_reply rp_reject; /* if rejected */
} __attribute__ ((__packed__));

enum sunrpc_auth_stat {
  SUNRPC_AUTH_OK=0,
  /*
   * failed at remote end
   */
  SUNRPC_AUTH_BADCRED=1,          /* bogus credentials (seal broken) */
  SUNRPC_AUTH_REJECTEDCRED=2,     /* client should begin new session */
  SUNRPC_AUTH_BADVERF=3,          /* bogus verifier (seal broken) */
  SUNRPC_AUTH_REJECTEDVERF=4,     /* verifier expired or was replayed */
  SUNRPC_AUTH_TOOWEAK=5,          /* rejected due to security reasons */
  /*
   * failed locally
   */
  SUNRPC_AUTH_INVALIDRESP=6,      /* bogus response verifier */
  SUNRPC_AUTH_FAILED=7            /* some unknown reason */
};

/*
 * Authentication info.  Opaque to client.
 */
struct sunrpc_opaque_auth {
  u_int32_t oa_flavor;            /* flavor of auth */
  u_int32_t oa_len;               /* length of opaque body */
  /* zero or more bytes of body */
}  __attribute__ ((__packed__));


/*
 * Body of an rpc request call.
 */
struct sunrpc_call_body {
  u_int32_t cb_rpcvers;   /* must be equal to two */
  u_int32_t cb_prog;
  u_int32_t cb_vers;
  u_int32_t cb_proc;
  struct sunrpc_opaque_auth cb_cred;
  /* followed by opaque verifier */
} __attribute__ ((__packed__));

/*
 * The rpc message
 */
struct sunrpc_msg {
  u_int32_t               rm_xid;
  u_int32_t               rm_direction;   /* enum msg_type */
  union {
    struct sunrpc_call_body RM_cmb;
    struct sunrpc_reply_body RM_rmb;
  } ru;
#define rm_call         ru.RM_cmb
#define rm_reply        ru.RM_rmb
} __attribute__ ((__packed__));

#endif
