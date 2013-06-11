//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definitions of Sun RPC (Remote Procedure Call) protocol.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_MESSAGE_H
#define RPC_MESSAGE_H
//------------------------------------------------------------------------------
#include <iostream>
#include <stdint.h>

#include <arpa/inet.h> // for ntohl() by Single UNIX ® Specification, Version 2
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace rpc
{

const uint32_t SUNRPC_MSG_VERSION = 2;

/*
 * Bottom up definition of an rpc message.
 * NOTE: call and reply use the same overall struct but
 * different parts of unions within it.
 */

enum MsgType
{
    SUNRPC_CALL =0,
    SUNRPC_REPLY=1
};

enum ReplyStat
{
    SUNRPC_MSG_ACCEPTED=0,
    SUNRPC_MSG_DENIED  =1
};

enum AcceptStat
{
    SUNRPC_SUCCESS      =0, /* RPC executed successfully             */
    SUNRPC_PROG_UNAVAIL =1, /* remote hasn't exported program        */
    SUNRPC_PROG_MISMATCH=2, /* remote can't support version #        */
    SUNRPC_PROC_UNAVAIL =3, /* program can't support procedure       */
    SUNRPC_GARBAGE_ARGS =4, /* procedure can't decode params         */
    SUNRPC_SYSTEM_ERR   =5  /* errors like memory allocation failure */
};

enum RejectStat
{
    SUNRPC_RPC_MISMATCH =0, /* RPC version number != 2          */
    SUNRPC_AUTH_ERROR   =1  /* remote can't authenticate caller */
};

// Status returned from authentication check
enum AuthStat
{
    SUNRPC_AUTH_OK          =0, /* success                          */
    /*
     * failed at remote end
     */
    SUNRPC_AUTH_BADCRED     =1, /* bad credential (seal broken)     */
    SUNRPC_AUTH_REJECTEDCRED=2, /* client must begin new session    */
    SUNRPC_AUTH_BADVERF     =3, /* bad verifier (seal broken)       */
    SUNRPC_AUTH_REJECTEDVERF=4, /* verifier expired or replayed     */
    SUNRPC_AUTH_TOOWEAK     =5, /* rejected for security reasons    */
    /*
     * failed locally
     */
    SUNRPC_AUTH_INVALIDRESP =6, /* bogus response verifier          */
    SUNRPC_AUTH_FAILED      =7  /* reason unknown                   */
};

enum AuthFlavor
{
     AUTH_NONE       = 0,
     AUTH_SYS        = 1,
     AUTH_SHORT      = 2,
};

// Authentication info. Opaque to client.
struct rpc_opaque_auth
{
    uint32_t oa_flavor; // flavor of auth
    uint32_t oa_len;    // length of opaque body, not to exceed MAX_AUTH_BYTES
} __attribute__ ((__packed__));


// Reply part of an RPC exchange

/*
 * Reply to an rpc request that was accepted by the server.
 * Note: there could be an error even though the request was
 * accepted.
 */
struct rpc_accepted_reply
{
    struct rpc_opaque_auth  ar_verf;
    uint32_t                ar_stat;    // enum AcceptStat
    union
    {
        struct
        {
            uint32_t low;
            uint32_t high;
        } mismatch_info;
        struct
        {
        /* procedure-specific results start here */
        } results;
        // and many other null cases
    } reply_data;
} __attribute__ ((__packed__));

// Reply to an RPC request that was rejected by the server.
struct rpc_rejected_reply
{
    uint32_t rej_stat;   // enum RejectStat
    union
    {
        struct
        {
            uint32_t low;
            uint32_t high;
        } mismatch_info;
        uint32_t auth_stat;  // enum AuthStat
    } reply_data;
} __attribute__ ((__packed__));

// Body of a reply to an RPC request.
struct rpc_reply_body
{
    uint32_t stat;   // enum ReplyStat
    union
    {
        struct rpc_accepted_reply areply;
        struct rpc_rejected_reply rreply;
    } reply_body;
} __attribute__ ((__packed__));

// Body of an rpc request call.
struct rpc_call_body
{
    uint32_t cb_rpcvers;  /* must be equal to two (2) */
    uint32_t cb_prog;
    uint32_t cb_vers;
    uint32_t cb_proc;
    struct rpc_opaque_auth cb_cred;
    struct rpc_opaque_auth cb_verf;
    /* procedure specific parameters start here */
} __attribute__ ((__packed__));

// The rpc message.
struct rpc_msg
{
    uint32_t xid;
    uint32_t mtype; // enum MsgType
    union
    {
        struct rpc_call_body  cbody;
        struct rpc_reply_body rbody;
    } body;
} __attribute__ ((__packed__));



struct MessageHeader; // forward declaration

struct RecordMark   //  RFC 1831 section.10
{
    inline const bool            is_last() const { return ntohl(mark) & 0x80000000; /*1st bit*/  }
    inline const uint32_t   fragment_len() const { return ntohl(mark) & 0x7FFFFFFF; /*31 bits*/  }
    inline const MessageHeader* fragment() const { return (MessageHeader*)(this+1);              }
private:
    RecordMark(); // undefined

    uint32_t mark;
}__attribute__ ((__packed__));


struct OpaqueAuthHeader
{
    inline const uint32_t   flavor() const { return ntohl(m_flavor);  }
    inline const uint32_t      len() const { return ntohl(m_len);     }
    inline const char* opaque_data() const { return (char*)(this+1);  }
private:
    OpaqueAuthHeader(); // undefined

    uint32_t m_flavor;
    uint32_t m_len;

}__attribute__ ((__packed__));


struct MessageHeader
{
    inline const uint32_t xid () const { return ntohl(m_xid);  }
    inline const uint32_t type() const { return ntohl(m_type); }
private:
    MessageHeader(); // undefined

    uint32_t m_xid;
    uint32_t m_type;
} __attribute__ ((__packed__));


struct CallHeader: public MessageHeader
{
    inline const uint32_t rpcvers() const { return ntohl(m_rpcvers);  }
    inline const uint32_t    prog() const { return ntohl(m_prog); }
    inline const uint32_t    vers() const { return ntohl(m_vers); }
    inline const uint32_t    proc() const { return ntohl(m_proc); }

    inline const OpaqueAuthHeader* credential() const
    {
        return (OpaqueAuthHeader*)(this+1);
    }
    inline const OpaqueAuthHeader*   verifier() const
    {
        const OpaqueAuthHeader* cred = credential();
        return (OpaqueAuthHeader*)(cred->opaque_data() + cred->len());
    }
private:
    CallHeader(); // undefined

    uint32_t m_rpcvers;  // must be equal to two (2)
    uint32_t m_prog;
    uint32_t m_vers;
    uint32_t m_proc;
} __attribute__ ((__packed__));


// TODO: finish definitions of RPC replies!
struct ReplyHeader: public MessageHeader
{
    inline const uint32_t stat() const { return ntohl(m_stat); }

private:
    ReplyHeader(); // undefined

    uint32_t m_stat;   // enum ReplyStat
};


struct AcceptedReplyHeader: public ReplyHeader
{
    inline const OpaqueAuthHeader* verifier() const
    {
        return (OpaqueAuthHeader*)(this);
    }
    inline const uint32_t stat() const
    {
        const OpaqueAuthHeader* verf = verifier();
        const uint32_t* stat = (uint32_t*)(verf->opaque_data() + verf->len());
        return ntohl(*stat);
    }
    inline const char* reply_data() const
    {
        const OpaqueAuthHeader* verf = verifier();
        return (verf->opaque_data() + verf->len() + sizeof(uint32_t)/*stat*/);
    }
private:
    AcceptedReplyHeader(); // undefined
};


struct RejectedReplyHeader: public ReplyHeader
{
    inline const uint32_t    stat() const { return ntohl(m_stat);         }
    inline const char* reply_data() const { return (const char*)(this+1); }
private:
    RejectedReplyHeader(); // undefined

    uint32_t m_stat;   // enum RejectStat
};


class AuthSYS  // RFC1831 appendix A: System Authentication
{
public:
    AuthSYS(const OpaqueAuthHeader* header);

    inline const uint32_t           stamp() const { return m_stamp;       }
    inline const std::string& machinename() const { return m_machinename; }
    inline const uint32_t             uid() const { return m_uid; }
    inline const uint32_t             gid() const { return m_gid; }
    inline const uint32_t      guid_count() const { return m_guid_count; }
    inline const uint32_t*          guids() const { return m_guids; }

private:
    uint32_t m_stamp;
    std::string m_machinename;  // TODO: there is performance drop in memory allocation
    uint32_t m_uid;
    uint32_t m_gid;
    uint32_t m_guid_count;
    uint32_t m_guids[16];
};


uint32_t rpc_roundup(uint32_t a); // round up uint32_t to near multiplicity of 4

// some functions for print out structures
std::ostream& operator<<(std::ostream& out, const OpaqueAuthHeader& a);
std::ostream& operator<<(std::ostream& out, const AuthSYS& a);
std::ostream& operator<<(std::ostream& out, const CallHeader& a);


} // namespace rpc
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_MESSAGE_H
//------------------------------------------------------------------------------
