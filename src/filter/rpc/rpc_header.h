//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definitions of Sun RPC (Remote Procedure Call) protocol headers.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_HEADER_H
#define RPC_HEADER_H
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
     AUTH_SHORT      = 2
};


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
    inline const uint32_t astat() const
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


class RPCValidator
{
public:
    static inline bool check(const MessageHeader*const msg)
    {
        const uint32_t type = msg->type();

        return type == SUNRPC_CALL ||
               type == SUNRPC_REPLY;
    }

    static inline bool check(const CallHeader*const call)
    {
        return call->rpcvers() == SUNRPC_MSG_VERSION;
    }

    static inline bool check(const ReplyHeader*const reply)
    {
        const uint32_t stat = reply->stat();
        
        return stat == SUNRPC_MSG_ACCEPTED ||
               stat == SUNRPC_MSG_DENIED;
    }
private:
    RPCValidator();  // undefined
};


template
<
    uint32_t Program,   // remote program number
    uint32_t Version,   // remote program version number
    uint32_t MinProc,   // min remote procedure number
    uint32_t MaxProc    // max remote procedure number
>
class RPCProgramValidator
{
public:
    static inline bool check(const CallHeader*const call)
    {
        const uint32_t proc = call->proc();

        return          proc <= MaxProc &&
                        proc >= MinProc &&
                call->prog() == Program &&
                call->vers() == Version ;
    }
private:
    RPCProgramValidator();  // undefined
};

// TODO: move to special NFSv3 header
typedef RPCProgramValidator<100003,// SunRPC/NFS program
                                3,      // v3
                                0,      // NFSPROC3_NULL
                                21>     // NFSPROC3_COMMIT
                                NFSv3Validator;


} // namespace rpc
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_HEADER_H
//------------------------------------------------------------------------------
