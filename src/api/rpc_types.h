//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Definition of Sun RPC (Remote Procedure Call) types
// RFC 5531 2009 RPC: Remote Procedure Call Protocol Specification Version 2
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_TYPES_H
#define RPC_TYPES_H
//------------------------------------------------------------------------------
#include "xdr_types.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

const uint32_t SUNRPC_MSG_VERSION = 2;

enum MsgType : int32_t
{
    CALL =0,
    REPLY=1
};

enum ReplyStat : int32_t
{
    MSG_ACCEPTED=0,
    MSG_DENIED  =1
};

enum AcceptStat : int32_t
{
    SUCCESS      =0, /* RPC executed successfully             */
    PROG_UNAVAIL =1, /* remote hasn't exported program        */
    PROG_MISMATCH=2, /* remote can't support version #        */
    PROC_UNAVAIL =3, /* program can't support procedure       */
    GARBAGE_ARGS =4, /* procedure can't decode params         */
    SYSTEM_ERR   =5  /* errors like memory allocation failure */
};

enum RejectStat : int32_t
{
    RPC_MISMATCH =0, /* RPC version number != 2          */
    AUTH_ERROR   =1  /* remote can't authenticate caller */
};

// Status returned from authentication check
enum AuthStat : int32_t
{
    AUTH_OK                 =0, /* success                          */
    /*
     * failed at remote end
     */
    AUTH_BADCRED            =1, /* bad credential (seal broken)     */
    AUTH_REJECTEDCRED       =2, /* client must begin new session    */
    AUTH_BADVERF            =3, /* bad verifier (seal broken)       */
    AUTH_REJECTEDVERF       =4, /* verifier expired or replayed     */
    AUTH_TOOWEAK            =5, /* rejected for security reasons    */
    /*
     * failed locally
     */
    SUNRPC_AUTH_INVALIDRESP =6, /* bogus response verifier          */
    SUNRPC_AUTH_FAILED      =7, /* reason unknown                   */
    /*
     * AUTH_KERB errors; deprecated.  See [RFC2695]
     */
    AUTH_KERB_GENERIC      = 8, /* kerberos generic error           */
    AUTH_TIMEEXPIRE        = 9, /* time of credential expired       */
    AUTH_TKT_FILE          = 10,/* problem with ticket file         */
    AUTH_DECODE            = 11,/* can't decode authenticator       */
    AUTH_NET_ADDR          = 12,/* wrong net address in ticket      */
    /*
     * RPCSEC_GSS GSS related errors
     */
    RPCSEC_GSS_CREDPROBLEM = 13,/* no credentials for user          */
    RPCSEC_GSS_CTXPROBLEM  = 14 /* problem with context             */
};

enum AuthFlavor : int32_t
{
     AUTH_NONE       = 0,
     AUTH_SYS        = 1,
     AUTH_SHORT      = 2,
     AUTH_DH         = 3,
     RPCSEC_GSS      = 6
};

struct OpaqueAuth
{
    uint32_t flavor;
    Opaque   body;
};

struct MismatchInfo
{
    uint32_t low;
    uint32_t high;
};

struct RPCMessage
{
    uint32_t  xid;
    uint32_t type;
};

struct RPCCall : public RPCMessage
{
    uint32_t rpcvers;
    uint32_t prog;
    uint32_t vers;
    uint32_t proc;
    OpaqueAuth cred;
    OpaqueAuth verf;
};

struct AcceptedReply
{
    OpaqueAuth      verf;
    uint32_t        stat;
    MismatchInfo    mismatch_info;
};

struct RejectedReply
{
    uint32_t         stat;
    union U
    {
        MismatchInfo mismatch_info;
        OpaqueAuth   auth_stat;
    } u;
};

struct RPCReply : public RPCMessage
{
    uint32_t          stat;
    union U
    {
        AcceptedReply accepted;
        RejectedReply rejected;
    } u;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_TYPES_H
//------------------------------------------------------------------------------
