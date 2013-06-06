//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definitions of Sun RPC (Remote Procedure Call) protocol.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_MESSAGE_H
#define RPC_MESSAGE_H
//------------------------------------------------------------------------------
#include <stdint.h>
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

// Authentication info. Opaque to client.
struct rpc_opaque_auth
{
    uint32_t oa_flavor; // flavor of auth
    uint32_t oa_len;    // length of opaque body
    // up to 400 bytes of body
};

// Reply part of an rpc exchange

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
};

// Reply to an rpc request that was rejected by the server.
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
};

// Body of a reply to an rpc request.
struct rpc_reply_body
{
    uint32_t stat;   // enum ReplyStat
    union
    {
        struct rpc_accepted_reply areply;
        struct rpc_rejected_reply rreply;
    } reply_body;
};

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
};

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
};

} // namespace rpc
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_MESSAGE_H
//------------------------------------------------------------------------------
