//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different rpc structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_STRUCTS_H
#define RPC_STRUCTS_H
//------------------------------------------------------------------------------
#include "../../auxiliary/exception.h"
#include "../../filter/rpc/rpc_header.h"
#include "../xdr/xdr_reader.h"
//------------------------------------------------------------------------------
using namespace NST::filter::rpc;
using namespace NST::analyzer::XDR;
using NST::auxiliary::Exception;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace RPC
{

struct OpaqueAuth
{
    inline friend XDRReader& operator>>(XDRReader& in, OpaqueAuth& o)
    {
        in >> o.flavor;
        in.read_varialble_len(o.body);
        return in;
    }

    inline uint32_t    get_flavor() const { return flavor; }
    inline const Opaque& get_body() const { return body;   }

private:
    uint32_t flavor;
    Opaque   body;
};

struct MismatchInfo
{
    inline friend XDRReader& operator>>(XDRReader& in, MismatchInfo& o)
    {
        return in >> o.low >> o.high;
    }

    inline uint32_t  get_low() const { return low; }
    inline uint32_t get_high() const { return high;}

private:
    uint32_t low;
    uint32_t high;
};

struct RPCMessage
{
    inline friend XDRReader& operator>>(XDRReader& in, RPCMessage& o)
    {
        return in >> o.xid >> o.type;
    }

    inline const uint32_t get_xid () const { return xid;  }
    inline const uint32_t get_type() const { return type; }

protected:
    uint32_t  xid;
    uint32_t type;
};

struct RPCCall : public RPCMessage
{
    inline friend XDRReader& operator>>(XDRReader& in, RPCCall& o)
    {
        in >> o.xid >> o.type; // direct fill RPCMessage fileds
        return in >> o.rpcvers >> o.prog >> o.vers >> o.proc >> o.cred >> o.verf;
    }

    inline const uint32_t get_rpcvers() const { return rpcvers; }
    inline const uint32_t    get_prog() const { return prog; }
    inline const uint32_t    get_vers() const { return vers; }
    inline const uint32_t    get_proc() const { return proc; }
    inline const OpaqueAuth& get_cred() const { return cred; }
    inline const OpaqueAuth& get_verf() const { return verf; }

private:
    uint32_t rpcvers;
    uint32_t prog;
    uint32_t vers;
    uint32_t proc;
    OpaqueAuth cred;
    OpaqueAuth verf;
};

struct AcceptedReply
{
    inline friend XDRReader& operator>>(XDRReader& in, AcceptedReply& obj)
    {
        in >> obj.verf >> obj.stat;
        switch(obj.stat)
        {
            case SUNRPC_SUCCESS:
                in.read_varialble_len(obj.proc_spec_data);
                break;
            case SUNRPC_PROG_MISMATCH:
                in >> obj.mismatch_info;
                break;
            case SUNRPC_PROG_UNAVAIL:
            case SUNRPC_PROC_UNAVAIL:
            case SUNRPC_GARBAGE_ARGS:
            case SUNRPC_SYSTEM_ERR:
                break;
        }
        return in;
    }

private:
    OpaqueAuth      verf;
    uint32_t        stat;
    Opaque          proc_spec_data;      // TODO: COPY TO THE LOCAL ARRAY
    MismatchInfo    mismatch_info;
};

struct RejectedReply
{
    inline friend XDRReader& operator>>(XDRReader& in, RejectedReply& obj)
    {
        in >> obj.stat;
        switch(obj.stat)
        {
            case SUNRPC_RPC_MISMATCH:   in >> obj.mismatch_info; break;
            case SUNRPC_AUTH_ERROR:     in >> obj.auth_stat;     break;
        }
        return in;
    }

    uint32_t         stat;
    union
    {
        MismatchInfo mismatch_info;
        OpaqueAuth   auth_stat;
    };
};

struct RPCReply : public RPCMessage
{
    inline friend XDRReader& operator>>(XDRReader& in, RPCReply& o)
    {
        in >> o.xid >> o.type; // direct fill RPCMessage fileds
        in >> o.stat;
        switch(o.stat)
        {
            case SUNRPC_MSG_ACCEPTED:  in >> o.accepted; break;
            case SUNRPC_MSG_DENIED:    in >> o.rejected; break;
        }
        return in;
    }

    uint32_t          stat;
    union
    {
        AcceptedReply accepted;
        RejectedReply rejected;
    };
};
/*
std::ostream& operator<<(std::ostream& out, const RPCMessage& obj);
std::ostream& operator<<(std::ostream& out, const RPCReply& obj);
*/
} // namespace rpc
} // namespace analyzer
} // namespace NFS
//------------------------------------------------------------------------------
#endif//RPC_STRUCTS_H
//------------------------------------------------------------------------------
