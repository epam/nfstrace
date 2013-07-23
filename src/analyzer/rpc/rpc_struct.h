//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different rpc structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_STRUCT_H
#define RPC_STRUCT_H
//------------------------------------------------------------------------------
#include <sstream>
#include <string>

#include "../../auxiliary/exception.h"
#include "../../filter/rpc/rpc_header.h"
#include "../xdr/xdr_struct.h"
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

class OpaqueAuth
{
    // TODO: Parse authentication
public:
    OpaqueAuth()
    {
    }
    OpaqueAuth(XDRReader& in)
    {
        in >> *this;
    }

    inline uint32_t get_auth_flavor() const
    {
        return auth_flavor;
    }
    inline const OpaqueDyn& get_body() const
    {
        return body;
    }

    friend XDRReader& operator>>(XDRReader& in, OpaqueAuth& obj);

private:
    uint32_t auth_flavor;
    OpaqueDyn body;
};

class RPCMessage
{
public:
    RPCMessage(XDRReader& in)
    {
        in >> xid >> type;
    }
    virtual ~RPCMessage()
    {
    }
    friend std::ostream& operator<<(std::ostream& out, const RPCMessage& obj);

    inline uint32_t get_xid() const
    {
        return xid;
    }
    inline uint32_t get_type() const
    {
        return type;
    }
    inline void set_time(const struct timeval& t)
    {
        time = t;
    }
    inline const timeval& get_time() const
    {
        return time;
    }

private:
    RPCMessage(const RPCMessage&);
    void operator=(const RPCMessage&);

    uint32_t  xid;
    uint32_t  type;
    struct timeval   time;
};

class RPCCall : public RPCMessage
{
public:
    RPCCall(XDRReader& in) : RPCMessage(in)
    {
        in >> rpcvers >> prog >> vers >> proc >> cred >> verf;
    }
    virtual ~RPCCall()
    {
    }
    friend std::ostream& operator<<(std::ostream& out, const RPCCall& obj);

    inline uint32_t get_rpcvers() const
    {
        return rpcvers;
    }
    inline uint32_t get_prog() const
    {
        return prog;
    }
    inline uint32_t get_vers() const
    {
        return vers;
    }
    inline uint32_t get_proc() const
    {
        return proc;
    }
    inline const OpaqueAuth& get_cred() const
    {
        return cred;
    }
    inline const OpaqueAuth& get_verf() const
    {
        return verf;
    }
    
private:
    RPCCall(const RPCCall&);
    void operator=(const RPCCall&);

    uint32_t rpcvers;
    uint32_t prog;
    uint32_t vers;
    uint32_t proc;
    OpaqueAuth cred;
    OpaqueAuth verf;
};

struct MismatchInfo
{
    MismatchInfo(XDRReader& in)
    {
        in >> low >> high;
    }

    uint32_t low;
    uint32_t high;
private:
    MismatchInfo(const MismatchInfo&);
    void operator=(const MismatchInfo&);
};

struct AcceptedReply
{
    AcceptedReply(XDRReader& in) : mismatch_info(NULL)
    {
        in >> verf >> stat;
        switch(stat)
        {
            case SUNRPC_SUCCESS:
                in >> proc_spec_data;
                break;
            case SUNRPC_PROG_MISMATCH:
                mismatch_info = new MismatchInfo(in);
                break;
            case SUNRPC_PROG_UNAVAIL:
            case SUNRPC_PROC_UNAVAIL:
            case SUNRPC_GARBAGE_ARGS:
            case SUNRPC_SYSTEM_ERR:
                break;
            default:
                throw Exception("Invalid RPC's AcceptStat");
        }
    }
    virtual ~AcceptedReply()
    {
        delete mismatch_info;
    }

    OpaqueDyn       proc_spec_data;      // TODO: COPY TO THE LOCAL ARRAY
    OpaqueAuth      verf;
    MismatchInfo*   mismatch_info;
    uint32_t        stat;
private:
    AcceptedReply(const AcceptedReply&);
    void operator=(const AcceptedReply&);
};

struct RejectedReply
{
    RejectedReply(XDRReader& in) : mismatch_info(NULL), auth_stat(NULL)
    {
        in >> stat;
        switch(stat)
        {
            case SUNRPC_RPC_MISMATCH:
                mismatch_info = new MismatchInfo(in);
                break;
            case SUNRPC_AUTH_ERROR:
                auth_stat = new OpaqueAuth(in);
                break;
            default:
                throw Exception("Invalid RPC's RejectStat");
        }
    }
    virtual ~RejectedReply()
    {
        delete mismatch_info;
        delete auth_stat;
    }

    uint32_t        stat;
    MismatchInfo*   mismatch_info;
    OpaqueAuth*     auth_stat;
private:
    RejectedReply(const RejectedReply&);
    void operator=(const RejectedReply&);
};


struct RPCReply : public RPCMessage
{
    RPCReply(XDRReader& in) : RPCMessage(in), accepted(NULL), rejected(NULL)
    {
        in >> stat;
        switch(stat)
        {
            case SUNRPC_MSG_ACCEPTED:
                accepted = new AcceptedReply(in);
                break;
            case SUNRPC_MSG_DENIED:
                rejected = new RejectedReply(in);
                break;
            default:
                throw Exception("Invalid RPC's ReplyStat");
        }
    }
    virtual ~RPCReply()
    {
        delete accepted;
        delete rejected;
    }
    friend std::ostream& operator<<(std::ostream& out, const RPCReply& obj);

    uint32_t        stat;
    AcceptedReply*  accepted;
    RejectedReply*  rejected;
private:
    RPCReply(const RPCReply&);
    void operator=(const RPCReply&);
};

} // namespace rpc
} // namespace analyzer 
} // namespace NFS
//------------------------------------------------------------------------------
#endif//RPC_STRUCT_H
//------------------------------------------------------------------------------

