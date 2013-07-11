//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different rpc structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_STRUCT_H
#define RPC_STRUCT_H
//------------------------------------------------------------------------------
#include "../../auxiliary/exception.h"
#include "../xdr/xdr_struct.h"
#include "../xdr/xdr_reader.h"
//------------------------------------------------------------------------------
using namespace NST::filter::XDR;
using NST::auxiliary::Exception;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace rpc
{

class OpaqueAuth
{
public:
    OpaqueAuth()
    {
    }
    OpaqueAuth(XDRReader& in)
    {
        in >> *this;
    }

    uint32_t get_auth_flavor() const
    {
        return auth_flavor;
    }
    const OpaqueDyn& get_body() const
    {
        return body;
    }

    friend XDRReader& operator>>(XDRReader& in, OpaqueAuth& obj)
    {
        return in >> obj.auth_flavor >> obj.body;
    }

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

    uint32_t get_xid() const
    {
        return xid;
    }
    uint32_t get_type() const
    {
        return type;
    }
    void set_time(const struct timeval& t)
    {
        time.tv_sec = t.tv_sec;
        time.tv_usec = t.tv_usec;
    }
    const timeval& get_time() const
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

// STUB
class RPCReply : public RPCMessage
{
public:
    RPCReply(XDRReader& in) : RPCMessage(in)
    {
    }
    virtual ~RPCReply()
    {
    }

private:
    RPCReply(const RPCReply&);
    void operator=(const RPCReply&);
};

} // namespace rpc
} // namespace filter
} // namespace NFS
//------------------------------------------------------------------------------
#endif//RPC_STRUCT_H
//------------------------------------------------------------------------------

