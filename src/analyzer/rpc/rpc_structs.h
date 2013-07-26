//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different rpc structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_STRUCTS_H
#define RPC_STRUCTS_H
//------------------------------------------------------------------------------
#include <sstream>
#include <string>

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
    friend XDRReader& operator>>(XDRReader& in, OpaqueAuth& obj);

    inline uint32_t    get_flavor() const { return flavor; }
    inline const Opaque& get_body() const { return body;   }

private:
    uint32_t flavor;
    Opaque   body;
};

struct MismatchInfo
{
    friend XDRReader& operator>>(XDRReader& in, MismatchInfo& obj);

    inline uint32_t  get_low() const { return low; }
    inline uint32_t get_high() const { return high;}

private:
    uint32_t low;
    uint32_t high;
};

class RPCMessage
{
public:
    RPCMessage(XDRReader& in)
    {
        // copy data to own storage
        dlen = in.data_size();
      //  std::cout << "len: " << dlen << std::endl;
        data = new uint8_t[dlen];
        memcpy(data, in.data(), dlen);
        // reset reader to read from own storage
        in.reset(data, dlen);

        in >> xid >> type;
    }
    virtual ~RPCMessage()
    {
        delete[] data;
    }

    inline uint32_t get_xid () const { return xid;  }
    inline uint32_t get_type() const { return type; }

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
    RPCMessage& operator=(const RPCMessage&);

    uint32_t         xid;
    uint32_t        type;
    struct timeval  time;

    uint8_t*        data;
    uint32_t        dlen;
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

    inline uint32_t get_rpcvers() const{ return rpcvers; }
    inline uint32_t get_prog() const { return prog; }
    inline uint32_t get_vers() const { return vers; }
    inline uint32_t get_proc() const { return proc; }
    inline const OpaqueAuth& get_cred() const { return cred; }
    inline const OpaqueAuth& get_verf() const { return verf; }

private:
    RPCCall(const RPCCall&);            // undefined
    RPCCall& operator=(const RPCCall&); // undefined

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
            default:
                throw Exception("Invalid RPC's AcceptStat");
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
            case SUNRPC_RPC_MISMATCH:
                in >> obj.u.mismatch_info;
                break;
            case SUNRPC_AUTH_ERROR:
                in >> obj.u.auth_stat;
                break;
            default:
                throw Exception("Invalid RPC's RejectStat");
        }
        return in;
    }

private:
    uint32_t         stat;
    union U
    {
        MismatchInfo mismatch_info;
        OpaqueAuth   auth_stat;
    } u;
};

struct RPCReply : public RPCMessage
{
    RPCReply(XDRReader& in) : RPCMessage(in)
    {
        in >> stat;
        switch(stat)
        {
            case SUNRPC_MSG_ACCEPTED:
                in >> u.accepted;
                break;
            case SUNRPC_MSG_DENIED:
                in >> u.rejected;
                break;
            default:
                throw Exception("Invalid RPC's ReplyStat");
        }
    }

private:
    RPCReply(const RPCReply&);
    RPCReply& operator=(const RPCReply&);

    uint32_t          stat;
    union U
    {
        AcceptedReply accepted;
        RejectedReply rejected;
    } u;

};

std::ostream& operator<<(std::ostream& out, const RPCMessage& obj);
std::ostream& operator<<(std::ostream& out, const RPCReply& obj);

} // namespace rpc
} // namespace analyzer 
} // namespace NFS
//------------------------------------------------------------------------------
#endif//RPC_STRUCTS_H
//------------------------------------------------------------------------------
