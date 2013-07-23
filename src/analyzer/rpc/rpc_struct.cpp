//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different rpc structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "rpc_struct.h"
#include "../../auxiliary/print/indent.h"
#include "../nfs3/nfs_procedures.h"
//------------------------------------------------------------------------------
using NST::auxiliary::print::Indent;
using NST::analyzer::NFS3::Proc;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer 
{
namespace RPC 
{

XDRReader& operator>>(XDRReader& in, OpaqueAuth& obj)
{
    return in >> obj.auth_flavor >> obj.body;
}

std::ostream& operator<<(std::ostream& out, const RPCMessage& obj)
{
    out << "RPC:" << std::endl;
    Indent indentation(out, 4);

    out << "xid: " << obj.xid << std::endl;
    out << "type: ";
    if(obj.type == SUNRPC_CALL)
        out << "CALL";
    else
        out << "REPLY";
    return out << std::endl;
}

std::ostream& operator<<(std::ostream& out, const RPCCall& obj)
{
    out << static_cast<const RPCMessage&>(obj);
    Indent indentation(out, 4);

    out << "rpcvers: " << obj.rpcvers << std::endl;
    out << "prog: " << obj.prog << std::endl;
    out << "vers: " << obj.vers << std::endl;
    out << "proc: " << Proc::titles[obj.proc] << "(" << obj.proc << ")";
    return out;
}

std::ostream& operator<<(std::ostream& out, const RPCReply& obj)
{
    out << static_cast<const RPCMessage&>(obj);
    Indent indentation(out, 4);

    out << "stat: ";
    if(obj.stat == SUNRPC_MSG_ACCEPTED)
        out << "MSG_ACCEPTED";
    else
        out << "MSG_DENIED";
    return out << std::endl;
}

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
