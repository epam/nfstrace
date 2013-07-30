//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Different rpc structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "rpc_structs.h"
#include "../../auxiliary/print/indent.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace RPC
{

/*
std::ostream& operator<<(std::ostream& out, const RPCMessage& obj)
{
    out << "RPC:" << std::endl;
    Indent indentation(out, 4);

    out << "xid: " << obj.get_xid() << std::endl;
    out << "type: ";
    out << ((obj.get_type() == SUNRPC_CALL) ? "CALL" : "REPLY");
    return out << std::endl;
}

std::ostream& operator<<(std::ostream& out, const RPCCall& obj)
{
    out << static_cast<const RPCMessage&>(obj);
    Indent indentation(out, 4);

    out << "rpcvers: " << obj.get_rpcvers() << std::endl;
    out << "prog: " << obj.get_prog() << std::endl;
    out << "vers: " << obj.get_vers() << std::endl;
    out << "proc: " << Proc::titles[obj.get_proc()] << "(" << obj.get_proc() << ")";
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
}*/

} // namespace RPC
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
