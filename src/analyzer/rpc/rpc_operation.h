//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Base structure for RPC Operation (Call + Reply + Session).
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_OPERATION_H
#define RPC_OPERATION_H
//------------------------------------------------------------------------------
#include <sys/time.h>
#include <iostream>

#include "../rpc_sessions.h"
#include "rpc_reader.h"
#include "rpc_structs.h"
//------------------------------------------------------------------------------
using NST::analyzer::RPCSession;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace RPC
{

class RPCOperation
{
public:

    RPCOperation(FilteredDataQueue::Ptr& c,
                 FilteredDataQueue::Ptr& r,
                 const RPCSession* s)
                 : cdata(c)
                 , rdata(r)
                 , session(s)
    {
        cdata >> call;  // fill call structure
        rdata >> reply; // fill reply structure
    }
    virtual ~RPCOperation()
    {
    }

public:
    inline const uint32_t            xid() const { return call.get_xid();  }
    inline const uint32_t      procedure() const { return call.get_proc(); }

    inline const RPCCall&      get_call () const { return call;     }
    inline const RPCReply&     get_reply() const { return reply;    }
    inline const RPCSession& get_session() const { return *session; }

    inline timeval get_call_time()  const { return cdata.data().timestamp; }
    inline timeval get_reply_time() const { return rdata.data().timestamp; }
    inline timeval latency() const
    {
        timeval diff;
        timerclear(&diff);
        timersub(&(rdata.data().timestamp), &(cdata.data().timestamp), &diff);
        return diff;
    }

private:
    RPCOperation(const RPCOperation&);            // undefined
    RPCOperation& operator=(const RPCOperation&); // undefined

protected:  // accessioble from inheritor class
    RPCReader cdata;    // data for RPC Call
    RPCReader rdata;    // data for RPC Reply

private:
    RPCCall  call;
    RPCReply reply;

    const RPCSession* session;
};

} // namespace RPC
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_OPERATION_H
//------------------------------------------------------------------------------
