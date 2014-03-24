//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Hash-table for rpc-sessions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_SESSIONS_H
#define RPC_SESSIONS_H
//------------------------------------------------------------------------------
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <utility>

#include "protocols/rpc/rpc_header.h"
#include "utils/filtered_data.h"
#include "utils/log.h"
#include "utils/out.h"
#include "utils/sessions.h"
//------------------------------------------------------------------------------
using NST::utils::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class RPCSession : public utils::ApplicationsSession
{
public:

    RPCSession(const utils::NetworkSession& s, utils::Session::Direction call_direction)
    : utils::ApplicationsSession{s, call_direction}
    {
        utils::Out message;
        message << "Detect session " << str();
    }
    ~RPCSession() = default;
    RPCSession(const RPCSession&)            = delete;
    RPCSession& operator=(const RPCSession&) = delete;
    
    void save_nfs_call_data(const uint32_t xid, FilteredDataQueue::Ptr&& data)
    {
        FilteredDataQueue::Ptr& e = operations[xid];
        if(e)                   // xid call already exists
        {
            LOG("replace RPC Call XID:%u for %s", xid, str().c_str());
        }

        e = std::move(data);    // replace existing or set new
    }
    inline FilteredDataQueue::Ptr get_nfs_call_data(const uint32_t xid)
    {
        FilteredDataQueue::Ptr ptr;

        auto i = operations.find(xid);
        if(i != operations.end())
        {
            ptr = std::move(i->second);
            operations.erase(i);
        }
        else
        {
            LOG("RPC Call XID:%u is not found for %s", xid, str().c_str());
        }

        return ptr;
    }

    inline const Session* get_session() const { return this; }
private:

    // TODO: add custom allocator based on BlockAllocator
    // to decrease cost of expensive insert/erase operations
    std::unordered_map<uint32_t, FilteredDataQueue::Ptr> operations;
};

class RPCSessions
{
public:
    using MsgType = NST::protocols::rpc::MsgType;

    RPCSessions() = default;
    ~RPCSessions()= default;
    RPCSessions(const RPCSessions&)           = delete;
    RPCSessions operator=(const RPCSessions&) = delete;

    RPCSession* get_session(utils::NetworkSession* app, NST::utils::Session::Direction dir, MsgType type)
    {
        if(app->application == nullptr)
        {
            if(type == MsgType::CALL) // add new session only for Call
            {
                std::unique_ptr<RPCSession> ptr{ new RPCSession{*app, dir} };
                sessions.emplace_back(std::move(ptr));

                app->application = sessions.back().get(); // set reference
            }
        }

        return reinterpret_cast<RPCSession*>(app->application);
    }

private:
    std::vector< std::unique_ptr<RPCSession> > sessions;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_SESSIONS_H
//------------------------------------------------------------------------------
