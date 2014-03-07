//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Hash-table for rpc-sessions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_SESSIONS_H
#define RPC_SESSIONS_H
//------------------------------------------------------------------------------
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <utility>

#include "utils/filtered_data.h"
#include "utils/logger.h"
#include "utils/session.h"
//------------------------------------------------------------------------------
using NST::utils::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class RPCSession
{
public:

    RPCSession(const utils::NetworkSession& s, utils::Session::Direction call_direction)
    : session {s, call_direction}
    {
    }
    ~RPCSession()
    {
    }
    RPCSession(const RPCSession&)            = delete;
    RPCSession& operator=(const RPCSession&) = delete;
    
    void save_nfs_call_data(uint32_t xid, FilteredDataQueue::Ptr&& data)
    {
        auto res = operations.emplace(xid, std::move(data));
        if(res.second == false) // we have some Call data with same XID
        {
            //TODO: add tracing

            operations.erase(res.first);    // remove existing data
            operations.emplace(xid, std::move(data));  // insert new data
        }
    }
    inline FilteredDataQueue::Ptr get_nfs_call_data(uint32_t xid)
    {
        FilteredDataQueue::Ptr ptr;

        auto i = operations.find(xid);
        if(i != operations.end())
        {
            ptr = std::move(i->second);
            operations.erase(i);
        }
        return ptr;
    }

    inline const Session* get_session() const
    {
        return &session;
    }

    const std::string& str() const
    {
        if(session_str.empty())
        {
            std::stringstream stream(std::ios_base::out);
            stream << session;
            session_str = stream.str();
        }
        return session_str;
    }

private:
    mutable std::string session_str; // cached string representation of session

    utils::ApplicationsSession session;

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
            if(type == MsgType::SUNRPC_CALL) // add new session only for Call
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
