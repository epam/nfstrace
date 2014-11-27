//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Hash-table for rpc-sessions.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
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
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class RPCSession : public utils::ApplicationSession
{
    using FilteredDataQueue = NST::utils::FilteredDataQueue;
public:

    RPCSession(const utils::NetworkSession& s, utils::Session::Direction call_direction)
    : utils::ApplicationSession{s, call_direction}
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
        auto i = operations.find(xid);
        if(i != operations.end())
        {
            FilteredDataQueue::Ptr ptr{std::move(i->second)};
            operations.erase(i);
            return ptr;
        }
        else
        {
            LOG("RPC Call XID:%u is not found for %s", xid, str().c_str());
        }

        return FilteredDataQueue::Ptr{};
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
    RPCSessions& operator=(const RPCSessions&) = delete;

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
