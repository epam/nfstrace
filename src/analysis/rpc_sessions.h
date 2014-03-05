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
    using Session = NST::utils::Session;

    RPCSession(const Session& s) : session(s)
    {
    }
    RPCSession(const RPCSession&)            = delete;
    RPCSession& operator=(const RPCSession&) = delete;
    ~RPCSession()
    {
    }
    
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

    Session session;
    std::unordered_map<uint32_t, FilteredDataQueue::Ptr> operations;
};

class RPCSessions
{
public:
    enum class Type { DIRECT, REVERSE };

    RPCSessions()
    {
    }
    RPCSessions(const RPCSessions&)           = delete;
    RPCSessions operator=(const RPCSessions&) = delete;
    ~RPCSessions()
    {
        for(auto& i : sessions)
        {
            delete i.second;
        }
    }

    RPCSession* get_session(const Session& key, Type type)
    {
        auto el = sessions.find(key);
        if(el == sessions.end())
        {
            if(type == Type::DIRECT) // add new session only for Call (type == DIRECT)
            {
                std::auto_ptr<RPCSession> s(new RPCSession(key));
                auto in_res = sessions.emplace(key, s.release());
                if(in_res.second == false)
                {
                    return NULL;
                }
                el = in_res.first;
            }
            else
            {
                return NULL;
            }
        }

        return el->second;
    }

private:

    struct Hash
    {
        std::size_t operator()(const Session& s) const
        {
            std::size_t key = s.port[0] + s.port[1];

            if(s.ip_type == Session::v4)
            {
                key += s.ip.v4.addr[0] + s.ip.v4.addr[1];
            }
            else
            {
                for(int i = 0; i < 16; ++i)
                {
                    key += s.ip.v6.addr[0][i] + s.ip.v6.addr[1][i];
                }
            }
            key <<= s.type;
            return key;
        }
    };

    struct Pred
    {
        bool operator() (const Session& a, const Session& b) const
        {
            if((a.ip_type != b.ip_type) || (a.type != b.type)) return false;

            switch(a.ip_type)
            {
                case Session::v4:
                {
                    if((a.port[0] == b.port[0]) &&
                       (a.port[1] == b.port[1]) &&
                       (a.ip.v4.addr[0] == b.ip.v4.addr[0]) &&
                       (a.ip.v4.addr[1] == b.ip.v4.addr[1]))
                        return true;

                    if((a.port[1] == b.port[0]) &&
                       (a.port[0] == b.port[1]) &&
                       (a.ip.v4.addr[1] == b.ip.v4.addr[0]) &&
                       (a.ip.v4.addr[0] == b.ip.v4.addr[1]))
                        return true;
                }
                break;
                case Session::v6:
                {
                    if((a.port[0] == b.port[0]) &&
                       (a.port[1] == b.port[1]) )
                    {
                        int i = 0;
                        for(; i < 16; ++i)
                        {
                            if((a.ip.v6.addr[0][i] != b.ip.v6.addr[0][i]) ||
                               (a.ip.v6.addr[1][i] != b.ip.v6.addr[1][i]))
                                break;
                        }
                        if(i == 16) return true;
                    }

                    if((a.port[1] == b.port[0]) &&
                       (a.port[0] == b.port[1]) )
                    {
                        int i = 0;
                        for(; i < 16; ++i)
                        {
                            if((a.ip.v6.addr[1][i] != b.ip.v6.addr[0][i]) ||
                               (a.ip.v6.addr[0][i] != b.ip.v6.addr[1][i]))
                                break;
                        }
                        if(i == 16) return true;
                    }
                }
                break;
            }
            return false;
        }
    };

    std::unordered_map<Session, RPCSession*, Hash, Pred> sessions;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_SESSIONS_H
//------------------------------------------------------------------------------
