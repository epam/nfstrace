//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Hash-table for rpc-sessions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_SESSIONS_H
#define RPC_SESSIONS_H
//------------------------------------------------------------------------------
#include <tr1/unordered_map>
#include <memory>
#include <sstream>
#include <string>

#include "../auxiliary/filtered_data.h"
#include "../auxiliary/logger.h"
#include "../auxiliary/session.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredDataQueue;
using NST::auxiliary::Session;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class RPCSession
{
    // TODO: Dangerous code the FilteredDataQueue::Ptr works like std::auto_ptr (move copy semantic)!
    typedef std::tr1::unordered_map<uint32_t, FilteredDataQueue::Ptr> Map;
    typedef Map::value_type Pair;

public:
    typedef NST::auxiliary::Session Session;
    typedef Map::iterator Iterator;

    RPCSession(const Session& s) : session(s)
    {
    }
    ~RPCSession()
    {
    }
    
    void save_nfs_call_data(uint32_t xid, FilteredDataQueue::Ptr& data)
    {
        std::pair<Iterator, bool> res = operations.insert( Pair(xid, data) );
        if(res.second == false) // we have some Call data with same XID
        {
            // TODO: add warning to log
            // remove existing data
            operations.erase(res.first);
            // insert new data
            res = operations.insert( Pair(xid, data) );
        }
    }
    inline FilteredDataQueue::Ptr get_nfs_call_data(uint32_t xid)
    {
        FilteredDataQueue::Ptr ptr;

        Iterator i = operations.find(xid);
        if(i != operations.end())
        {
            ptr = i->second;
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
    RPCSession(const RPCSession&);              // undefined
    RPCSession& operator=(const RPCSession&);   // undefined

    mutable std::string session_str;    // cached string representation of session

    Session session;
    Map operations;
};

class RPCSessions
{

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


    typedef std::tr1::unordered_map<Session, RPCSession*, Hash, Pred> Map;
    typedef Map::iterator Iterator;
    typedef Map::const_iterator ConstIterator;
    typedef Map::value_type Pair;

public:
    enum Type
    {
        DIRECT,
        REVERSE
    };

    RPCSessions()
    {
    }
    ~RPCSessions()
    {
        Iterator i = sessions.begin();
        Iterator end = sessions.end();

        for(; i != end; ++i)
        {
            delete i->second;
        }
    }

    RPCSession* get_session(const Session& key, Type type)
    {
        Iterator el = sessions.find(key);
        if(el == sessions.end())
        {
            if(type == DIRECT) // add new session only for Call (type == DIRECT)
            {
                std::auto_ptr<RPCSession> s(new RPCSession(key));
                std::pair<Iterator, bool> in_res = sessions.insert(Pair(key, s.release()));
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
    RPCSessions(const RPCSessions&);
    void operator=(const RPCSessions&);

    Map sessions;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_SESSIONS_H
//------------------------------------------------------------------------------
