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
#include <string>

#include "../auxiliary/filtered_data.h"
#include "../auxiliary/session.h"
#include "transmission.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredDataQueue;
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

private:
    Session session;
    Map operations;
};

class RPCSessions
{
    typedef std::tr1::unordered_map<Transmission, RPCSession*, Transmission::Hash> Map;
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

    RPCSession* get_session(const Session& session, Type type)
    {
        Transmission key(session, (type == DIRECT) ? Session::Source : Session::Destination);

        Iterator el = sessions.find(key);
        if(el == sessions.end())
        {
            std::auto_ptr<RPCSession> s(new RPCSession(session));
            std::pair<Iterator, bool> in_res = sessions.insert(Pair(key, s.release()));
            if(in_res.second == false)
            {
                return NULL;
            }
            el = in_res.first;
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
