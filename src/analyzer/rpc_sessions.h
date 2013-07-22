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
#include "../filter/nfs/nfs_operation.h"
#include "transmission.h"
//------------------------------------------------------------------------------
using namespace NST::filter::NFS3;

using NST::auxiliary::Session;
using NST::auxiliary::FilteredData;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class RPCSession
{
    typedef std::tr1::unordered_map<uint32_t, RPCCall*> Map;
    typedef Map::value_type Pair;

public:
    typedef Map::iterator Iterator;

    RPCSession(const Session& s) : session(s)
    {
    }
    ~RPCSession()
    {
        Iterator i = operations.begin();
        Iterator end = operations.end();

        for(; i != end; ++i)
        {
            delete i->second;
        }
    }

    Iterator insert(std::auto_ptr<RPCCall>& call)
    {
        uint32_t xid = call->get_xid();
        Iterator el = find(xid);
        if(el == operations.end())
        {
            std::pair<Iterator, bool> res = operations.insert(Pair(xid, call.release()));
            if(res.second == true)
            {
                el = res.first;
            }
        }
        return el;
    }
    inline Iterator remove(Iterator& el)
    {
        return operations.erase(el);
    }
    inline Iterator find(uint32_t xid)
    {
        return operations.find(xid);
    }
    inline bool is_valid(Iterator& iterator)
    {
        return iterator != operations.end();
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
