//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Hash for network sessions
// Copyright (c) 2014 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SESSIONS_HASH_H
#define SESSIONS_HASH_H
//------------------------------------------------------------------------------
#include <cassert>
#include <memory>
#include <type_traits>
#include <unordered_map>

#include <pcap/pcap.h>

#include "utils/logger.h"
#include "utils/session.h"
#include "controller/parameters.h"
#include "filtration/packet.h"
//------------------------------------------------------------------------------
using NST::utils::Logger;
using NST::utils::Session;
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

struct IPv4TCPMapper
{
    static void fill_session(const PacketInfo& info, Session& session)
    {
        session.ip_type = Session::v4;
        session.ip.v4.addr[0] = info.ipv4->src();
        session.ip.v4.addr[1] = info.ipv4->dst();

        session.type = Session::TCP;
        session.port[0] = info.tcp->sport();
        session.port[1] = info.tcp->dport();
    }

    static inline Session::Direction fill_hash_key(const PacketInfo& info, Session& key)
    {
        key.ip.v4.addr[0] = info.ipv4->network_bo_src();
        key.ip.v4.addr[1] = info.ipv4->network_bo_dst();

        key.port[0] = info.tcp->network_bo_sport();
        key.port[1] = info.tcp->network_bo_dport();

        if(key.ip.v4.addr[0] < key.ip.v4.addr[1]) return Session::Source;
        else
        if(key.ip.v4.addr[0] > key.ip.v4.addr[1]) return Session::Destination;
        else // Ok, addresses are equal, compare ports
        return (key.port[0] < key.port[1]) ? Session::Source : Session::Destination;
    }

    struct KeyHash
    {
        std::size_t operator() (const Session& key) const
        {
            return key.port[0] + key.port[1] + key.ip.v4.addr[0] + key.ip.v4.addr[1];
        }
    };

    struct KeyEqual
    {
        bool operator() (const Session& a, const Session& b) const
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
            return false;
        }
    };
};

struct IPv4UDPMapper
{
    static void fill_session(const PacketInfo& info, Session& session)
    {
        session.ip_type = Session::v4;
        session.ip.v4.addr[0] = info.ipv4->src();
        session.ip.v4.addr[1] = info.ipv4->dst();

        session.type = Session::UDP;
        session.port[0] = info.udp->sport();
        session.port[1] = info.udp->dport();
    }

    static inline Session::Direction fill_hash_key(const PacketInfo& info, Session& key)
    {
        key.ip.v4.addr[0] = info.ipv4->network_bo_src();
        key.ip.v4.addr[1] = info.ipv4->network_bo_dst();

        key.port[0] = info.udp->network_bo_sport();
        key.port[1] = info.udp->network_bo_dport();

        if(key.ip.v4.addr[0] < key.ip.v4.addr[1]) return Session::Source;
        else
        if(key.ip.v4.addr[0] > key.ip.v4.addr[1]) return Session::Destination;
        else // Ok, addresses are equal, compare ports
        return (key.port[0] < key.port[1]) ? Session::Source : Session::Destination;
    }

    struct KeyHash
    {
        std::size_t operator() (const Session& key) const
        {
            return key.port[0] + key.port[1] + key.ip.v4.addr[0] + key.ip.v4.addr[1];
        }
    };

    struct KeyEqual
    {
        bool operator() (const Session& a, const Session& b) const
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
            return false;
        }
    };
};

// SessionsHash creates sessions and stores them in hash
// Also it
template
<
    typename Mapper,        // map PacketInfo& to SessionImpl*
    typename SessionImpl,   // mapped type
    typename Writer
>
class SessionsHash
{
public:
    static_assert(std::is_convertible<SessionImpl, utils::Session>::value,
                  "SessionImpl must be convertible to utils::Session");

    using Container = std::unordered_map<utils::Session, SessionImpl*,
                                         typename Mapper::KeyHash,
                                         typename Mapper::KeyEqual>;

    SessionsHash(Writer* w)
    : sessions  { }
    , writer    {w}
    , max_hdr   {0}
    {
        max_hdr = controller::Parameters::instance()->rpcmsg_limit();
    }
    ~SessionsHash()
    {
        for(auto& s : sessions)
        {
            delete s.second;
        }
    }

    void collect_packet(PacketInfo& info)
    {
        utils::Session key;
        const Session::Direction direction = Mapper::fill_hash_key(info, key);

        auto i = sessions.find(key);
        if(i == sessions.end())
        {
            auto res = sessions.emplace(key, new SessionImpl{writer, max_hdr});
            i = res.first;
            if(res.second) // add new - success
            {
                // fill new session after construction
                utils::Session& session = *(res.first->second);
                Mapper::fill_session(info, session);

                Logger::Buffer buffer;
                buffer << "create new session " << session;
            }
        }

        i->second->collect(info, direction);
    }

private:
    Container sessions;
    Writer*   writer;
    uint32_t max_hdr;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//SESSIONS_HASH_H
//------------------------------------------------------------------------------
