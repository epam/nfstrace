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

#include "controller/parameters.h"
#include "filtration/packet.h"
#include "utils/logger.h"
#include "utils/session.h"
//------------------------------------------------------------------------------
using NST::utils::Logger;
using NST::utils::Session;
using NST::utils::NetworkSession;
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

struct IPv4TCPMapper
{
    static inline void fill_session(const PacketInfo& info, NetworkSession& session)
    {
        session.ip_type   = Session::v4;
        session.type      = Session::TCP;
        session.direction = info.direction;

        session.port[0] = info.tcp->sport();
        session.port[1] = info.tcp->dport();

        session.ip.v4.addr[0] = info.ipv4->src();
        session.ip.v4.addr[1] = info.ipv4->dst();
    }

    static inline void fill_hash_key(PacketInfo& info, Session& key)
    {
        key.port[0] = info.tcp->network_bo_sport();
        key.port[1] = info.tcp->network_bo_dport();

        key.ip.v4.addr[0] = info.ipv4->network_bo_src();
        key.ip.v4.addr[1] = info.ipv4->network_bo_dst();

        if(key.ip.v4.addr[0] < key.ip.v4.addr[1]) info.direction = Session::Source;
        else
        if(key.ip.v4.addr[0] > key.ip.v4.addr[1]) info.direction = Session::Destination;
        else // Ok, addresses are equal, compare ports
        info.direction =  (key.port[0] < key.port[1]) ? Session::Source : Session::Destination;
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
    static inline void fill_session(const PacketInfo& info, NetworkSession& session)
    {
        session.ip_type   = Session::v4;
        session.type      = Session::UDP;
        session.direction = info.direction;

        session.port[0] = info.udp->sport();
        session.port[1] = info.udp->dport();

        session.ip.v4.addr[0] = info.ipv4->src();
        session.ip.v4.addr[1] = info.ipv4->dst();
    }

    static inline void fill_hash_key(PacketInfo& info, Session& key)
    {
        key.port[0] = info.udp->network_bo_sport();
        key.port[1] = info.udp->network_bo_dport();

        key.ip.v4.addr[0] = info.ipv4->network_bo_src();
        key.ip.v4.addr[1] = info.ipv4->network_bo_dst();

        if(key.ip.v4.addr[0] < key.ip.v4.addr[1]) info.direction = Session::Source;
        else
        if(key.ip.v4.addr[0] > key.ip.v4.addr[1]) info.direction = Session::Destination;
        else // Ok, addresses are equal, compare ports
        info.direction = (key.port[0] < key.port[1]) ? Session::Source : Session::Destination;
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
    static_assert(std::is_convertible<SessionImpl, utils::NetworkSession>::value,
                  "SessionImpl must be convertible to utils::NetworkSession");

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
        Mapper::fill_hash_key(info, key);

        auto i = sessions.find(key);
        if(i == sessions.end())
        {
            std::unique_ptr<SessionImpl> ptr{ new SessionImpl{writer, max_hdr} };

            auto res = sessions.emplace(key, ptr.get());
            if(res.second) // add new - success
            {
                ptr.release();
                i = res.first;

                // fill new session after construction
                NetworkSession& session = *(res.first->second);
                Mapper::fill_session(info, session);

                Logger::Buffer buffer;
                buffer << "create new session " << session;
            }
        }

        i->second->collect(info);
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
