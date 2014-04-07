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
#include "utils/out.h"
#include "utils/sessions.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

using Session        = NST::utils::Session;
using NetworkSession = NST::utils::NetworkSession;

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
        key.port[0] = info.tcp->sport();
        key.port[1] = info.tcp->dport();

        key.ip.v4.addr[0] = info.ipv4->src();
        key.ip.v4.addr[1] = info.ipv4->dst();

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
            return key.port[0] +
                   key.port[1] +
                   key.ip.v4.addr[0] +
                   key.ip.v4.addr[1];
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
        key.port[0] = info.udp->sport();
        key.port[1] = info.udp->dport();

        key.ip.v4.addr[0] = info.ipv4->src();
        key.ip.v4.addr[1] = info.ipv4->dst();

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
            return key.port[0] +
                   key.port[1] +
                   key.ip.v4.addr[0] +
                   key.ip.v4.addr[1];
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

struct IPv6TCPMapper
{
    static inline void fill_session(const PacketInfo& info, NetworkSession& session)
    {
        session.ip_type   = Session::v6;
        session.type      = Session::TCP;
        session.direction = info.direction;

        session.port[0] = info.tcp->sport();
        session.port[1] = info.tcp->dport();

        memcpy(session.ip.v6.addr[0], &(info.ipv6->src()), sizeof(session.ip.v6.addr[0]));
        memcpy(session.ip.v6.addr[1], &(info.ipv6->dst()), sizeof(session.ip.v6.addr[1]));
    }

    static inline void fill_hash_key(PacketInfo& info, Session& key)
    {
        key.port[0] = info.tcp->sport();
        key.port[1] = info.tcp->dport();

        memcpy(key.ip.v6.addr[0], &(info.ipv6->src()), sizeof(key.ip.v6.addr[0]));
        memcpy(key.ip.v6.addr[1], &(info.ipv6->dst()), sizeof(key.ip.v6.addr[1]));

        const int r = memcmp(key.ip.v6.addr[0], key.ip.v6.addr[1], sizeof(key.ip.v6.addr[0]));

        if(r < 0) info.direction = Session::Source;
        else
        if(r > 0) info.direction = Session::Destination;
        else // Ok, addresses are equal, compare ports
        info.direction =  (key.port[0] < key.port[1]) ? Session::Source : Session::Destination;
    }

    struct KeyHash
    {
        std::size_t operator() (const Session& key) const
        {
            std::size_t ret = key.port[0] + key.port[1];
            for(std::size_t i=0; i<sizeof(key.ip.v6.addr[0]); ++i)
            {
                ret += key.ip.v6.addr[0][i];
            }
            for(std::size_t i=0; i<sizeof(key.ip.v6.addr[1]); ++i)
            {
                ret += key.ip.v6.addr[1][i];
            }
            return ret;
        }
    };

    struct KeyEqual
    {
        bool operator() (const Session& a, const Session& b) const
        {
            if((a.port[0] == b.port[0]) && (a.port[1] == b.port[1]))
            {
                // compare src and dst addresses in one call
                if(memcmp(&(a.ip.v6), &(b.ip.v6), sizeof(a.ip.v6)) == 0)
                    return true;
            }

            if((a.port[1] == b.port[0]) && (a.port[0] == b.port[1]))
            {
                if( memcmp(a.ip.v6.addr[1], b.ip.v6.addr[0], sizeof(a.ip.v6.addr[1])) == 0
                &&  memcmp(a.ip.v6.addr[0], b.ip.v6.addr[1], sizeof(a.ip.v6.addr[0])) == 0)
                    return true;
            }
            return false;
        }
    };
};

struct IPv6UDPMapper
{
    static inline void fill_session(const PacketInfo& info, NetworkSession& session)
    {
        session.ip_type   = Session::v6;
        session.type      = Session::UDP;
        session.direction = info.direction;

        session.port[0] = info.udp->sport();
        session.port[1] = info.udp->dport();

        memcpy(session.ip.v6.addr[0], &(info.ipv6->src()), sizeof(session.ip.v6.addr[0]));
        memcpy(session.ip.v6.addr[1], &(info.ipv6->dst()), sizeof(session.ip.v6.addr[1]));
    }

    static inline void fill_hash_key(PacketInfo& info, Session& key)
    {
        key.port[0] = info.udp->sport();
        key.port[1] = info.udp->dport();

        memcpy(key.ip.v6.addr[0], &(info.ipv6->src()), sizeof(key.ip.v6.addr[0]));
        memcpy(key.ip.v6.addr[1], &(info.ipv6->dst()), sizeof(key.ip.v6.addr[1]));

        const int r = memcmp(key.ip.v6.addr[0], key.ip.v6.addr[1], sizeof(key.ip.v6.addr[0]));

        if(r < 0) info.direction = Session::Source;
        else
        if(r > 0) info.direction = Session::Destination;
        else // Ok, addresses are equal, compare ports
        info.direction =  (key.port[0] < key.port[1]) ? Session::Source : Session::Destination;
    }

    struct KeyHash
    {
        std::size_t operator() (const Session& key) const
        {
            std::size_t ret = key.port[0] + key.port[1];
            for(std::size_t i=0; i<sizeof(key.ip.v6.addr[0]); ++i)
            {
                ret += key.ip.v6.addr[0][i];
            }
            for(std::size_t i=0; i<sizeof(key.ip.v6.addr[1]); ++i)
            {
                ret += key.ip.v6.addr[1][i];
            }
            return ret;
        }
    };

    struct KeyEqual
    {
        bool operator() (const Session& a, const Session& b) const
        {
            if((a.port[0] == b.port[0]) && (a.port[1] == b.port[1]))
            {
                // compare src and dst addresses in one call
                if(memcmp(&(a.ip.v6), &(b.ip.v6), sizeof(a.ip.v6)) == 0)
                    return true;
            }

            if((a.port[1] == b.port[0]) && (a.port[0] == b.port[1]))
            {
                if( memcmp(a.ip.v6.addr[1], b.ip.v6.addr[0], sizeof(a.ip.v6.addr[1])) == 0
                &&  memcmp(a.ip.v6.addr[0], b.ip.v6.addr[1], sizeof(a.ip.v6.addr[0])) == 0)
                    return true;
            }
            return false;
        }
    };
};

// SessionsHash creates sessions and stores them in hash
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
