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

struct MapperImpl
{
    using Session        = NST::utils::Session;
    using NetworkSession = NST::utils::NetworkSession;

    MapperImpl() = delete;

    static inline Session::Direction ipv4_direction(const Session& key)
    {
        if(key.port[0] < key.port[1]) return Session::Source;
        else
        if(key.port[0] > key.port[1]) return Session::Destination;

        // Ok, ports are equal, compare addresses
        return (key.ip.v4.addr[0] < key.ip.v4.addr[1]) ? Session::Source : Session::Destination;
    }

    struct IPv4PortsKeyHash
    {
        inline std::size_t operator() (const Session& key) const
        {
            return key.port[0] +
                   key.port[1] +
                   key.ip.v4.addr[0] +
                   key.ip.v4.addr[1];
        }
    };

    struct IPv4PortsKeyEqual
    {
        inline bool operator() (const Session& a, const Session& b) const
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

    static inline Session::Direction ipv6_direction(const Session& key)
    {
        if(key.port[0] < key.port[1]) return Session::Source;
        else
        if(key.port[0] > key.port[1]) return Session::Destination;

        // Ok, ports are equal, compare addresses
        const uint32_t* s = key.ip.v6.addr_uint32[0];
        const uint32_t* d = key.ip.v6.addr_uint32[1];

        if(s[0] != d[0]) return (s[0] < d[0]) ? Session::Source : Session::Destination;
        if(s[1] != d[1]) return (s[1] < d[1]) ? Session::Source : Session::Destination;
        if(s[2] != d[2]) return (s[2] < d[2]) ? Session::Source : Session::Destination;

                         return (s[3] < d[3]) ? Session::Source : Session::Destination;
    }

    static inline void copy_ipv6(uint32_t dst[4], const uint8_t src[16])
    {
        // TODO:: fix alignment of src!
        const uint32_t* s = reinterpret_cast<const uint32_t*>(src);
        dst[0] = s[0];
        dst[1] = s[1];
        dst[2] = s[2];
        dst[3] = s[3];
    }

    struct IPv6PortsKeyHash
    {
        std::size_t operator() (const Session& key) const
        {
            std::size_t ret = key.port[0] + key.port[1];

            ret += key.ip.v6.addr_uint32[0][0];
            ret += key.ip.v6.addr_uint32[0][1];
            ret += key.ip.v6.addr_uint32[0][2];
            ret += key.ip.v6.addr_uint32[0][3];

            ret += key.ip.v6.addr_uint32[1][0];
            ret += key.ip.v6.addr_uint32[1][1];
            ret += key.ip.v6.addr_uint32[1][2];
            ret += key.ip.v6.addr_uint32[1][3];

            return ret;
        }
    };

    struct IPv6PortsKeyEqual
    {
        static inline bool eq_ipv6_address(const uint32_t a[4], const uint32_t b[4])
        {
            return a[0] == b[0] &&
                   a[1] == b[1] &&
                   a[2] == b[2] &&
                   a[3] == b[3];
        }

        bool operator() (const Session& a, const Session& b) const
        {
            if((a.port[0] == b.port[0]) && (a.port[1] == b.port[1]))
            {
                if( eq_ipv6_address(a.ip.v6.addr_uint32[0], b.ip.v6.addr_uint32[0] )
                &&  eq_ipv6_address(a.ip.v6.addr_uint32[1], b.ip.v6.addr_uint32[1] ))
                    return true;
            }

            if((a.port[1] == b.port[0]) && (a.port[0] == b.port[1]))
            {
                if( eq_ipv6_address(a.ip.v6.addr_uint32[1], b.ip.v6.addr_uint32[0] )
                &&  eq_ipv6_address(a.ip.v6.addr_uint32[0], b.ip.v6.addr_uint32[1] ))
                    return true;
            }
            return false;
        }
    };
};

struct IPv4TCPMapper : private MapperImpl
{
    static inline void fill_hash_key(PacketInfo& info, Session& key)
    {
        key.port[0] = info.tcp->sport();
        key.port[1] = info.tcp->dport();

        key.ip.v4.addr[0] = info.ipv4->src();
        key.ip.v4.addr[1] = info.ipv4->dst();

        info.direction = MapperImpl::ipv4_direction(key);
    }

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

    using KeyHash  = MapperImpl::IPv4PortsKeyHash;
    using KeyEqual = MapperImpl::IPv4PortsKeyEqual;
};

struct IPv4UDPMapper : private MapperImpl
{
    static inline void fill_hash_key(PacketInfo& info, Session& key)
    {
        key.port[0] = info.udp->sport();
        key.port[1] = info.udp->dport();

        key.ip.v4.addr[0] = info.ipv4->src();
        key.ip.v4.addr[1] = info.ipv4->dst();

        info.direction = MapperImpl::ipv4_direction(key);
    }

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

    using KeyHash  = MapperImpl::IPv4PortsKeyHash;
    using KeyEqual = MapperImpl::IPv4PortsKeyEqual;
};

struct IPv6TCPMapper : private MapperImpl
{
    static inline void fill_hash_key(PacketInfo& info, Session& key)
    {
        key.port[0] = info.tcp->sport();
        key.port[1] = info.tcp->dport();

        MapperImpl::copy_ipv6(key.ip.v6.addr_uint32[0], info.ipv6->src());
        MapperImpl::copy_ipv6(key.ip.v6.addr_uint32[1], info.ipv6->dst());

        info.direction = MapperImpl::ipv6_direction(key);
    }

    static inline void fill_session(const PacketInfo& info, NetworkSession& session)
    {
        session.ip_type   = Session::v6;
        session.type      = Session::TCP;
        session.direction = info.direction;

        session.port[0] = info.tcp->sport();
        session.port[1] = info.tcp->dport();

        MapperImpl::copy_ipv6(session.ip.v6.addr_uint32[0], info.ipv6->src());
        MapperImpl::copy_ipv6(session.ip.v6.addr_uint32[1], info.ipv6->dst());
    }

    using KeyHash  = MapperImpl::IPv6PortsKeyHash;
    using KeyEqual = MapperImpl::IPv6PortsKeyEqual;
};

struct IPv6UDPMapper : private MapperImpl
{
    static inline void fill_hash_key(PacketInfo& info, Session& key)
    {
        key.port[0] = info.udp->sport();
        key.port[1] = info.udp->dport();

        MapperImpl::copy_ipv6(key.ip.v6.addr_uint32[0], info.ipv6->src());
        MapperImpl::copy_ipv6(key.ip.v6.addr_uint32[1], info.ipv6->dst());

        info.direction = MapperImpl::ipv6_direction(key);
    }

    static inline void fill_session(const PacketInfo& info, NetworkSession& session)
    {
        session.ip_type   = Session::v6;
        session.type      = Session::UDP;
        session.direction = info.direction;

        session.port[0] = info.udp->sport();
        session.port[1] = info.udp->dport();

        MapperImpl::copy_ipv6(session.ip.v6.addr_uint32[0], info.ipv6->src());
        MapperImpl::copy_ipv6(session.ip.v6.addr_uint32[1], info.ipv6->dst());
    }

    using KeyHash  = MapperImpl::IPv6PortsKeyHash;
    using KeyEqual = MapperImpl::IPv6PortsKeyEqual;
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
                utils::NetworkSession& session = *(res.first->second);
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
