//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Hash for network sessions
// Copyright (c) 2014 EPAM Systems. All Rights Reserved.
// TODO: THIS CODE MUST BE TOTALLY REFACTORED!
//------------------------------------------------------------------------------
#ifndef SESSIONS_HASH_H
#define SESSIONS_HASH_H
//------------------------------------------------------------------------------
#include <cassert>
#include <memory>
#include <string>
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
    static inline Session::Direction fill_session(const PacketInfo& info, Session& s)
    {
        s.ip_type = Session::v4;
        s.ip.v4.addr[0] = info.ipv4->src();
        s.ip.v4.addr[1] = info.ipv4->dst();

        s.type = Session::TCP;
        s.port[0] = info.tcp->sport();
        s.port[1] = info.tcp->dport();

        if(s.ip.v4.addr[0] < s.ip.v4.addr[1]) return Session::Source;
        else
        if(s.ip.v4.addr[0] > s.ip.v4.addr[1]) return Session::Destination;
        else // Ok, addresses are equal, compare ports
        return (s.port[0] < s.port[1]) ? Session::Source : Session::Destination;
    }

    struct Hash
    {
        std::size_t operator() (const Session& s) const
        {
            return s.port[0] + s.port[1] + s.ip.v4.addr[0] + s.ip.v4.addr[1];
        }
    };

    struct Pred
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
    static inline Session::Direction fill_session(const PacketInfo& info, Session& s)
    {
        s.ip_type = Session::v4;
        s.ip.v4.addr[0] = info.ipv4->src();
        s.ip.v4.addr[1] = info.ipv4->dst();

        s.type = Session::UDP;
        s.port[0] = info.udp->sport();
        s.port[1] = info.udp->dport();

        if(s.ip.v4.addr[0] < s.ip.v4.addr[1]) return Session::Source;
        else
        if(s.ip.v4.addr[0] > s.ip.v4.addr[1]) return Session::Destination;
        else // Ok, addresses are equal, compare ports
        return (s.port[0] < s.port[1]) ? Session::Source : Session::Destination;
    }

    struct Hash
    {
        std::size_t operator() (const Session& s) const
        {
            return s.port[0] + s.port[1] + s.ip.v4.addr[0] + s.ip.v4.addr[1];
        }
    };

    struct Pred
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

template<typename Mapper, typename Collector, typename Writer>
class SessionsHash
{
public:

    using Container = std::unordered_map<Session, Collector*,
                                         typename Mapper::Hash,
                                         typename Mapper::Pred>;

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
        Session key;
        const Session::Direction direction = Mapper::fill_session(info, key);

        auto i = sessions.find(key);
        if(i == sessions.end())
        {
            auto res = sessions.emplace(key, new Collector{writer, max_hdr});
            i = res.first;
            if(res.second)
            {
                Logger::Buffer buffer;
                buffer << "create new session " << key;
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
