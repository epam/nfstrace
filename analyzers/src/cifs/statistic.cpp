//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Statistic structure
// Copyright (c) 2015 EPAM Systems
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
#include "statistic.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
bool Less::operator()(const Session& a, const Session& b) const
{
    return ( (std::uint16_t)(a.ip_type) < (std::uint16_t)(b.ip_type) ) || // compare versions of IP address
           ( ntohs(a.port[0]) < ntohs(b.port[0])                     ) || // compare Source(client) ports
           ( ntohs(a.port[1]) < ntohs(b.port[1])                     ) || // compare Destination(server) ports

           ( (a.ip_type == Session::IPType::v4) ? // compare IPv4
             ((ntohl(a.ip.v4.addr[0]) < ntohl(b.ip.v4.addr[0])) || (ntohl(a.ip.v4.addr[1]) < ntohl(b.ip.v4.addr[1])))
             :
             (memcmp(&a.ip.v6, &b.ip.v6, sizeof(a.ip.v6)) < 0 )
           );
}

Statistic::Statistic(size_t proc_types_count)
    : proc_types_count(proc_types_count)
    , counter(proc_types_count)
{}

void Statistic::for_each_procedure(std::function<void (const BreakdownCounter&, size_t)> on_procedure) const
{
    for (size_t procedure = 0; procedure < proc_types_count; ++procedure)
    {
        on_procedure(counter, procedure);
    }
}

void Statistic::for_each_session(std::function<void (const Session&)> on_session) const
{
    for (auto& it : per_session_statistic)
    {
        on_session(it.first);
    }
}

void Statistic::for_each_procedure_in_session(const Session& session, std::function<void (const BreakdownCounter&, size_t)> on_procedure) const
{
    const BreakdownCounter& current = per_session_statistic.at(session);
    for (size_t procedure = 0; procedure < proc_types_count; ++procedure)
    {
        on_procedure(current, procedure);
    }
}
//------------------------------------------------------------------------------
