//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Statistic counter
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
#ifndef BREAKDOWNCOUNTER_H
#define BREAKDOWNCOUNTER_H
//------------------------------------------------------------------------------
#include <algorithm>
#include <numeric>

#include "latencies.h"
//------------------------------------------------------------------------------
template
<
    typename T,
    class Algorithm,
    int COUNT
    >
class BreakdownCounter
{
public:
    BreakdownCounter() {}
    ~BreakdownCounter() {}
    const NST::breakdown::Latencies& operator[](int index) const
    {
        return latencies[index];
    }
    NST::breakdown::Latencies& operator[](int index)
    {
        return latencies[index];
    }

    uint64_t getTotalCount () const
    {
        return std::accumulate(std::begin(latencies), std::end(latencies), 0, [](int sum, const NST::breakdown::Latencies& latency)
        {
            return sum + latency.get_count();
        });
    }

private:
    void operator=  (const BreakdownCounter&) = delete;

    NST::breakdown::Latencies latencies[COUNT];
};


template<typename Cmd, typename Code, typename Stats>
void account(const Cmd* proc, Code cmd_code, Stats& stats)
{
    typename Stats::PerOpStat::iterator i;
    timeval latency {0, 0};

    // diff between 'reply' and 'call' timestamps
    timersub(proc->rtimestamp, proc->ctimestamp, &latency);

    ++stats.procedures_total_count;
    ++stats.procedures_count[cmd_code];

    i = stats.per_procedure_statistic.find(*proc->session);
    if (i == stats.per_procedure_statistic.end())
    {
        auto session_res = stats.per_procedure_statistic.emplace(*proc->session, typename Stats::Breakdown {});
        if (session_res.second == false)
        {
            return;
        }
        i = session_res.first;
    }

    (i->second)[static_cast<int>(cmd_code)].add(latency);
}

//------------------------------------------------------------------------------
#endif // BREAKDOWNCOUNTER_H
//------------------------------------------------------------------------------

