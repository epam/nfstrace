//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Statistics counter
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
#include <map>

#include "latencies.h"
//------------------------------------------------------------------------------
/*! Counts and keeps breakdown statistic
 */
class BreakdownCounter
{
public:
    BreakdownCounter();
    ~BreakdownCounter();

    const NST::breakdown::Latencies operator[](int index) const;

    NST::breakdown::Latencies& operator[](int index);

    uint64_t get_total_count () const;

private:
    void operator= (const BreakdownCounter&) = delete;
    std::map<int, NST::breakdown::Latencies> latencies;
};

template<typename Cmd, typename Code, typename Stats>
void account(const Cmd* proc, Code cmd_code, Stats& stats)
{
    timeval latency {0, 0};

    // diff between 'reply' and 'call' timestamps
    timersub(proc->rtimestamp, proc->ctimestamp, &latency);

    ++stats.procedures_total_count;
    ++stats.procedures_count[static_cast<int>(cmd_code)];

    auto i = stats.per_procedure_statistic.find(*proc->session);
    if (i == stats.per_procedure_statistic.end())
    {
        auto session_res = stats.per_procedure_statistic.emplace(*proc->session, BreakdownCounter {});
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
