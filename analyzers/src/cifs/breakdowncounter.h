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
#include <cinttypes>
#include <vector>

#include "latencies.h"
//------------------------------------------------------------------------------
/*! Counts and keeps breakdown statistic for session
 */
class BreakdownCounter
{
public:
    BreakdownCounter(std::size_t count);
    ~BreakdownCounter();

    /*!
     * \brief operator [] returns statistic by index (command number)
     * \param index - command number
     * \return statistic
     */
    const NST::breakdown::Latencies operator[](int index) const;

    /*!
     * \brief operator [] returns statistic by index (command number)
     * \param index - command number
     * \return statistic
     */
    NST::breakdown::Latencies& operator[](int index);

    /*!
     * \brief get_total_count returns total amount of commands
     * \return commands count
     */
    uint64_t get_total_count () const;

private:
    void operator= (const BreakdownCounter&) = delete;
    std::vector<NST::breakdown::Latencies> latencies;
};

/*!
 * Saves statistic on commands receive
 * \param proc - command
 * \param cmd_code - commands code
 * \param stats - statistic
 */
template<typename Cmd, typename Code, typename Stats>
void account(const Cmd* proc, Code cmd_code, Stats& stats)
{
    timeval latency {0, 0};
    const int cmd_index = static_cast<int>(cmd_code);

    // diff between 'reply' and 'call' timestamps
    timersub(proc->rtimestamp, proc->ctimestamp, &latency);

    stats.counter[cmd_index].add(latency);

    auto i = stats.per_session_statistic.find(*proc->session);
    if (i == stats.per_session_statistic.end())
    {
        auto session_res = stats.per_session_statistic.emplace(*proc->session, BreakdownCounter {stats.proc_types_count});
        if (session_res.second == false)
        {
            return;
        }
        i = session_res.first;
    }

    (i->second)[cmd_index].add(latency);
}
//------------------------------------------------------------------------------
#endif // BREAKDOWNCOUNTER_H
//------------------------------------------------------------------------------
