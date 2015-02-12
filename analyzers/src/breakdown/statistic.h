//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Statistics structure
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
#ifndef STATISTICS_H
#define STATISTICS_H
//------------------------------------------------------------------------------
#include <functional>
#include <map>

#include <api/plugin_api.h>

#include "breakdowncounter.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
/*! \brief Comparator for sessions
 */
struct Less
{
    bool operator() (const Session& a, const Session& b) const;
};

/*! \brief All statistics data
 */
struct Statistics
{
    using PerSessionStatistics = std::map<Session, BreakdownCounter, Less>;
    using ProceduresCount = std::vector<int>;

    const size_t proc_types_count;//!< Count of types of procedures

    BreakdownCounter counter;//!< Statistics for all sessions
    PerSessionStatistics per_session_statistics;//!< Statistics for each session
    Statistics(size_t proc_types_count);

    virtual void for_each_procedure(std::function<void(const BreakdownCounter&, size_t)> on_procedure) const;

    void for_each_session(std::function<void(const Session&)> on_session) const;

    virtual void for_each_procedure_in_session(const Session& session, std::function<void(const BreakdownCounter&, size_t)> on_procedure) const;

    /*!
     * Saves statistics on commands receive
     * \param proc - command
     * \param cmd_code - commands code
     * \param stats - statistics
     */
    template<typename Cmd, typename Code>
    void account(const Cmd* proc, Code cmd_code)
    {
        timeval latency {0, 0};
        const int cmd_index = static_cast<int>(cmd_code);

        // diff between 'reply' and 'call' timestamps
        timersub(proc->rtimestamp, proc->ctimestamp, &latency);

        counter[cmd_index].add(latency);

        auto i = per_session_statistics.find(*proc->session);
        if (i == per_session_statistics.end())
        {
            auto session_res = per_session_statistics.emplace(*proc->session, BreakdownCounter {proc_types_count});
            if (session_res.second == false)
            {
                return;
            }
            i = session_res.first;
        }

        (i->second)[cmd_index].add(latency);
    }

};
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // STATISTICS_H
//------------------------------------------------------------------------------

