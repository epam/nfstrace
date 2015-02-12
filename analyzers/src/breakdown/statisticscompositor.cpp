//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Statistics compositor
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
#include <assert.h>

#include "statisticscompositor.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
StatisticsCompositor::StatisticsCompositor(Statistics& procedures_stats, Statistics& operations_stats)
    : Statistics(operations_stats)
    , procedures_stats(procedures_stats)
{}

void StatisticsCompositor::for_each_procedure(std::function<void(const BreakdownCounter&, size_t)> on_procedure) const
{
    assert(procedures_stats.proc_types_count < proc_types_count);

    for (size_t procedure = 0; procedure < procedures_stats.proc_types_count; ++procedure)
    {
        on_procedure(procedures_stats.counter, procedure);
    }

    for (size_t procedure = procedures_stats.proc_types_count; procedure < proc_types_count; ++procedure)
    {
        on_procedure(counter, procedure);
    }
}

void StatisticsCompositor::for_each_procedure_in_session(const Session& session, std::function<void (const BreakdownCounter&, size_t)> on_procedure) const
{
    auto it = procedures_stats.per_session_statistics.find(session);
    if (it != procedures_stats.per_session_statistics.end())
    {
        for (size_t procedure = 0; procedure < procedures_stats.proc_types_count; ++procedure)
        {
            on_procedure((*it).second, procedure);
        }
    }
    else
    {
        BreakdownCounter empty(procedures_stats.proc_types_count);
        for (size_t procedure = 0; procedure < procedures_stats.proc_types_count; ++procedure)
        {
            on_procedure(empty, procedure);
        }
    }

    const BreakdownCounter& current = per_session_statistics.at(session);
    for (size_t procedure = procedures_stats.proc_types_count; procedure < proc_types_count; ++procedure)
    {
        on_procedure(current, procedure);
    }
}
