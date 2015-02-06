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
#include <algorithm>
#include <numeric>

#include "breakdowncounter.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
BreakdownCounter::BreakdownCounter() {}

BreakdownCounter::~BreakdownCounter() {}

Latencies& BreakdownCounter::operator[](int index)
{
    return latencies[index];
}

uint64_t BreakdownCounter::get_total_count() const
{
    using LatenciesMap = std::map<int, NST::breakdown::Latencies>;

    return std::accumulate(std::begin(latencies), std::end(latencies), 0, [](int sum, LatenciesMap::value_type latency)
    {
        return sum + latency.second.get_count();
    });
}

const Latencies BreakdownCounter::operator[](int index) const
{
    if (latencies.find(index) != latencies.end())
    {
        return latencies.at(index);
    }
    return NST::breakdown::Latencies();
}
//------------------------------------------------------------------------------
