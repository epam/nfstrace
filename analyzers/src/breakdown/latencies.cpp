//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Helpers for parsing CIFS v2 structures.
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
#include <cmath>

#include "latencies.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------

Latencies::Latencies() : count {0}, avg {0}, m2 {0}
{
    timerclear(&min);
    timerclear(&max);
}

void Latencies::add(const timeval& t)
{
    long double x = to_sec(t);
    long double delta = x - avg;
    avg += delta / (++count);
    m2 += delta * (x - avg);

    set_range(t);
}

uint64_t Latencies::get_count() const
{
    return count;
}

long double Latencies::get_avg() const
{
    return avg;
}

long double Latencies::get_st_dev() const
{
    if (count < 2)
    {
        return 0;
    }
    return sqrt(m2 / (count - 1));
}

const timeval& Latencies::get_min() const
{
    return min;
}

const timeval& Latencies::get_max() const
{
    return max;
}

void Latencies::set_range(const timeval& t)
{
    if (timercmp(&t, &min, < ))
    {
        min = t;
    }
    if (min.tv_sec == 0 && min.tv_usec == 0)
    {
        min = t;
    }
    if (timercmp(&t, &max, > ))
    {
        max = t;
    }
}

long double NST::breakdown::to_sec(const timeval& val)
{
    return (((long double)val.tv_sec) + ((long double)val.tv_usec) / 1000000.0);
}
//------------------------------------------------------------------------------
