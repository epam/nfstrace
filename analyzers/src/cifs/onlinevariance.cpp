//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Calculator of average timeouts
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

#include "onlinevariance.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------

NST::breakdown::OnlineVariance::OnlineVariance()
    : count {0}
    , avg {}
    , m2 {}
{}

OnlineVariance::~OnlineVariance() {}

void OnlineVariance::add(const timeval &t)
{
    T x = to_sec<T>(t);
    T delta = x - avg;
    avg += delta / (++count);
    m2 += delta * (x - avg);
}

uint32_t OnlineVariance::get_count() const
{
    return count;
}

OnlineVariance::T OnlineVariance::get_avg() const
{
    return avg;
}

OnlineVariance::T OnlineVariance::get_st_dev() const
{
    if (count < 2)
    {
        return T();
    }
    return sqrt(m2 / (count - 1));
}
//------------------------------------------------------------------------------
