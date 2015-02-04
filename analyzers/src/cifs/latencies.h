//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Latencies calculator
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
#ifndef LATENCIES_H
#define LATENCIES_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <sys/time.h>

#include "onlinevariance.h"
//------------------------------------------------------------------------------

namespace NST
{
namespace breakdown
{
//------------------------------------------------------------------------------
/*!
 * \brief The Latencies class calculates latencies
 */
class Latencies
{
public:
    Latencies();

    void add(const timeval& t);
    uint64_t       get_count()  const;
    long double    get_avg()    const;
    long double    get_st_dev() const;
    const timeval& get_min()    const;
    const timeval& get_max()    const;

private:
    void operator=(const Latencies&) = delete;

    void set_range(const timeval& t);

    OnlineVariance algorithm;
    timeval min;
    timeval max;
};
//------------------------------------------------------------------------------
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // LATENCIES_H
//------------------------------------------------------------------------------

