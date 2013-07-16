//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Count latencies for every type of the nfs-operation.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <cmath>

#include "latencies.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

void Latencies::add(const timeval& t)
{
    ++count;
    latencies.push_back(t);
    set_range(t);
}

double Latencies::get_avg() const
{
    double avg = 0.0;
    if(count != 0)
    {
        ConstIterator i = latencies.begin();
        ConstIterator end = latencies.end();

        timeval res;
        timerclear(&res);
        for(; i != end; ++i)
        {
            timeradd(&res, &(*i), &res);
        }
        avg = to_sec(res) / count;
    }
    return avg;
}

double Latencies::get_st_dev() const
{
    if(!count) return 0.0;

    double avg = get_avg();
    double st_dev = 0.0;
    double diff;

    ConstIterator i = latencies.begin();
    ConstIterator end = latencies.end();
    for(; i != end; ++i)
    {
        diff = to_sec(*i) - avg;
        st_dev += pow(diff, 2);
    }
    st_dev /= count;
    return sqrt(st_dev);
}

void Latencies::set_range(const timeval& t)
{
    if(timercmp(&t, &min, <))
        min = t;
    if(min.tv_sec == 0 && min.tv_usec == 0)
        min = t;
    if(timercmp(&t, &max, >))
        max = t;
}

double Latencies::to_sec(const timeval& val)
{
    return (double(val.tv_sec) + double(val.tv_usec) / 1000000.0);
}

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------

