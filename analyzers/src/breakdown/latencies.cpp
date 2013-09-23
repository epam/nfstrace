//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Count latencies for every type of the nfs-operation.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <cmath>

#include "latencies.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

void Latencies::add(const timeval& t)
{
    ++count;
    latencies.push_back(t);
    set_range(t);
}

long double Latencies::get_avg() const
{
    if(count == 0) return 0.0L;

    ConstIterator i = latencies.begin();
    ConstIterator end = latencies.end();

    timeval res;
    timerclear(&res);
    for(; i != end; ++i)
    {
        timeradd(&res, &(*i), &res);
    }
    return to_sec(res) / count;
}

long double Latencies::get_st_dev() const
{
    if(count == 0) return 0.0L;

    const long double avg = get_avg();
    long double st_dev = 0.0L;
    long double diff;

    ConstIterator i = latencies.begin();
    ConstIterator end = latencies.end();
    for(; i != end; ++i)
    {
        diff = to_sec(*i) - avg;
        st_dev += pow(diff, 2.0L);
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

long double Latencies::to_sec(const timeval& val)
{
    return (((long double)val.tv_sec) + ((long double)val.tv_usec) / 1000000.0L);
}

//------------------------------------------------------------------------------
