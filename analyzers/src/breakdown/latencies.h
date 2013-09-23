//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Count latencies for every type of the nfs-operation.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef LATENCIES_H
#define LATENCIES_H
//------------------------------------------------------------------------------
#include <list>

#include <stdint.h>
#include <sys/time.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

class Latencies
{
    typedef std::list<timeval>::const_iterator ConstIterator;
public:
    Latencies() : count(0)
    {
        timerclear(&min);
        timerclear(&max);
    }
    void add(const timeval& t);
    inline uint64_t get_count() const { return count; }
    long double get_avg() const;
    long double get_st_dev() const;
    inline const timeval& get_min() const
    {
        return min;
    }
    inline const timeval& get_max() const
    {
        return max;
    }
    static long double to_sec(const timeval& val);
private:
    Latencies(const Latencies&);       // Protection
    void operator=(const Latencies&);  // Protection

    void set_range(const timeval& t);

    uint64_t count;
    std::list<timeval> latencies;
    timeval min;
    timeval max;
};

//------------------------------------------------------------------------------
#endif//LATENCIES_H
//------------------------------------------------------------------------------
