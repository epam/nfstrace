//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Operation breakdown - Latencies storage.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BREAKDOWN_H
#define BREAKDOWN_H
//------------------------------------------------------------------------------
#include <vector>

#include "api/plugin_api.h"
#include "latencies.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

class Breakdown
{
public:
    Breakdown()
    {
    }
    ~Breakdown()
    {
    }
    inline const Latencies& operator[](uint32_t index) const
    {
        return latencies[index];
    }
    inline Latencies& operator[](uint32_t index)
    {
        return latencies[index];
    }

private:
    Breakdown(const Breakdown& breakdown);  //Protection
    void operator=(const Breakdown&);       //Protection

    Latencies latencies[ProcEnum::count];
};

//------------------------------------------------------------------------------
#endif//BREAKDOWN_H
//------------------------------------------------------------------------------
