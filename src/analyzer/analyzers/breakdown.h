//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Operation breakdown - Latencies storage.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BREAKDOWN_H
#define BREAKDOWN_H
//------------------------------------------------------------------------------
#include <vector>

#include "../nfs3/nfs_structs.h"
#include "latencies.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

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

    Latencies latencies[NFS3::Proc::num];
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BREAKDOWN_H
//------------------------------------------------------------------------------
