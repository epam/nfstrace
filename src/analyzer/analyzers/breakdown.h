//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Operation breakdown - Latencies storage.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BREAKDOWN_H
#define BREAKDOWN_H
//------------------------------------------------------------------------------
#include <vector>

#include "../nfs3/nfs_procedures.h"
#include "latencies.h"
//------------------------------------------------------------------------------
using NST::analyzer::NFS3::Proc;
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
    inline const Latencies& operator[](uint32_t ind) const
    {
        return latencies[ind];
    }
    inline Latencies& operator[](uint32_t ind)
    {
        return latencies[ind];
    }

private:
    Breakdown(const Breakdown& breakdown);  //Protection
    void operator=(const Breakdown&);       //Protection

    Latencies latencies[Proc::num];
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BREAKDOWN_H
//------------------------------------------------------------------------------
