//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Operation breakdown - Latencies storage.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BREAKDOWN_H
#define BREAKDOWN_H
//------------------------------------------------------------------------------
#include <vector>

#include "../../filter/nfs/nfs_procedures.h"
#include "latencies.h"
//------------------------------------------------------------------------------
using NST::filter::NFS3::Proc;
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
        for(int i = 0; i < Proc::num; ++i)
        {
            latencies.push_back(new Latencies());
        }
    }
    ~Breakdown()
    {
        for(int i = 0; i < Proc::num; ++i)
        {
            delete latencies[i];
        }
    }
    inline Latencies& operator[](uint32_t ind)
    {
        return *latencies[ind];
    }

private:
    Breakdown(const Breakdown& breakdown);  //Protection
    void operator=(const Breakdown&);       //Protection

    std::vector<Latencies*> latencies;
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BREAKDOWN_H
//------------------------------------------------------------------------------
