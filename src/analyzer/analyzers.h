//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Analyzers storage. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <list>

#include "../controller/running_status.h"
#include "base_analyzer.h"
#include "nfs_data.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer 
{

class Analyzers
{
    typedef std::list<BaseAnalyzer*> Storage;
public:
    Analyzers()
    {
    }
    ~Analyzers()
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            delete *i;
        }
    }

    void add(BaseAnalyzer* analyzer)
    {
        analyzers.push_back(analyzer);
    }

    void process(const NFSData& data)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->process(data);
        }
    }

    void result()
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->result();
        }
    }

private:
    Storage analyzers;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
