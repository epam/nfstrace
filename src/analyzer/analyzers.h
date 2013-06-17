//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside filter module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <list>

#include <base_analyzer.h>
#include "../controller/running_status.h"
//------------------------------------------------------------------------------
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer 
{

class Analyzers
{
    Analyzers()
    {
    }
    ~Analyzers() 
    {
        list<BaseAnalyzer*>::iterator i = analyzers.begin();
        list<BaseAnalyzer*>::iterator end = analyzer.end();
        for(; i != end; ++i)
        {
            delete *i;
        }
    }

    void add(BaseAnalyzer* analyzer)
    {
        analyzers.push_back(analyzer);
    }

    void process()
    {
        list<BaseAnalyzer*>::iterator i = analyzers.begin();
        list<BaseAnalyzer*>::iterator end = analyzer.end();
        for(; i != end; ++i)
        {
            (*i)->process();
        }
    }

    void result()
    {
        list<BaseAnalyzer*>::iterator i = analyzers.begin();
        list<BaseAnalyzer*>::iterator end = analyzer.end();
        for(; i != end; ++i)
        {
            (*i)->result();
        }
    }

private:
    list<BaseAnalyzer*> analyzers;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
