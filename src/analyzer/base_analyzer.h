//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base analyzer, which implement restoring rpc/nfs structures from plain rpc header.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BASE_ANALYZER_H
#define BASE_ANALYZER_H
//------------------------------------------------------------------------------
#include "nfs_data.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer 
{

class BaseAnalyzer
{
public:
    BaseAnalyzer()
    {
    }
    virtual ~BaseAnalyzer()
    {
    }

    virtual void process(NFSData* data) = 0;
    virtual void result() = 0;

    // TODO: Add 
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_ANALYZER_H
//------------------------------------------------------------------------------
