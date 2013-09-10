//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin-API describe interface expected by nfstrace.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef TEST_ANALYZER_H
#define TEST_ANALYZER_H
//------------------------------------------------------------------------------
#include <iostream>
//------------------------------------------------------------------------------
extern "C"
{
#include "../../src/api/plugin_api.h"

//------------------------------------------------------------------------------

class TestAnalyzer : public BaseAnalyzer2
{
public:
    TestAnalyzer(const char* opts)
    {
        std::cout << "TestAnalyzer::TestAnalyzer(const char*)" << std::endl;
    }

    ~TestAnalyzer()
    {
        std::cout << "TestAnalyzer::~TestAnalyzer()" << std::endl;
    }
    
    virtual const char* usage() { return "Relax!"; }
};
}
//------------------------------------------------------------------------------
#endif//TEST_ANALYZER_H
//------------------------------------------------------------------------------

