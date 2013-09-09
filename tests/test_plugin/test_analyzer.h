//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin-API describe interface expected by nfstrace.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef TEST_ANALYZER_H
#define TEST_ANALYZER_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
#include "plugin_api.h"

#include <iostream>
//------------------------------------------------------------------------------

class TestAnalyzer : public BaseAnalyzer
{
public:
    TestAnalyzer() : BaseAnalyzer()
    {
        std::cout << "TestAnalyzer::TestAnalyzer()" << std::endl;
    }

    virtual ~TestAnalyzer()
    {
        std::cout << "TestAnalyzer::~TestAnalyzer()" << std::endl;
    }

    virtual const char* name() const
    {
        return "TestAnalyzer";
    }

    virtual void analyse(int data)
    {
        std::cout << "TestAnalyzer::analyse(int)" << std::endl;
        std::cout << "data = " << data << std::endl;
    }

    virtual void stage()
    {
        std::cout << "TestAnalyzer::stage()" << std::endl;
    }

    virtual void terminate(int)
    {
        std::cout << "TestAnalyzer::terminate()" << std::endl;
    }
};
//------------------------------------------------------------------------------
#endif//TEST_ANALYZER_H
//------------------------------------------------------------------------------

