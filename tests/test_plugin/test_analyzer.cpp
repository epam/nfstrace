//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin-API describe interface expected by nfstrace.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <string>

#include "../../src/api/plugin_api.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

class TestAnalyzer : public BaseAnalyzer
{
public:
    TestAnalyzer(const char* opts):options(opts)
    {
        std::cout << "TestAnalyzer::TestAnalyzer(" << options << ")" << std::endl;
    }

    ~TestAnalyzer()
    {
        std::cout << "TestAnalyzer::~TestAnalyzer()" << std::endl;
    }
    
    virtual const char* usage() { return "Relax!"; }
private:
    std::string options;
};

extern "C"
{

const char* usage()
{
    return "test Analyzer: any options";
}

BaseAnalyzer* create(const char* opts)
{
    return new TestAnalyzer(opts);
}

void destroy(BaseAnalyzer* handle)
{
    delete handle;
}

}
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
