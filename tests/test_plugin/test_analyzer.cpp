//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin-API describe interface expected by nfstrace.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "test_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
BaseAnalyzer* create(const char*)
{
    return new TestAnalyzer;
}

void destroy(BaseAnalyzer* handle)
{
    delete handle;
}
//------------------------------------------------------------------------------
