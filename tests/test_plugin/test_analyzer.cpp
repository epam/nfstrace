//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin-API describe interface expected by nfstrace.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "test_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
BaseAnalyzer2* create(const char* opts)
{
    return new TestAnalyzer(opts);
}

void destroy(BaseAnalyzer2* handle)
{
    delete handle;
}
//------------------------------------------------------------------------------
