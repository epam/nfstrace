//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin which encapsulate all requests to shared object library.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "plugin.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

Plugin::Plugin(const std::string& path, const std::string& args) : DynamicLoad(path.c_str())
{
    create_t create = NULL;
    load_address_of("create" , create );
    load_address_of("destroy", destroy);

    analyzer = (BaseAnalyzer2*)(*create)(args.c_str());
}

Plugin::~Plugin()
{
    (*destroy)(analyzer);
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
