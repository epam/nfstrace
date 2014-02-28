//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin which encapsulate all requests to shared object library.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <stdexcept>

#include "analysis/plugin.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

Plugin::Plugin(const std::string& path)
    : DynamicLoad{path.c_str()}
    , usage  {nullptr}
    , create {nullptr}
    , destroy{nullptr}
{
    load_address_of("usage" ,  usage  );
    load_address_of("create" , create );
    load_address_of("destroy", destroy);
}

const std::string Plugin::usage_of(const std::string& path)
{
    Plugin instance(path);
    return instance.usage();
}

PluginInstance::PluginInstance(const std::string& path, const std::string& args) : Plugin{path}
{
    analysis = create(args.c_str());
    if(!analysis)
    {
        throw std::runtime_error(path + ": create call returns NULL-pointer");
    }
}

PluginInstance::~PluginInstance()
{
    destroy(analysis);
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
