//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin which encapsulate all requests to shared object library.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <dlfcn.h>

#include "../auxiliary/logger.h"
#include "plugin.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

Plugin::Plugin(const std::string& path, const std::string& args)
{
    handle = dlopen(path.c_str(), RTLD_LAZY);
    if(!handle)
        throw PluginException(path + " cannot be opened");

    // Converting from data type pointer (void*) to function pointer (create_t) [and vice versa] is forbidden by C89 standard
    create_t create = (create_t)dlsym(handle, "create");
    destroy = (destroy_t)dlsym(handle, "destroy");
    if(!create || !destroy)
        throw PluginException(path + " is not a loadable/unloadable plugin");
    analyzer = (BaseAnalyzer2*)(*create)(args.c_str());
}

Plugin::~Plugin()
{
    // Converting from data type pointer (void*) to function pointer (destroy_t) [and vice versa] is forbidden by C89 standard
    (*destroy)(analyzer);
    dlclose(handle);
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
