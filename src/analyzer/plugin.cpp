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
        throw int();

    // Converting from data type pointer (void*) to function pointer (create_t) [and vice versa] are forbidden by C89 standard
    create_t create = (create_t)dlsym(handle, "create");
    if(!create)
        throw int();
    context = (*create)(args.c_str());
}

Plugin::~Plugin()
{
    // Converting from data type pointer (void*) to function pointer (destroy_t) [and vice versa] are forbidden by C89 standard
    destroy_t destroy = (destroy_t)dlsym(handle, "destroy");
    if(!destroy)
        LOG("Possible memory leak. Plugin doesn't provide cleaning function");
    (*destroy)(context);
    dlclose(handle);
}

void* Plugin::provide_func(const std::string& function)
{
    void* func = dlsym(handle, function.c_str());
    if(!func)
        throw int();
    return func;
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
