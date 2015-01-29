//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Wrapper for dlopen and related functions
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#include <dlfcn.h>

#include "utils/dynamic_load.h"
//------------------------------------------------------------------------------
using namespace NST::utils;
//------------------------------------------------------------------------------

DynamicLoad::DynamicLoad(const std::string &file)
{
    handle = dlopen(file.c_str(), RTLD_LAZY);
    if(handle == nullptr)
    {
        throw DLException{std::string{"Loading dynamic module: "} + file + " failed with error:" + dlerror()};
    }
}

DynamicLoad::~DynamicLoad()
{
    dlclose(handle);
}

void DynamicLoad::load_address_of(const std::string &name, plugin_get_entry_points_func &address)
{
    static_assert(sizeof(void*) == sizeof(plugin_get_entry_points_func), "object pointer and function pointer sizes must be equal");

    // suppression warning: ISO C++ forbids casting between pointer-to-function and pointer-to-object
    using hook_dlsym_t = plugin_get_entry_points_func (*)(void *, const char *);

    address = reinterpret_cast<hook_dlsym_t>(dlsym)(handle, name.c_str());
    if(address == nullptr)
    {
        throw DLException{std::string{"Loading symbol "} + name + " failed with error:" + dlerror()};
    }
}
//------------------------------------------------------------------------------
