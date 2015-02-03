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
#include <string>

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

void* DynamicLoad::get_symbol(const std::string &name)
{
    void* address = (dlsym)(handle, name.c_str());
    if(address == nullptr)
    {
        throw DLException{std::string{"Loading symbol "} + name + " failed with error:" + dlerror()};
    }

    return address;
}

//------------------------------------------------------------------------------
