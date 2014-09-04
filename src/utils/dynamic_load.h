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
#ifndef DYNAMIC_LOAD_H
#define DYNAMIC_LOAD_H
//------------------------------------------------------------------------------
#include <stdexcept>

#include <dlfcn.h>
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

class DynamicLoad
{
public:
    class DLException : public std::runtime_error
    {
    public:
        explicit DLException(const std::string& msg) : std::runtime_error(msg) { }
    };

protected:
    DynamicLoad(const std::string& file)
    {
        handle = dlopen(file.c_str(), RTLD_LAZY);
        if(handle == NULL)
        {
            throw DLException(std::string("Loading dynamic module: ") + file + " failed with error:" + dlerror());
        }
    }
    ~DynamicLoad()
    {
        dlclose(handle);
    }

    template<typename SymbolPtr>
    inline void load_address_of(const char* name, SymbolPtr& address)
    {
        static_assert(sizeof(void*) == sizeof(SymbolPtr), "object pointer and function pointer sizes must be equal");

        // suppression warning: ISO C++ forbids casting between pointer-to-function and pointer-to-object
        using hook_dlsym_t = SymbolPtr (*)(void *, const char *);

        address = reinterpret_cast<hook_dlsym_t>(dlsym)(handle, name);
        if(address == NULL)
        {
            throw DLException(std::string("Loading symbol ") + name + " failed with error:" + dlerror());
        }
    }

private:
    void* handle;
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//DYNAMIC_LOAD_H
//------------------------------------------------------------------------------
