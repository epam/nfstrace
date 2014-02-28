//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Wrapper for dlopen and related functions
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef DYNAMIC_LOAD_H
#define DYNAMIC_LOAD_H
//------------------------------------------------------------------------------
#include <cassert>
#include <stdexcept>

#include <dlfcn.h>
//------------------------------------------------------------------------------
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
    DynamicLoad(const char* file)
    {
        handle = dlopen(file, RTLD_LAZY);
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
        assert( sizeof(void*) == sizeof(SymbolPtr) );

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
