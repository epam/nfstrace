//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Wrapper for dlopen and related functions
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef DYNAMIC_LOAD_H
#define DYNAMIC_LOAD_H
//------------------------------------------------------------------------------
#include <cassert>

#include <dlfcn.h>

#include "exception.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class DynamicLoad
{
public:
    class DLException : public Exception
    {
    public:
        explicit DLException(const std::string& msg) : Exception(msg) { }

        virtual const DLException* dynamic_clone() const { return new DLException(*this); }
        virtual void               dynamic_throw() const { throw *this; }
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
        // TODO: replace with static_assert(sizeof(void *) == sizeof(SymbolPtr), "object pointer and function pointer sizes must equal");
        assert( sizeof(void*) == sizeof(SymbolPtr) );

        // suppression warning: ISO C++ forbids casting between pointer-to-function and pointer-to-object
        typedef SymbolPtr (*hook_dlsym_t)(void *, const char *);

        address = ((hook_dlsym_t)(dlsym))(handle, name);
        if(address == NULL)
        {
            throw DLException(std::string("Loading symbol ") + name + " failed with error:" + dlerror());
        }
    }

private:
    void* handle;
};

} // auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//DYNAMIC_LOAD_H
//------------------------------------------------------------------------------
