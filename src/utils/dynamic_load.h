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
        explicit DLException(const std::string& msg)
            : std::runtime_error{msg}
        {
        }
    };

protected:
    explicit DynamicLoad(const std::string& file);
    ~DynamicLoad();

    template <typename SymbolPtr>
    void load_address_of(const std::string& name, SymbolPtr& address)
    {
        static_assert(sizeof(void*) == sizeof(SymbolPtr), "object pointer and function pointer sizes must be equal");

        // suppression warning: ISO C++ forbids casting between pointer-to-function and pointer-to-object
        using hook_dlsym_t = SymbolPtr (DynamicLoad::*)(const std::string&);

        hook_dlsym_t get_symbol_func = reinterpret_cast<hook_dlsym_t>(&DynamicLoad::get_symbol);
        address                      = (*this.*get_symbol_func)(name);
    }

    /*!
     * Gets symbol by name from DLL
     * Throws exception if fails
     * \param name - name of symbol
     * \return pointer to valid symbol
     */
    void* get_symbol(const std::string& name);

private:
    void* handle;
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif // DYNAMIC_LOAD_H
//------------------------------------------------------------------------------
