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

#include "api/plugin_api.h"
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
        explicit DLException(const std::string& msg) : std::runtime_error{msg} { }
    };

protected:
    explicit DynamicLoad(const std::string& file);
    ~DynamicLoad();

    void load_address_of(const std::string& name, plugin_get_entry_points_func& address);

private:
    void* handle;
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//DYNAMIC_LOAD_H
//------------------------------------------------------------------------------
