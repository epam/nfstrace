//------------------------------------------------------------------------------
// Author: Pavel Karneliuk (Dzianis Huznou)
// Description: Wrapper for pcap handle.
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
#ifndef HANDLE_H
#define HANDLE_H
//------------------------------------------------------------------------------
#include <pcap/pcap.h>
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

class Handle
{
public:
    inline Handle(pcap_t* p = nullptr) : handle{p}{}
    inline Handle(const Handle&)            = delete;
    inline Handle& operator=(const Handle&) = delete;
    inline ~Handle()
    {
        if(handle)
        {
            pcap_close(handle);
        }
    }

    inline void operator=(pcap_t* p)       { handle = p; }
    inline      operator bool     () const { return handle; }
    inline      operator pcap_t*  () const { return handle; }

private:
    pcap_t* handle;
};

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//HANDLE_H
//------------------------------------------------------------------------------
