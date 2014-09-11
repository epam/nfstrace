//------------------------------------------------------------------------------
// Author: Alexey Costroma 
// Description: Helpers for parsing NFS structures.
// Copyright (c) 2014 EPAM Systems
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
#include <iomanip>

#include "protocols/nfs/nfs_utils.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS
{

std::ostream& print_hex(std::ostream& out, const uint32_t* const val, const uint32_t len)
{
    if(len)
    {
        out << std::hex << std::setfill('0') << "0x";
        for(uint32_t i = 0; i < len; i++)
        {
            out << std::setw(2) << val[i];
        }
        return out << std::dec << std::setfill(' ');
    }
    else
    {
        return out << "void";
    }
}

std::ostream& print_hex(std::ostream& out, const char* const val, const uint32_t len)
{
    if(len)
    {
        out << std::hex << std::setfill('0') << "0x" ;
        for(uint32_t i = 0; i < len; i++)
        {
                out << std::setw(2) << ((static_cast<int32_t>(val[i])) & 0xFF);
        }
        return out << std::dec << std::setfill(' ');
    }
    else
    {
        return out << "void";
    }
}

std::ostream& print_access3(std::ostream& out, const rpcgen::uint32 val)
{
    if (val & rpcgen::ACCESS3_READ)    out << "READ ";
    if (val & rpcgen::ACCESS3_LOOKUP)  out << "LOOKUP ";
    if (val & rpcgen::ACCESS3_MODIFY)  out << "MODIFY ";
    if (val & rpcgen::ACCESS3_EXTEND)  out << "EXTEND ";
    if (val & rpcgen::ACCESS3_DELETE)  out << "DELETE ";
    if (val & rpcgen::ACCESS3_EXECUTE) out << "EXECUTE ";

    return out;
}

} // namespace NFS
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
