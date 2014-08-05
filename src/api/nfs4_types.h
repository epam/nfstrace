//------------------------------------------------------------------------------
// Author: Alexey Costroma
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
#ifndef NFS4_TYPES_H
#define NFS4_TYPES_H
//------------------------------------------------------------------------------
#include "xdr_types.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

struct ProcEnumNFS4
{
    enum NFSProcedure
    {
        NFS_NULL    = 0,
        COMPOUND    = 1
    };
    static const int32_t count = 2;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS4_TYPES_H
//------------------------------------------------------------------------------
