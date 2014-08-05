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
        NFS_NULL            = 0,
        COMPOUND            = 1,
        ACCESS              = 3,
        CLOSE               = 4,
        COMMIT              = 5,
        CREATE              = 6,
        DELEGPURGE          = 7,
        DELEGRETURN         = 8,
        GETATTR             = 9,
        GETFH               = 10,
        LINK                = 11,
        LOCK                = 12,
        LOCKT               = 13,
        LOCKU               = 14,
        LOOKUP              = 15,
        LOOKUPP             = 16,
        NVERIFY             = 17,
        OPEN                = 18,
        OPENATTR            = 19,
        OPEN_CONFIRM        = 20,
        OPEN_DOWNGRADE      = 21,
        PUTFH               = 22,
        PUTPUBFH            = 23,
        PUTROOTFH           = 24,
        READ                = 25,
        READDIR             = 26,
        READLINK            = 27,
        REMOVE              = 28,
        RENAME              = 29,
        RENEW               = 30,
        RESTOREFH           = 31,
        SAVEFH              = 32,
        SECINFO             = 33,
        SETATTR             = 34,
        SETCLIENTID         = 35,
        SETCLIENTID_CONFIRM = 36,
        VERIFY              = 37,
        WRITE               = 38,
        RELEASE_LOCKOWNER   = 39,
        ILLEGAL             = 10044
    };
    static const int32_t count = 40;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS4_TYPES_H
//------------------------------------------------------------------------------
