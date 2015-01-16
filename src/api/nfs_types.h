//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: All RFC1813 declared structures.
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
#ifndef NFS_TYPES_H
#define NFS_TYPES_H
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

const uint32_t NFS_V40 {0};
const uint32_t NFS_V41 {1};

struct ProcEnumNFS3
{
    enum NFSProcedure
    {
        NFS_NULL    = 0,
        GETATTR     = 1,
        SETATTR     = 2,
        LOOKUP      = 3,
        ACCESS      = 4,
        READLINK    = 5,
        READ        = 6,
        WRITE       = 7,
        CREATE      = 8,
        MKDIR       = 9,
        SYMLINK     = 10,
        MKNOD       = 11,
        REMOVE      = 12,
        RMDIR       = 13,
        RENAME      = 14,
        LINK        = 15,
        READDIR     = 16,
        READDIRPLUS = 17,
        FSSTAT      = 18,
        FSINFO      = 19,
        PATHCONF    = 20,
        COMMIT      = 21
    };
    static const int32_t count {22};
};

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
        GET_DIR_DELEGATION  = 40,
        ILLEGAL             = 10044
        // Pleause, keep in mind that in all cases we suppose that NFSv4
        // operation ILLEGAL(10044) has the second position in ProcEnumNFS4
    };
    static const int32_t count      {41};
    static const int32_t count_proc {2};
};

struct ProcEnumNFS41
{
    enum NFSProcedure
    {
        NFS_NULL             = 0,
        COMPOUND             = 1,
        ACCESS               = 3,
        CLOSE                = 4,
        COMMIT               = 5,
        CREATE               = 6,
        DELEGPURGE           = 7,
        DELEGRETURN          = 8,
        GETATTR              = 9,
        GETFH                = 10,
        LINK                 = 11,
        LOCK                 = 12,
        LOCKT                = 13,
        LOCKU                = 14,
        LOOKUP               = 15,
        LOOKUPP              = 16,
        NVERIFY              = 17,
        OPEN                 = 18,
        OPENATTR             = 19,
        OPEN_CONFIRM         = 20,
        OPEN_DOWNGRADE       = 21,
        PUTFH                = 22,
        PUTPUBFH             = 23,
        PUTROOTFH            = 24,
        READ                 = 25,
        READDIR              = 26,
        READLINK             = 27,
        REMOVE               = 28,
        RENAME               = 29,
        RENEW                = 30,
        RESTOREFH            = 31,
        SAVEFH               = 32,
        SECINFO              = 33,
        SETATTR              = 34,
        SETCLIENTID          = 35,
        SETCLIENTID_CONFIRM  = 36,
        VERIFY               = 37,
        WRITE                = 38,
        RELEASE_LOCKOWNER    = 39,
        BACKCHANNEL_CTL      = 40,
        BIND_CONN_TO_SESSION = 41,
        EXCHANGE_ID          = 42,
        CREATE_SESSION       = 43,
        DESTROY_SESSION      = 44,
        FREE_STATEID         = 45,
        GET_DIR_DELEGATION   = 46,
        GETDEVICEINFO        = 47,
        GETDEVICELIST        = 48,
        LAYOUTCOMMIT         = 49,
        LAYOUTGET            = 50,
        LAYOUTRETURN         = 51,
        SECINFO_NO_NAME      = 52,
        SEQUENCE             = 53,
        SET_SSV              = 54,
        TEST_STATEID         = 55,
        WANT_DELEGATION      = 56,
        DESTROY_CLIENTID     = 57,
        RECLAIM_COMPLETE     = 58,
        ILLEGAL              = 10044
        // Pleause, keep in mind that in all cases we suppose that NFSv41
        // operation ILLEGAL(10044) has the second position in ProcEnumNFS41
    };
    static const int32_t count      {59};
    static const int32_t count_proc {2};
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_TYPES_H
//------------------------------------------------------------------------------
