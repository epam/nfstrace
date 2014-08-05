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
#ifndef NFS4_UTILS_H
#define NFS4_UTILS_H
//------------------------------------------------------------------------------
#include <iostream>

#include "api/nfs4_types.h"
#include "api/nfs4_types_rpcgen.h"

#include "protocols/rpc/rpc_header.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS4
{
using ProcEnumNFS4 = API::ProcEnumNFS4;

using Validator = rpc::RPCProgramValidator
                <
                    100003,                   // SunRPC/NFS program
                    4,                        // v4
                    ProcEnumNFS4::NFS_NULL,   // NFSPROC4RPCGEN_NULL     (0)
                    ProcEnumNFS4::COMPOUND    // NFSPROC4RPCGEN_COMPOUND (1)
                >;

static const char* const NFS4ProcedureTitles[ProcEnumNFS4::count] =
{
"NULL",           "COMPOUND", "ACCESS",            "CLOSE",
"COMMIT",         "CREATE",   "DELEGPURGE",        "DELEGRETURN",
"GETATTR",        "GETFH",    "LINK",              "LOCK",
"LOCKT",          "LOCKU",    "LOOKUP",            "LOOKUPP",
"NVERIFY",        "OPEN",     "OPENATTR",          "OPEN_CONFIRM",
"OPEN_DOWNGRADE", "PUTFH",    "PUTPUBFH",          "PUTROOTFH",
"READ",           "READDIR",  "READLINK",          "REMOVE",
"RENAME",         "RENEW",    "RESTOREFH",         "SAVEFH",
"SECINFO",        "SETATTR",  "SETCLIENTID",       "SETCLIENTID_CONFIRM",
"VERIFY",         "WRITE",    "RELEASE_LOCKOWNER", "ILLEGAL" 
};

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(rpcgen::NULL4args&)->decltype(&rpcgen::xdr_NULL4args)
{
    return &rpcgen::xdr_NULL4args;
}

inline auto proc_t_of(rpcgen::NULL4res&)->decltype(&rpcgen::xdr_NULL4res)
{
    return &rpcgen::xdr_NULL4res;
}

// Procedure 1: COMPOUND
inline auto proc_t_of(rpcgen::COMPOUND4args&)->decltype(&rpcgen::xdr_COMPOUND4args)
{
    return &rpcgen::xdr_COMPOUND4args;
}

inline auto proc_t_of(rpcgen::COMPOUND4res&)->decltype(&rpcgen::xdr_COMPOUND4res)
{
    return &rpcgen::xdr_COMPOUND4res;
}

extern"C"
void print_nfs4_procedures(std::ostream& out, const ProcEnumNFS4::NFSProcedure proc);

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS4::NFSProcedure proc);

} // namespace NFS4
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS4_UTILS_H
//------------------------------------------------------------------------------
