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
#define NST_PUBLIC __attribute__ ((visibility("default")))
#ifndef NFS4_UTILS_H
#define NFS4_UTILS_H
//------------------------------------------------------------------------------
#include <ostream>

#include "api/nfs_types.h"
#include "api/nfs4_types_rpcgen.h"
#include "protocols/nfs/nfs_utils.h"
#include "protocols/rpc/rpc_header.h"
//------------------------------------------------------------------------------
using namespace NST::API::NFS4;
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
                    100003,                 // SunRPC/NFS program
                    4,                      // v4
                    ProcEnumNFS4::NFS_NULL, // NFSPROC4RPCGEN_NULL     (0)
                    ProcEnumNFS4::COMPOUND  // NFSPROC4RPCGEN_COMPOUND (1)
                >;

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(NULL4args&)->decltype(&xdr_NULL4args)
{
    return &xdr_NULL4args;
}

inline auto proc_t_of(NULL4res&)->decltype(&xdr_NULL4res)
{
    return &xdr_NULL4res;
}

// Procedure 1: COMPOUND
inline auto proc_t_of(COMPOUND4args&)->decltype(&xdr_COMPOUND4args)
{
    return &xdr_COMPOUND4args;
}

inline auto proc_t_of(COMPOUND4res&)->decltype(&xdr_COMPOUND4res)
{
    return &xdr_COMPOUND4res;
}

extern"C"
NST_PUBLIC
const char* print_nfs4_procedures(const ProcEnumNFS4::NFSProcedure proc);

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS4::NFSProcedure proc);
std::ostream& operator<<(std::ostream& out, const nfs_ftype4& obj);
std::ostream& operator<<(std::ostream& out, const nfsstat4& obj);
std::ostream& operator<<(std::ostream& out, const bitmap4& obj);
std::ostream& operator<<(std::ostream& out, const utf8string& obj);
std::ostream& operator<<(std::ostream& out, const pathname4& obj);
std::ostream& operator<<(std::ostream& out, const sec_oid4& obj);
std::ostream& operator<<(std::ostream& out, const nfstime4& obj);
std::ostream& operator<<(std::ostream& out, const time_how4& obj);
std::ostream& operator<<(std::ostream& out, const settime4& obj);
std::ostream& operator<<(std::ostream& out, const nfs_fh4& obj);
std::ostream& operator<<(std::ostream& out, const fsid4& obj);
std::ostream& operator<<(std::ostream& out, const fs_location4& obj);
std::ostream& operator<<(std::ostream& out, const fs_locations4& obj);
std::ostream& operator<<(std::ostream& out, const nfsace4& obj);
std::ostream& operator<<(std::ostream& out, const specdata4& obj);
std::ostream& operator<<(std::ostream& out, const fattr4_acl& obj);
std::ostream& operator<<(std::ostream& out, const attrlist4& obj);
std::ostream& operator<<(std::ostream& out, const fattr4& obj);
std::ostream& operator<<(std::ostream& out, const change_info4& obj);
std::ostream& operator<<(std::ostream& out, const clientaddr4& obj);
std::ostream& operator<<(std::ostream& out, const cb_client4& obj);
std::ostream& operator<<(std::ostream& out, const stateid4& obj);
std::ostream& operator<<(std::ostream& out, const nfs_client_id4& obj);
std::ostream& operator<<(std::ostream& out, const open_owner4& obj);
std::ostream& operator<<(std::ostream& out, const lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const nfs_lock_type4& obj);
std::ostream& operator<<(std::ostream& out, const createtype4& obj);
std::ostream& operator<<(std::ostream& out, const dir_delegation_status4& obj);
std::ostream& operator<<(std::ostream& out, const open_to_lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const exist_lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const locker4& obj);
std::ostream& operator<<(std::ostream& out, const createmode4& obj);
std::ostream& operator<<(std::ostream& out, const opentype4& obj);
std::ostream& operator<<(std::ostream& out, const limit_by4& obj);
std::ostream& operator<<(std::ostream& out, const open_delegation_type4& obj);
std::ostream& operator<<(std::ostream& out, const open_claim_type4& obj);
std::ostream& operator<<(std::ostream& out, const rpc_gss_svc_t& obj);
std::ostream& operator<<(std::ostream& out, const stable_how4& obj);
std::ostream& operator<<(std::ostream& out, const createhow4& obj);
std::ostream& operator<<(std::ostream& out, const openflag4& obj);
std::ostream& operator<<(std::ostream& out, const nfs_modified_limit4& obj);
std::ostream& operator<<(std::ostream& out, const nfs_space_limit4& obj);
std::ostream& operator<<(std::ostream& out, const open_claim_delegate_cur4& obj);
std::ostream& operator<<(std::ostream& out, const open_claim4& obj);
std::ostream& operator<<(std::ostream& out, const open_read_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const open_write_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const open_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const entry4& obj);
std::ostream& operator<<(std::ostream& out, const dirlist4& obj);
std::ostream& operator<<(std::ostream& out, const rpcsec_gss_info& obj);
std::ostream& operator<<(std::ostream& out, const secinfo4& obj);

} // namespace NFS4
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS4_UTILS_H
//------------------------------------------------------------------------------
