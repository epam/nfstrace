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
NST_PUBLIC
const char* print_nfs4_procedures(const ProcEnumNFS4::NFSProcedure proc);

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS4::NFSProcedure proc);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_ftype4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfsstat4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::bitmap4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::utf8string& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::pathname4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::sec_oid4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfstime4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::time_how4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::settime4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_fh4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::fsid4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::fs_location4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::fs_locations4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfsace4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::specdata4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::fattr4_acl& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::attrlist4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::fattr4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::change_info4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::clientaddr4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::cb_client4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::stateid4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_client_id4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::open_owner4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_lock_type4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::createtype4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::dir_delegation_status4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::open_to_lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::exist_lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::locker4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::createmode4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::opentype4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::limit_by4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::open_delegation_type4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::open_claim_type4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::rpc_gss_svc_t& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::stable_how4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::createhow4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::openflag4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_modified_limit4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_space_limit4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::open_claim_delegate_cur4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::open_claim4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::open_read_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::open_write_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::open_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::entry4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::dirlist4& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::rpcsec_gss_info& obj);
std::ostream& operator<<(std::ostream& out, const rpcgen::secinfo4& obj);

} // namespace NFS4
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS4_UTILS_H
//------------------------------------------------------------------------------
