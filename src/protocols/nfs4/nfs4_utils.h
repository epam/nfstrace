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

namespace NFS4 = NST::API::NFS4;

using ProcEnumNFS4 = API::ProcEnumNFS4;

using Validator = rpc::RPCProgramValidator
                <
                    100003,                 // SunRPC/NFS program
                    4,                      // v4
                    ProcEnumNFS4::NFS_NULL, // NFSPROC4RPCGEN_NULL     (0)
                    ProcEnumNFS4::COMPOUND  // NFSPROC4RPCGEN_COMPOUND (1)
                >;

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(NFS4::NULL4args&)->decltype(&NFS4::xdr_NULL4args)
{
    return &NFS4::xdr_NULL4args;
}

inline auto proc_t_of(NFS4::NULL4res&)->decltype(&NFS4::xdr_NULL4res)
{
    return &NFS4::xdr_NULL4res;
}

// Procedure 1: COMPOUND
inline auto proc_t_of(NFS4::COMPOUND4args&)->decltype(&NFS4::xdr_COMPOUND4args)
{
    return &NFS4::xdr_COMPOUND4args;
}

inline auto proc_t_of(NFS4::COMPOUND4res&)->decltype(&NFS4::xdr_COMPOUND4res)
{
    return &NFS4::xdr_COMPOUND4res;
}

extern"C"
NST_PUBLIC
const char* print_nfs4_procedures(const ProcEnumNFS4::NFSProcedure proc);

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS4::NFSProcedure proc);
std::ostream& operator<<(std::ostream& out, const NFS4::nfs_ftype4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::nfsstat4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::bitmap4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::utf8string& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::pathname4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::sec_oid4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::nfstime4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::time_how4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::settime4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::nfs_fh4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::fsid4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::fs_location4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::fs_locations4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::nfsace4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::specdata4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::fattr4_acl& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::attrlist4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::fattr4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::change_info4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::clientaddr4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::cb_client4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::stateid4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::nfs_client_id4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::open_owner4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::nfs_lock_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::createtype4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::dir_delegation_status4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::open_to_lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::exist_lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::locker4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::createmode4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::opentype4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::limit_by4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::open_delegation_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::open_claim_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::rpc_gss_svc_t& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::stable_how4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::createhow4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::openflag4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::nfs_modified_limit4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::nfs_space_limit4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::open_claim_delegate_cur4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::open_claim4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::open_read_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::open_write_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::open_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::entry4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::dirlist4& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::rpcsec_gss_info& obj);
std::ostream& operator<<(std::ostream& out, const NFS4::secinfo4& obj);

} // namespace NFS4
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS4_UTILS_H
//------------------------------------------------------------------------------
