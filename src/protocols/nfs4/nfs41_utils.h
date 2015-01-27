//------------------------------------------------------------------------------
// Author: Alexey Costroma
// Description: Helpers for parsing NFS structures.
// Copyright (c) 2015 EPAM Systems
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
#ifndef NFS41_UTILS_H
#define NFS41_UTILS_H
//------------------------------------------------------------------------------
#include <ostream>

#include "api/nfs_types.h"
#include "api/nfs41_types_rpcgen.h"
#include "protocols/nfs/nfs_utils.h"
#include "protocols/rpc/rpc_header.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS41
{

namespace NFS41 = NST::API::NFS41;

using ProcEnumNFS41 = API::ProcEnumNFS41;

using Validator = rpc::RPCProgramValidator
                <
                    100003,                  // SunRPC/NFS program
                    4,                       // v4
                    ProcEnumNFS41::NFS_NULL, // NFSPROC41RPCGEN_NULL     (0)
                    ProcEnumNFS41::COMPOUND  // NFSPROC41RPCGEN_COMPOUND (1)
                >;

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(NFS41::NULL4args&)->decltype(&NFS41::xdr_NULL4args)
{
    return &NFS41::xdr_NULL4args;
}

inline auto proc_t_of(NFS41::NULL4res&)->decltype(&NFS41::xdr_NULL4res)
{
    return &NFS41::xdr_NULL4res;
}

// Procedure 1: COMPOUND
inline auto proc_t_of(NFS41::COMPOUND4args&)->decltype(&NFS41::xdr_COMPOUND4args)
{
    return &NFS41::xdr_COMPOUND4args;
}

inline auto proc_t_of(NFS41::COMPOUND4res&)->decltype(&NFS41::xdr_COMPOUND4res)
{
    return &NFS41::xdr_COMPOUND4res;
}

extern"C"
NST_PUBLIC
const char* print_nfs41_procedures(const ProcEnumNFS41::NFSProcedure proc);

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS41::NFSProcedure proc);
std::ostream& operator<<(std::ostream& out, const NFS41::nfs_ftype4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfsstat4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::bitmap4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfs_fh4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::sec_oid4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::utf8string& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::pathname4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfstime4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::time_how4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::settime4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fsid4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fs_location4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fs_locations4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfsace4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::change_policy4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfsacl41& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::mode_masked4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::specdata4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::netaddr4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfs_impl_id4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::stateid4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layouttype4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layout_content4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layouthint4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layoutiomode4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layout4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::device_addr4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layoutupdate4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layoutreturn_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layoutreturn_file4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layoutreturn4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fs4_status_type& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fs4_status& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::threshold_item4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::mdsthreshold4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::retention_get4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::retention_set4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fattr4_acl& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fattr4_fs_layout_types& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fattr4_layout_types& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fattr4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::change_info4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::cb_client4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfs_client_id4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::client_owner4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::server_owner4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::state_owner4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfs_lock_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::ssv_subkey4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::ssv_mic_plain_tkn4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::ssv_mic_tkn4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::ssv_seal_plain_tkn4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::ssv_seal_cipher_tkn4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fs_locations_server4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fs_locations_item4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::fs_locations_info4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::filelayout_hint_care4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfsv4_1_file_layouthint4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::multipath_list4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfsv4_1_file_layout_ds_addr4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfsv4_1_file_layout4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::createtype4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::open_to_lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::exist_lock_owner4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::locker4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::createmode4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::creatverfattr& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::createhow4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::opentype4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::openflag4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::limit_by4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfs_modified_limit4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::nfs_space_limit4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::open_delegation_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::open_claim_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::open_claim_delegate_cur4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::open_claim4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::open_read_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::open_write_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::why_no_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::open_none_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::open_delegation4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::entry4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::dirlist4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::rpc_gss_svc_t& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::rpcsec_gss_info& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::secinfo4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::stable_how4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::gsshandle4_t& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::gss_cb_handles4& obj);
std::ostream& operator<<(std::ostream& out, const authunix_parms& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::authsys_parms& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::callback_sec_parms4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::channel_dir_from_client4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::channel_dir_from_server4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::state_protect_ops4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::ssv_sp_parms4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::state_protect_how4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::state_protect4_a& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::ssv_prot_info4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::state_protect4_r& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::channel_attrs4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::gddrnf4_status& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::newtime4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::newoffset4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::newsize4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layoutreturn_stateid& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::secinfo_style4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::SEQUENCE4args& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::ssa_digest_input4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::ssr_digest_input4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::deleg_claim4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layoutrecall_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layoutrecall_file4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::layoutrecall4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_entry4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::prev_entry4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_remove4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_add4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_attr4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_rename4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_verifier4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notifylist4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::referring_call4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::referring_call_list4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_deviceid_type4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_deviceid_delete4& obj);
std::ostream& operator<<(std::ostream& out, const NFS41::notify_deviceid_change4& obj);

} // namespace NFS41
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS41_UTILS_H
//------------------------------------------------------------------------------
