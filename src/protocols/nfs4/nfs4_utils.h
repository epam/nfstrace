//------------------------------------------------------------------------------
// Author: Alexey Costroma
// Description: Helpers for parsing NFS structures.
// Copyright (c) 2014-2015 EPAM Systems
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
#include <ostream>

#include "api/nfs4_types_rpcgen.h"
#include "api/nfs_types.h"
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

using Validator = rpc::RPCProgramValidator<
    100003,                 // SunRPC/NFS program
    4,                      // v4
    ProcEnumNFS4::NFS_NULL, // NFSPROC4RPCGEN_NULL     (0)
    ProcEnumNFS4::COMPOUND  // NFSPROC4RPCGEN_COMPOUND (1)
    >;

// clang-format off
bool_t xdr_nfs_ftype4 (XDR *, NFS4::nfs_ftype4*);
bool_t xdr_nfsstat4 (XDR *, NFS4::nfsstat4*);
bool_t xdr_bitmap4 (XDR *, NFS4::bitmap4*);
bool_t xdr_offset4 (XDR *, NFS4::offset4*);
bool_t xdr_count4 (XDR *, NFS4::count4*);
bool_t xdr_length4 (XDR *, NFS4::length4*);
bool_t xdr_clientid4 (XDR *, NFS4::clientid4*);
bool_t xdr_seqid4 (XDR *, NFS4::seqid4*);
bool_t xdr_utf8string (XDR *, NFS4::utf8string*);
bool_t xdr_utf8str_cis (XDR *, NFS4::utf8str_cis*);
bool_t xdr_utf8str_cs (XDR *, NFS4::utf8str_cs*);
bool_t xdr_utf8str_mixed (XDR *, NFS4::utf8str_mixed*);
bool_t xdr_component4 (XDR *, NFS4::component4*);
bool_t xdr_pathname4 (XDR *, NFS4::pathname4*);
bool_t xdr_nfs_lockid4 (XDR *, NFS4::nfs_lockid4*);
bool_t xdr_nfs_cookie4 (XDR *, NFS4::nfs_cookie4*);
bool_t xdr_linktext4 (XDR *, NFS4::linktext4*);
bool_t xdr_sec_oid4 (XDR *, NFS4::sec_oid4*);
bool_t xdr_qop4 (XDR *, NFS4::qop4*);
bool_t xdr_mode4 (XDR *, NFS4::mode4*);
bool_t xdr_changeid4 (XDR *, NFS4::changeid4*);
bool_t xdr_verifier4 (XDR *, NFS4::verifier4);
bool_t xdr_nfstime4 (XDR *, NFS4::nfstime4*);
bool_t xdr_time_how4 (XDR *, NFS4::time_how4*);
bool_t xdr_settime4 (XDR *, NFS4::settime4*);
bool_t xdr_nfs_fh4 (XDR *, NFS4::nfs_fh4*);
bool_t xdr_fsid4 (XDR *, NFS4::fsid4*);
bool_t xdr_fs_location4 (XDR *, NFS4::fs_location4*);
bool_t xdr_fs_locations4 (XDR *, NFS4::fs_locations4*);
bool_t xdr_acetype4 (XDR *, NFS4::acetype4*);
bool_t xdr_aceflag4 (XDR *, NFS4::aceflag4*);
bool_t xdr_acemask4 (XDR *, NFS4::acemask4*);
bool_t xdr_nfsace4 (XDR *, NFS4::nfsace4*);
bool_t xdr_specdata4 (XDR *, NFS4::specdata4*);
bool_t xdr_fattr4_supported_attrs (XDR *, NFS4::fattr4_supported_attrs*);
bool_t xdr_fattr4_type (XDR *, NFS4::fattr4_type*);
bool_t xdr_fattr4_fh_expire_type (XDR *, NFS4::fattr4_fh_expire_type*);
bool_t xdr_fattr4_change (XDR *, NFS4::fattr4_change*);
bool_t xdr_fattr4_size (XDR *, NFS4::fattr4_size*);
bool_t xdr_fattr4_link_support (XDR *, NFS4::fattr4_link_support*);
bool_t xdr_fattr4_symlink_support (XDR *, NFS4::fattr4_symlink_support*);
bool_t xdr_fattr4_named_attr (XDR *, NFS4::fattr4_named_attr*);
bool_t xdr_fattr4_fsid (XDR *, NFS4::fattr4_fsid*);
bool_t xdr_fattr4_unique_handles (XDR *, NFS4::fattr4_unique_handles*);
bool_t xdr_fattr4_lease_time (XDR *, NFS4::fattr4_lease_time*);
bool_t xdr_fattr4_rdattr_error (XDR *, NFS4::fattr4_rdattr_error*);
bool_t xdr_fattr4_acl (XDR *, NFS4::fattr4_acl*);
bool_t xdr_fattr4_aclsupport (XDR *, NFS4::fattr4_aclsupport*);
bool_t xdr_fattr4_archive (XDR *, NFS4::fattr4_archive*);
bool_t xdr_fattr4_cansettime (XDR *, NFS4::fattr4_cansettime*);
bool_t xdr_fattr4_case_insensitive (XDR *, NFS4::fattr4_case_insensitive*);
bool_t xdr_fattr4_case_preserving (XDR *, NFS4::fattr4_case_preserving*);
bool_t xdr_fattr4_chown_restricted (XDR *, NFS4::fattr4_chown_restricted*);
bool_t xdr_fattr4_fileid (XDR *, NFS4::fattr4_fileid*);
bool_t xdr_fattr4_files_avail (XDR *, NFS4::fattr4_files_avail*);
bool_t xdr_fattr4_filehandle (XDR *, NFS4::fattr4_filehandle*);
bool_t xdr_fattr4_files_free (XDR *, NFS4::fattr4_files_free*);
bool_t xdr_fattr4_files_total (XDR *, NFS4::fattr4_files_total*);
bool_t xdr_fattr4_fs_locations (XDR *, NFS4::fattr4_fs_locations*);
bool_t xdr_fattr4_hidden (XDR *, NFS4::fattr4_hidden*);
bool_t xdr_fattr4_homogeneous (XDR *, NFS4::fattr4_homogeneous*);
bool_t xdr_fattr4_maxfilesize (XDR *, NFS4::fattr4_maxfilesize*);
bool_t xdr_fattr4_maxlink (XDR *, NFS4::fattr4_maxlink*);
bool_t xdr_fattr4_maxname (XDR *, NFS4::fattr4_maxname*);
bool_t xdr_fattr4_maxread (XDR *, NFS4::fattr4_maxread*);
bool_t xdr_fattr4_maxwrite (XDR *, NFS4::fattr4_maxwrite*);
bool_t xdr_fattr4_mimetype (XDR *, NFS4::fattr4_mimetype*);
bool_t xdr_fattr4_mode (XDR *, NFS4::fattr4_mode*);
bool_t xdr_fattr4_mounted_on_fileid (XDR *, NFS4::fattr4_mounted_on_fileid*);
bool_t xdr_fattr4_no_trunc (XDR *, NFS4::fattr4_no_trunc*);
bool_t xdr_fattr4_numlinks (XDR *, NFS4::fattr4_numlinks*);
bool_t xdr_fattr4_owner (XDR *, NFS4::fattr4_owner*);
bool_t xdr_fattr4_owner_group (XDR *, NFS4::fattr4_owner_group*);
bool_t xdr_fattr4_quota_avail_hard (XDR *, NFS4::fattr4_quota_avail_hard*);
bool_t xdr_fattr4_quota_avail_soft (XDR *, NFS4::fattr4_quota_avail_soft*);
bool_t xdr_fattr4_quota_used (XDR *, NFS4::fattr4_quota_used*);
bool_t xdr_fattr4_rawdev (XDR *, NFS4::fattr4_rawdev*);
bool_t xdr_fattr4_space_avail (XDR *, NFS4::fattr4_space_avail*);
bool_t xdr_fattr4_space_free (XDR *, NFS4::fattr4_space_free*);
bool_t xdr_fattr4_space_total (XDR *, NFS4::fattr4_space_total*);
bool_t xdr_fattr4_space_used (XDR *, NFS4::fattr4_space_used*);
bool_t xdr_fattr4_system (XDR *, NFS4::fattr4_system*);
bool_t xdr_fattr4_time_access (XDR *, NFS4::fattr4_time_access*);
bool_t xdr_fattr4_time_access_set (XDR *, NFS4::fattr4_time_access_set*);
bool_t xdr_fattr4_time_backup (XDR *, NFS4::fattr4_time_backup*);
bool_t xdr_fattr4_time_create (XDR *, NFS4::fattr4_time_create*);
bool_t xdr_fattr4_time_delta (XDR *, NFS4::fattr4_time_delta*);
bool_t xdr_fattr4_time_metadata (XDR *, NFS4::fattr4_time_metadata*);
bool_t xdr_fattr4_time_modify (XDR *, NFS4::fattr4_time_modify*);
bool_t xdr_fattr4_time_modify_set (XDR *, NFS4::fattr4_time_modify_set*);
bool_t xdr_attrlist4 (XDR *, NFS4::attrlist4*);
bool_t xdr_fattr4 (XDR *, NFS4::fattr4*);
bool_t xdr_change_info4 (XDR *, NFS4::change_info4*);
bool_t xdr_clientaddr4 (XDR *, NFS4::clientaddr4*);
bool_t xdr_cb_client4 (XDR *, NFS4::cb_client4*);
bool_t xdr_stateid4 (XDR *, NFS4::stateid4*);
bool_t xdr_nfs_client_id4 (XDR *, NFS4::nfs_client_id4*);
bool_t xdr_open_owner4 (XDR *, NFS4::open_owner4*);
bool_t xdr_lock_owner4 (XDR *, NFS4::lock_owner4*);
bool_t xdr_nfs_lock_type4 (XDR *, NFS4::nfs_lock_type4*);
bool_t xdr_NULL4args (XDR *, NFS4::NULL4args*); // for compatibility
bool_t xdr_NULL4res (XDR *, NFS4::NULL4res*);   // for compatibility
bool_t xdr_ACCESS4args (XDR *, NFS4::ACCESS4args*);
bool_t xdr_ACCESS4resok (XDR *, NFS4::ACCESS4resok*);
bool_t xdr_ACCESS4res (XDR *, NFS4::ACCESS4res*);
bool_t xdr_CLOSE4args (XDR *, NFS4::CLOSE4args*);
bool_t xdr_CLOSE4res (XDR *, NFS4::CLOSE4res*);
bool_t xdr_COMMIT4args (XDR *, NFS4::COMMIT4args*);
bool_t xdr_COMMIT4resok (XDR *, NFS4::COMMIT4resok*);
bool_t xdr_COMMIT4res (XDR *, NFS4::COMMIT4res*);
bool_t xdr_createtype4 (XDR *, NFS4::createtype4*);
bool_t xdr_CREATE4args (XDR *, NFS4::CREATE4args*);
bool_t xdr_CREATE4resok (XDR *, NFS4::CREATE4resok*);
bool_t xdr_CREATE4res (XDR *, NFS4::CREATE4res*);
bool_t xdr_DELEGPURGE4args (XDR *, NFS4::DELEGPURGE4args*);
bool_t xdr_DELEGPURGE4res (XDR *, NFS4::DELEGPURGE4res*);
bool_t xdr_DELEGRETURN4args (XDR *, NFS4::DELEGRETURN4args*);
bool_t xdr_DELEGRETURN4res (XDR *, NFS4::DELEGRETURN4res*);
bool_t xdr_GETATTR4args (XDR *, NFS4::GETATTR4args*);
bool_t xdr_GETATTR4resok (XDR *, NFS4::GETATTR4resok*);
bool_t xdr_GETATTR4res (XDR *, NFS4::GETATTR4res*);
bool_t xdr_notification_types4 (XDR *, NFS4::notification_types4*);
bool_t xdr_notification_delay4 (XDR *, NFS4::notification_delay4*);
bool_t xdr_dir_delegation_status4 (XDR *, NFS4::dir_delegation_status4*);
bool_t xdr_GET_DIR_DELEGATION4args (XDR *, NFS4::GET_DIR_DELEGATION4args*);
bool_t xdr_GET_DIR_DELEGATION4resok (XDR *, NFS4::GET_DIR_DELEGATION4resok*);
bool_t xdr_GET_DIR_DELEGATION4res (XDR *, NFS4::GET_DIR_DELEGATION4res*);
bool_t xdr_GETFH4resok (XDR *, NFS4::GETFH4resok*);
bool_t xdr_GETFH4res (XDR *, NFS4::GETFH4res*);
bool_t xdr_LINK4args (XDR *, NFS4::LINK4args*);
bool_t xdr_LINK4resok (XDR *, NFS4::LINK4resok*);
bool_t xdr_LINK4res (XDR *, NFS4::LINK4res*);
bool_t xdr_open_to_lock_owner4 (XDR *, NFS4::open_to_lock_owner4*);
bool_t xdr_exist_lock_owner4 (XDR *, NFS4::exist_lock_owner4*);
bool_t xdr_locker4 (XDR *, NFS4::locker4*);
bool_t xdr_LOCK4args (XDR *, NFS4::LOCK4args*);
bool_t xdr_LOCK4denied (XDR *, NFS4::LOCK4denied*);
bool_t xdr_LOCK4resok (XDR *, NFS4::LOCK4resok*);
bool_t xdr_LOCK4res (XDR *, NFS4::LOCK4res*);
bool_t xdr_LOCKT4args (XDR *, NFS4::LOCKT4args*);
bool_t xdr_LOCKT4res (XDR *, NFS4::LOCKT4res*);
bool_t xdr_LOCKU4args (XDR *, NFS4::LOCKU4args*);
bool_t xdr_LOCKU4res (XDR *, NFS4::LOCKU4res*);
bool_t xdr_LOOKUP4args (XDR *, NFS4::LOOKUP4args*);
bool_t xdr_LOOKUP4res (XDR *, NFS4::LOOKUP4res*);
bool_t xdr_LOOKUPP4res (XDR *, NFS4::LOOKUPP4res*);
bool_t xdr_NVERIFY4args (XDR *, NFS4::NVERIFY4args*);
bool_t xdr_NVERIFY4res (XDR *, NFS4::NVERIFY4res*);
bool_t xdr_createmode4 (XDR *, NFS4::createmode4*);
bool_t xdr_createhow4 (XDR *, NFS4::createhow4*);
bool_t xdr_opentype4 (XDR *, NFS4::opentype4*);
bool_t xdr_openflag4 (XDR *, NFS4::openflag4*);
bool_t xdr_limit_by4 (XDR *, NFS4::limit_by4*);
bool_t xdr_nfs_modified_limit4 (XDR *, NFS4::nfs_modified_limit4*);
bool_t xdr_nfs_space_limit4 (XDR *, NFS4::nfs_space_limit4*);
bool_t xdr_open_delegation_type4 (XDR *, NFS4::open_delegation_type4*);
bool_t xdr_open_claim_type4 (XDR *, NFS4::open_claim_type4*);
bool_t xdr_open_claim_delegate_cur4 (XDR *, NFS4::open_claim_delegate_cur4*);
bool_t xdr_open_claim4 (XDR *, NFS4::open_claim4*);
bool_t xdr_OPEN4args (XDR *, NFS4::OPEN4args*);
bool_t xdr_open_read_delegation4 (XDR *, NFS4::open_read_delegation4*);
bool_t xdr_open_write_delegation4 (XDR *, NFS4::open_write_delegation4*);
bool_t xdr_open_delegation4 (XDR *, NFS4::open_delegation4*);
bool_t xdr_OPEN4resok (XDR *, NFS4::OPEN4resok*);
bool_t xdr_OPEN4res (XDR *, NFS4::OPEN4res*);
bool_t xdr_OPENATTR4args (XDR *, NFS4::OPENATTR4args*);
bool_t xdr_OPENATTR4res (XDR *, NFS4::OPENATTR4res*);
bool_t xdr_OPEN_CONFIRM4args (XDR *, NFS4::OPEN_CONFIRM4args*);
bool_t xdr_OPEN_CONFIRM4resok (XDR *, NFS4::OPEN_CONFIRM4resok*);
bool_t xdr_OPEN_CONFIRM4res (XDR *, NFS4::OPEN_CONFIRM4res*);
bool_t xdr_OPEN_DOWNGRADE4args (XDR *, NFS4::OPEN_DOWNGRADE4args*);
bool_t xdr_OPEN_DOWNGRADE4resok (XDR *, NFS4::OPEN_DOWNGRADE4resok*);
bool_t xdr_OPEN_DOWNGRADE4res (XDR *, NFS4::OPEN_DOWNGRADE4res*);
bool_t xdr_PUTFH4args (XDR *, NFS4::PUTFH4args*);
bool_t xdr_PUTFH4res (XDR *, NFS4::PUTFH4res*);
bool_t xdr_PUTPUBFH4res (XDR *, NFS4::PUTPUBFH4res*);
bool_t xdr_PUTROOTFH4res (XDR *, NFS4::PUTROOTFH4res*);
bool_t xdr_READ4args (XDR *, NFS4::READ4args*);
bool_t xdr_READ4resok (XDR *, NFS4::READ4resok*);
bool_t xdr_READ4res (XDR *, NFS4::READ4res*);
bool_t xdr_READDIR4args (XDR *, NFS4::READDIR4args*);
bool_t xdr_entry4 (XDR *, NFS4::entry4*);
bool_t xdr_dirlist4 (XDR *, NFS4::dirlist4*);
bool_t xdr_READDIR4resok (XDR *, NFS4::READDIR4resok*);
bool_t xdr_READDIR4res (XDR *, NFS4::READDIR4res*);
bool_t xdr_READLINK4resok (XDR *, NFS4::READLINK4resok*);
bool_t xdr_READLINK4res (XDR *, NFS4::READLINK4res*);
bool_t xdr_REMOVE4args (XDR *, NFS4::REMOVE4args*);
bool_t xdr_REMOVE4resok (XDR *, NFS4::REMOVE4resok*);
bool_t xdr_REMOVE4res (XDR *, NFS4::REMOVE4res*);
bool_t xdr_RENAME4args (XDR *, NFS4::RENAME4args*);
bool_t xdr_RENAME4resok (XDR *, NFS4::RENAME4resok*);
bool_t xdr_RENAME4res (XDR *, NFS4::RENAME4res*);
bool_t xdr_RENEW4args (XDR *, NFS4::RENEW4args*);
bool_t xdr_RENEW4res (XDR *, NFS4::RENEW4res*);
bool_t xdr_RESTOREFH4res (XDR *, NFS4::RESTOREFH4res*);
bool_t xdr_SAVEFH4res (XDR *, NFS4::SAVEFH4res*);
bool_t xdr_SECINFO4args (XDR *, NFS4::SECINFO4args*);
bool_t xdr_rpc_gss_svc_t (XDR *, NFS4::rpc_gss_svc_t*);
bool_t xdr_rpcsec_gss_info (XDR *, NFS4::rpcsec_gss_info*);
bool_t xdr_secinfo4 (XDR *, NFS4::secinfo4*);
bool_t xdr_SECINFO4resok (XDR *, NFS4::SECINFO4resok*);
bool_t xdr_SECINFO4res (XDR *, NFS4::SECINFO4res*);
bool_t xdr_SETATTR4args (XDR *, NFS4::SETATTR4args*);
bool_t xdr_SETATTR4res (XDR *, NFS4::SETATTR4res*);
bool_t xdr_SETCLIENTID4args (XDR *, NFS4::SETCLIENTID4args*);
bool_t xdr_SETCLIENTID4resok (XDR *, NFS4::SETCLIENTID4resok*);
bool_t xdr_SETCLIENTID4res (XDR *, NFS4::SETCLIENTID4res*);
bool_t xdr_SETCLIENTID_CONFIRM4args (XDR *, NFS4::SETCLIENTID_CONFIRM4args*);
bool_t xdr_SETCLIENTID_CONFIRM4res (XDR *, NFS4::SETCLIENTID_CONFIRM4res*);
bool_t xdr_VERIFY4args (XDR *, NFS4::VERIFY4args*);
bool_t xdr_VERIFY4res (XDR *, NFS4::VERIFY4res*);
bool_t xdr_stable_how4 (XDR *, NFS4::stable_how4*);
bool_t xdr_WRITE4args (XDR *, NFS4::WRITE4args*);
bool_t xdr_WRITE4resok (XDR *, NFS4::WRITE4resok*);
bool_t xdr_WRITE4res (XDR *, NFS4::WRITE4res*);
bool_t xdr_RELEASE_LOCKOWNER4args (XDR *, NFS4::RELEASE_LOCKOWNER4args*);
bool_t xdr_RELEASE_LOCKOWNER4res (XDR *, NFS4::RELEASE_LOCKOWNER4res*);
bool_t xdr_ILLEGAL4res (XDR *, NFS4::ILLEGAL4res*);
bool_t xdr_nfs_opnum4 (XDR *, NFS4::nfs_opnum4*);
bool_t xdr_nfs_argop4 (XDR *, NFS4::nfs_argop4*);
bool_t xdr_nfs_resop4 (XDR *, NFS4::nfs_resop4*);
bool_t xdr_COMPOUND4args (XDR *, NFS4::COMPOUND4args*);
bool_t xdr_COMPOUND4res (XDR *, NFS4::COMPOUND4res*);
bool_t xdr_CB_GETATTR4args (XDR *, NFS4::CB_GETATTR4args*);
bool_t xdr_CB_GETATTR4resok (XDR *, NFS4::CB_GETATTR4resok*);
bool_t xdr_CB_GETATTR4res (XDR *, NFS4::CB_GETATTR4res*);
bool_t xdr_CB_RECALL4args (XDR *, NFS4::CB_RECALL4args*);
bool_t xdr_CB_RECALL4res (XDR *, NFS4::CB_RECALL4res*);
bool_t xdr_CB_ILLEGAL4res (XDR *, NFS4::CB_ILLEGAL4res*);
bool_t xdr_nfs_cb_opnum4 (XDR *, NFS4::nfs_cb_opnum4*);
bool_t xdr_nfs_cb_argop4 (XDR *, NFS4::nfs_cb_argop4*);
bool_t xdr_nfs_cb_resop4 (XDR *, NFS4::nfs_cb_resop4*);
bool_t xdr_CB_COMPOUND4args (XDR *, NFS4::CB_COMPOUND4args*);
bool_t xdr_CB_COMPOUND4res (XDR *, NFS4::CB_COMPOUND4res*);
// clang-format on

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(NFS4::NULL4args&) -> decltype(&xdr_NULL4args)
{
    return &xdr_NULL4args;
}

inline auto proc_t_of(NFS4::NULL4res&) -> decltype(&xdr_NULL4res)
{
    return &xdr_NULL4res;
}

// Procedure 1: COMPOUND
inline auto proc_t_of(NFS4::COMPOUND4args&) -> decltype(&xdr_COMPOUND4args)
{
    return &xdr_COMPOUND4args;
}

inline auto proc_t_of(NFS4::COMPOUND4res&) -> decltype(&xdr_COMPOUND4res)
{
    return &xdr_COMPOUND4res;
}

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
#endif // NFS4_UTILS_H
//------------------------------------------------------------------------------
