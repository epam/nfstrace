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
#ifndef NFS41_UTILS_H
#define NFS41_UTILS_H
//------------------------------------------------------------------------------
#include <ostream>

#include "api/nfs41_types_rpcgen.h"
#include "api/nfs_types.h"
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

using Validator = rpc::RPCProgramValidator<
    100003,                  // SunRPC/NFS program
    4,                       // v4
    ProcEnumNFS41::NFS_NULL, // NFSPROC41RPCGEN_NULL     (0)
    ProcEnumNFS41::COMPOUND  // NFSPROC41RPCGEN_COMPOUND (1)
    >;

// clang-format off
bool_t xdr_nfs_ftype4 (XDR *, NFS41::nfs_ftype4*);
bool_t xdr_nfsstat4 (XDR *, NFS41::nfsstat4*);
bool_t xdr_attrlist4 (XDR *, NFS41::attrlist4*);
bool_t xdr_bitmap4 (XDR *, NFS41::bitmap4*);
bool_t xdr_changeid4 (XDR *, NFS41::changeid4*);
bool_t xdr_clientid4 (XDR *, NFS41::clientid4*);
bool_t xdr_count4 (XDR *, NFS41::count4*);
bool_t xdr_length4 (XDR *, NFS41::length4*);
bool_t xdr_mode4 (XDR *, NFS41::mode4*);
bool_t xdr_nfs_cookie4 (XDR *, NFS41::nfs_cookie4*);
bool_t xdr_nfs_fh4 (XDR *, NFS41::nfs_fh4*);
bool_t xdr_offset4 (XDR *, NFS41::offset4*);
bool_t xdr_qop4 (XDR *, NFS41::qop4*);
bool_t xdr_sec_oid4 (XDR *, NFS41::sec_oid4*);
bool_t xdr_sequenceid4 (XDR *, NFS41::sequenceid4*);
bool_t xdr_seqid4 (XDR *, NFS41::seqid4*);
bool_t xdr_sessionid4 (XDR *, NFS41::sessionid4);
bool_t xdr_slotid4 (XDR *, NFS41::slotid4*);
bool_t xdr_utf8string (XDR *, NFS41::utf8string*);
bool_t xdr_utf8str_cis (XDR *, NFS41::utf8str_cis*);
bool_t xdr_utf8str_cs (XDR *, NFS41::utf8str_cs*);
bool_t xdr_utf8str_mixed (XDR *, NFS41::utf8str_mixed*);
bool_t xdr_component4 (XDR *, NFS41::component4*);
bool_t xdr_linktext4 (XDR *, NFS41::linktext4*);
bool_t xdr_pathname4 (XDR *, NFS41::pathname4*);
bool_t xdr_verifier4 (XDR *, NFS41::verifier4);
bool_t xdr_nfstime4 (XDR *, NFS41::nfstime4*);
bool_t xdr_time_how4 (XDR *, NFS41::time_how4*);
bool_t xdr_settime4 (XDR *, NFS41::settime4*);
bool_t xdr_nfs_lease4 (XDR *, NFS41::nfs_lease4*);
bool_t xdr_fsid4 (XDR *, NFS41::fsid4*);
bool_t xdr_change_policy4 (XDR *, NFS41::change_policy4*);
bool_t xdr_fs_location4 (XDR *, NFS41::fs_location4*);
bool_t xdr_fs_locations4 (XDR *, NFS41::fs_locations4*);
bool_t xdr_acetype4 (XDR *, NFS41::acetype4*);
bool_t xdr_aceflag4 (XDR *, NFS41::aceflag4*);
bool_t xdr_acemask4 (XDR *, NFS41::acemask4*);
bool_t xdr_nfsace4 (XDR *, NFS41::nfsace4*);
bool_t xdr_aclflag4 (XDR *, NFS41::aclflag4*);
bool_t xdr_nfsacl41 (XDR *, NFS41::nfsacl41*);
bool_t xdr_mode_masked4 (XDR *, NFS41::mode_masked4*);
bool_t xdr_specdata4 (XDR *, NFS41::specdata4*);
bool_t xdr_netaddr4 (XDR *, NFS41::netaddr4*);
bool_t xdr_nfs_impl_id4 (XDR *, NFS41::nfs_impl_id4*);
bool_t xdr_stateid4 (XDR *, NFS41::stateid4*);
bool_t xdr_layouttype4 (XDR *, NFS41::layouttype4*);
bool_t xdr_layout_content4 (XDR *, NFS41::layout_content4*);
bool_t xdr_layouthint4 (XDR *, NFS41::layouthint4*);
bool_t xdr_layoutiomode4 (XDR *, NFS41::layoutiomode4*);
bool_t xdr_layout4 (XDR *, NFS41::layout4*);
bool_t xdr_deviceid4 (XDR *, NFS41::deviceid4);
bool_t xdr_device_addr4 (XDR *, NFS41::device_addr4*);
bool_t xdr_layoutupdate4 (XDR *, NFS41::layoutupdate4*);
bool_t xdr_layoutreturn_type4 (XDR *, NFS41::layoutreturn_type4*);
bool_t xdr_layoutreturn_file4 (XDR *, NFS41::layoutreturn_file4*);
bool_t xdr_layoutreturn4 (XDR *, NFS41::layoutreturn4*);
bool_t xdr_fs4_status_type (XDR *, NFS41::fs4_status_type*);
bool_t xdr_fs4_status (XDR *, NFS41::fs4_status*);
bool_t xdr_threshold4_read_size (XDR *, NFS41::threshold4_read_size*);
bool_t xdr_threshold4_write_size (XDR *, NFS41::threshold4_write_size*);
bool_t xdr_threshold4_read_iosize (XDR *, NFS41::threshold4_read_iosize*);
bool_t xdr_threshold4_write_iosize (XDR *, NFS41::threshold4_write_iosize*);
bool_t xdr_threshold_item4 (XDR *, NFS41::threshold_item4*);
bool_t xdr_mdsthreshold4 (XDR *, NFS41::mdsthreshold4*);
bool_t xdr_retention_get4 (XDR *, NFS41::retention_get4*);
bool_t xdr_retention_set4 (XDR *, NFS41::retention_set4*);
bool_t xdr_fs_charset_cap4 (XDR *, NFS41::fs_charset_cap4*);
bool_t xdr_fattr4_supported_attrs (XDR *, NFS41::fattr4_supported_attrs*);
bool_t xdr_fattr4_type (XDR *, NFS41::fattr4_type*);
bool_t xdr_fattr4_fh_expire_type (XDR *, NFS41::fattr4_fh_expire_type*);
bool_t xdr_fattr4_change (XDR *, NFS41::fattr4_change*);
bool_t xdr_fattr4_size (XDR *, NFS41::fattr4_size*);
bool_t xdr_fattr4_link_support (XDR *, NFS41::fattr4_link_support*);
bool_t xdr_fattr4_symlink_support (XDR *, NFS41::fattr4_symlink_support*);
bool_t xdr_fattr4_named_attr (XDR *, NFS41::fattr4_named_attr*);
bool_t xdr_fattr4_fsid (XDR *, NFS41::fattr4_fsid*);
bool_t xdr_fattr4_unique_handles (XDR *, NFS41::fattr4_unique_handles*);
bool_t xdr_fattr4_lease_time (XDR *, NFS41::fattr4_lease_time*);
bool_t xdr_fattr4_rdattr_error (XDR *, NFS41::fattr4_rdattr_error*);
bool_t xdr_fattr4_acl (XDR *, NFS41::fattr4_acl*);
bool_t xdr_fattr4_aclsupport (XDR *, NFS41::fattr4_aclsupport*);
bool_t xdr_fattr4_archive (XDR *, NFS41::fattr4_archive*);
bool_t xdr_fattr4_cansettime (XDR *, NFS41::fattr4_cansettime*);
bool_t xdr_fattr4_case_insensitive (XDR *, NFS41::fattr4_case_insensitive*);
bool_t xdr_fattr4_case_preserving (XDR *, NFS41::fattr4_case_preserving*);
bool_t xdr_fattr4_chown_restricted (XDR *, NFS41::fattr4_chown_restricted*);
bool_t xdr_fattr4_fileid (XDR *, NFS41::fattr4_fileid*);
bool_t xdr_fattr4_files_avail (XDR *, NFS41::fattr4_files_avail*);
bool_t xdr_fattr4_filehandle (XDR *, NFS41::fattr4_filehandle*);
bool_t xdr_fattr4_files_free (XDR *, NFS41::fattr4_files_free*);
bool_t xdr_fattr4_files_total (XDR *, NFS41::fattr4_files_total*);
bool_t xdr_fattr4_fs_locations (XDR *, NFS41::fattr4_fs_locations*);
bool_t xdr_fattr4_hidden (XDR *, NFS41::fattr4_hidden*);
bool_t xdr_fattr4_homogeneous (XDR *, NFS41::fattr4_homogeneous*);
bool_t xdr_fattr4_maxfilesize (XDR *, NFS41::fattr4_maxfilesize*);
bool_t xdr_fattr4_maxlink (XDR *, NFS41::fattr4_maxlink*);
bool_t xdr_fattr4_maxname (XDR *, NFS41::fattr4_maxname*);
bool_t xdr_fattr4_maxread (XDR *, NFS41::fattr4_maxread*);
bool_t xdr_fattr4_maxwrite (XDR *, NFS41::fattr4_maxwrite*);
bool_t xdr_fattr4_mimetype (XDR *, NFS41::fattr4_mimetype*);
bool_t xdr_fattr4_mode (XDR *, NFS41::fattr4_mode*);
bool_t xdr_fattr4_mode_set_masked (XDR *, NFS41::fattr4_mode_set_masked*);
bool_t xdr_fattr4_mounted_on_fileid (XDR *, NFS41::fattr4_mounted_on_fileid*);
bool_t xdr_fattr4_no_trunc (XDR *, NFS41::fattr4_no_trunc*);
bool_t xdr_fattr4_numlinks (XDR *, NFS41::fattr4_numlinks*);
bool_t xdr_fattr4_owner (XDR *, NFS41::fattr4_owner*);
bool_t xdr_fattr4_owner_group (XDR *, NFS41::fattr4_owner_group*);
bool_t xdr_fattr4_quota_avail_hard (XDR *, NFS41::fattr4_quota_avail_hard*);
bool_t xdr_fattr4_quota_avail_soft (XDR *, NFS41::fattr4_quota_avail_soft*);
bool_t xdr_fattr4_quota_used (XDR *, NFS41::fattr4_quota_used*);
bool_t xdr_fattr4_rawdev (XDR *, NFS41::fattr4_rawdev*);
bool_t xdr_fattr4_space_avail (XDR *, NFS41::fattr4_space_avail*);
bool_t xdr_fattr4_space_free (XDR *, NFS41::fattr4_space_free*);
bool_t xdr_fattr4_space_total (XDR *, NFS41::fattr4_space_total*);
bool_t xdr_fattr4_space_used (XDR *, NFS41::fattr4_space_used*);
bool_t xdr_fattr4_system (XDR *, NFS41::fattr4_system*);
bool_t xdr_fattr4_time_access (XDR *, NFS41::fattr4_time_access*);
bool_t xdr_fattr4_time_access_set (XDR *, NFS41::fattr4_time_access_set*);
bool_t xdr_fattr4_time_backup (XDR *, NFS41::fattr4_time_backup*);
bool_t xdr_fattr4_time_create (XDR *, NFS41::fattr4_time_create*);
bool_t xdr_fattr4_time_delta (XDR *, NFS41::fattr4_time_delta*);
bool_t xdr_fattr4_time_metadata (XDR *, NFS41::fattr4_time_metadata*);
bool_t xdr_fattr4_time_modify (XDR *, NFS41::fattr4_time_modify*);
bool_t xdr_fattr4_time_modify_set (XDR *, NFS41::fattr4_time_modify_set*);
bool_t xdr_fattr4_suppattr_exclcreat (XDR *, NFS41::fattr4_suppattr_exclcreat*);
bool_t xdr_fattr4_dir_notif_delay (XDR *, NFS41::fattr4_dir_notif_delay*);
bool_t xdr_fattr4_dirent_notif_delay (XDR *, NFS41::fattr4_dirent_notif_delay*);
bool_t xdr_fattr4_fs_layout_types (XDR *, NFS41::fattr4_fs_layout_types*);
bool_t xdr_fattr4_fs_status (XDR *, NFS41::fattr4_fs_status*);
bool_t xdr_fattr4_fs_charset_cap (XDR *, NFS41::fattr4_fs_charset_cap*);
bool_t xdr_fattr4_layout_alignment (XDR *, NFS41::fattr4_layout_alignment*);
bool_t xdr_fattr4_layout_blksize (XDR *, NFS41::fattr4_layout_blksize*);
bool_t xdr_fattr4_layout_hint (XDR *, NFS41::fattr4_layout_hint*);
bool_t xdr_fattr4_layout_types (XDR *, NFS41::fattr4_layout_types*);
bool_t xdr_fattr4_mdsthreshold (XDR *, NFS41::fattr4_mdsthreshold*);
bool_t xdr_fattr4_retention_get (XDR *, NFS41::fattr4_retention_get*);
bool_t xdr_fattr4_retention_set (XDR *, NFS41::fattr4_retention_set*);
bool_t xdr_fattr4_retentevt_get (XDR *, NFS41::fattr4_retentevt_get*);
bool_t xdr_fattr4_retentevt_set (XDR *, NFS41::fattr4_retentevt_set*);
bool_t xdr_fattr4_retention_hold (XDR *, NFS41::fattr4_retention_hold*);
bool_t xdr_fattr4_dacl (XDR *, NFS41::fattr4_dacl*);
bool_t xdr_fattr4_sacl (XDR *, NFS41::fattr4_sacl*);
bool_t xdr_fattr4_change_policy (XDR *, NFS41::fattr4_change_policy*);
bool_t xdr_fattr4 (XDR *, NFS41::fattr4*);
bool_t xdr_change_info4 (XDR *, NFS41::change_info4*);
bool_t xdr_clientaddr4 (XDR *, NFS41::clientaddr4*);
bool_t xdr_cb_client4 (XDR *, NFS41::cb_client4*);
bool_t xdr_nfs_client_id4 (XDR *, NFS41::nfs_client_id4*);
bool_t xdr_client_owner4 (XDR *, NFS41::client_owner4*);
bool_t xdr_server_owner4 (XDR *, NFS41::server_owner4*);
bool_t xdr_state_owner4 (XDR *, NFS41::state_owner4*);
bool_t xdr_open_owner4 (XDR *, NFS41::open_owner4*);
bool_t xdr_lock_owner4 (XDR *, NFS41::lock_owner4*);
bool_t xdr_nfs_lock_type4 (XDR *, NFS41::nfs_lock_type4*);
bool_t xdr_ssv_subkey4 (XDR *, NFS41::ssv_subkey4*);
bool_t xdr_ssv_mic_plain_tkn4 (XDR *, NFS41::ssv_mic_plain_tkn4*);
bool_t xdr_ssv_mic_tkn4 (XDR *, NFS41::ssv_mic_tkn4*);
bool_t xdr_ssv_seal_plain_tkn4 (XDR *, NFS41::ssv_seal_plain_tkn4*);
bool_t xdr_ssv_seal_cipher_tkn4 (XDR *, NFS41::ssv_seal_cipher_tkn4*);
bool_t xdr_fs_locations_server4 (XDR *, NFS41::fs_locations_server4*);
bool_t xdr_fs_locations_item4 (XDR *, NFS41::fs_locations_item4*);
bool_t xdr_fs_locations_info4 (XDR *, NFS41::fs_locations_info4*);
bool_t xdr_fattr4_fs_locations_info (XDR *, NFS41::fattr4_fs_locations_info*);
bool_t xdr_nfl_util4 (XDR *, NFS41::nfl_util4*);
bool_t xdr_filelayout_hint_care4 (XDR *, NFS41::filelayout_hint_care4*);
bool_t xdr_nfsv4_1_file_layouthint4 (XDR *, NFS41::nfsv4_1_file_layouthint4*);
bool_t xdr_multipath_list4 (XDR *, NFS41::multipath_list4*);
bool_t xdr_nfsv4_1_file_layout_ds_addr4 (XDR *, NFS41::nfsv4_1_file_layout_ds_addr4*);
bool_t xdr_nfsv4_1_file_layout4 (XDR *, NFS41::nfsv4_1_file_layout4*);
bool_t xdr_NULL4args (XDR *, NFS41::NULL4args*); // for compatibility
bool_t xdr_NULL4res (XDR *, NFS41::NULL4res*);   // for compatibility
bool_t xdr_ACCESS4args (XDR *, NFS41::ACCESS4args*);
bool_t xdr_ACCESS4resok (XDR *, NFS41::ACCESS4resok*);
bool_t xdr_ACCESS4res (XDR *, NFS41::ACCESS4res*);
bool_t xdr_CLOSE4args (XDR *, NFS41::CLOSE4args*);
bool_t xdr_CLOSE4res (XDR *, NFS41::CLOSE4res*);
bool_t xdr_COMMIT4args (XDR *, NFS41::COMMIT4args*);
bool_t xdr_COMMIT4resok (XDR *, NFS41::COMMIT4resok*);
bool_t xdr_COMMIT4res (XDR *, NFS41::COMMIT4res*);
bool_t xdr_createtype4 (XDR *, NFS41::createtype4*);
bool_t xdr_CREATE4args (XDR *, NFS41::CREATE4args*);
bool_t xdr_CREATE4resok (XDR *, NFS41::CREATE4resok*);
bool_t xdr_CREATE4res (XDR *, NFS41::CREATE4res*);
bool_t xdr_DELEGPURGE4args (XDR *, NFS41::DELEGPURGE4args*);
bool_t xdr_DELEGPURGE4res (XDR *, NFS41::DELEGPURGE4res*);
bool_t xdr_DELEGRETURN4args (XDR *, NFS41::DELEGRETURN4args*);
bool_t xdr_DELEGRETURN4res (XDR *, NFS41::DELEGRETURN4res*);
bool_t xdr_GETATTR4args (XDR *, NFS41::GETATTR4args*);
bool_t xdr_GETATTR4resok (XDR *, NFS41::GETATTR4resok*);
bool_t xdr_GETATTR4res (XDR *, NFS41::GETATTR4res*);
bool_t xdr_GETFH4resok (XDR *, NFS41::GETFH4resok*);
bool_t xdr_GETFH4res (XDR *, NFS41::GETFH4res*);
bool_t xdr_LINK4args (XDR *, NFS41::LINK4args*);
bool_t xdr_LINK4resok (XDR *, NFS41::LINK4resok*);
bool_t xdr_LINK4res (XDR *, NFS41::LINK4res*);
bool_t xdr_open_to_lock_owner4 (XDR *, NFS41::open_to_lock_owner4*);
bool_t xdr_exist_lock_owner4 (XDR *, NFS41::exist_lock_owner4*);
bool_t xdr_locker4 (XDR *, NFS41::locker4*);
bool_t xdr_LOCK4args (XDR *, NFS41::LOCK4args*);
bool_t xdr_LOCK4denied (XDR *, NFS41::LOCK4denied*);
bool_t xdr_LOCK4resok (XDR *, NFS41::LOCK4resok*);
bool_t xdr_LOCK4res (XDR *, NFS41::LOCK4res*);
bool_t xdr_LOCKT4args (XDR *, NFS41::LOCKT4args*);
bool_t xdr_LOCKT4res (XDR *, NFS41::LOCKT4res*);
bool_t xdr_LOCKU4args (XDR *, NFS41::LOCKU4args*);
bool_t xdr_LOCKU4res (XDR *, NFS41::LOCKU4res*);
bool_t xdr_LOOKUP4args (XDR *, NFS41::LOOKUP4args*);
bool_t xdr_LOOKUP4res (XDR *, NFS41::LOOKUP4res*);
bool_t xdr_LOOKUPP4res (XDR *, NFS41::LOOKUPP4res*);
bool_t xdr_NVERIFY4args (XDR *, NFS41::NVERIFY4args*);
bool_t xdr_NVERIFY4res (XDR *, NFS41::NVERIFY4res*);
bool_t xdr_createmode4 (XDR *, NFS41::createmode4*);
bool_t xdr_creatverfattr (XDR *, NFS41::creatverfattr*);
bool_t xdr_createhow4 (XDR *, NFS41::createhow4*);
bool_t xdr_opentype4 (XDR *, NFS41::opentype4*);
bool_t xdr_openflag4 (XDR *, NFS41::openflag4*);
bool_t xdr_limit_by4 (XDR *, NFS41::limit_by4*);
bool_t xdr_nfs_modified_limit4 (XDR *, NFS41::nfs_modified_limit4*);
bool_t xdr_nfs_space_limit4 (XDR *, NFS41::nfs_space_limit4*);
bool_t xdr_open_delegation_type4 (XDR *, NFS41::open_delegation_type4*);
bool_t xdr_open_claim_type4 (XDR *, NFS41::open_claim_type4*);
bool_t xdr_open_claim_delegate_cur4 (XDR *, NFS41::open_claim_delegate_cur4*);
bool_t xdr_open_claim4 (XDR *, NFS41::open_claim4*);
bool_t xdr_OPEN4args (XDR *, NFS41::OPEN4args*);
bool_t xdr_open_read_delegation4 (XDR *, NFS41::open_read_delegation4*);
bool_t xdr_open_write_delegation4 (XDR *, NFS41::open_write_delegation4*);
bool_t xdr_why_no_delegation4 (XDR *, NFS41::why_no_delegation4*);
bool_t xdr_open_none_delegation4 (XDR *, NFS41::open_none_delegation4*);
bool_t xdr_open_delegation4 (XDR *, NFS41::open_delegation4*);
bool_t xdr_OPEN4resok (XDR *, NFS41::OPEN4resok*);
bool_t xdr_OPEN4res (XDR *, NFS41::OPEN4res*);
bool_t xdr_OPENATTR4args (XDR *, NFS41::OPENATTR4args*);
bool_t xdr_OPENATTR4res (XDR *, NFS41::OPENATTR4res*);
bool_t xdr_OPEN_CONFIRM4args (XDR *, NFS41::OPEN_CONFIRM4args*);
bool_t xdr_OPEN_CONFIRM4resok (XDR *, NFS41::OPEN_CONFIRM4resok*);
bool_t xdr_OPEN_CONFIRM4res (XDR *, NFS41::OPEN_CONFIRM4res*);
bool_t xdr_OPEN_DOWNGRADE4args (XDR *, NFS41::OPEN_DOWNGRADE4args*);
bool_t xdr_OPEN_DOWNGRADE4resok (XDR *, NFS41::OPEN_DOWNGRADE4resok*);
bool_t xdr_OPEN_DOWNGRADE4res (XDR *, NFS41::OPEN_DOWNGRADE4res*);
bool_t xdr_PUTFH4args (XDR *, NFS41::PUTFH4args*);
bool_t xdr_PUTFH4res (XDR *, NFS41::PUTFH4res*);
bool_t xdr_PUTPUBFH4res (XDR *, NFS41::PUTPUBFH4res*);
bool_t xdr_PUTROOTFH4res (XDR *, NFS41::PUTROOTFH4res*);
bool_t xdr_READ4args (XDR *, NFS41::READ4args*);
bool_t xdr_READ4resok (XDR *, NFS41::READ4resok*);
bool_t xdr_READ4res (XDR *, NFS41::READ4res*);
bool_t xdr_READDIR4args (XDR *, NFS41::READDIR4args*);
bool_t xdr_entry4 (XDR *, NFS41::entry4*);
bool_t xdr_dirlist4 (XDR *, NFS41::dirlist4*);
bool_t xdr_READDIR4resok (XDR *, NFS41::READDIR4resok*);
bool_t xdr_READDIR4res (XDR *, NFS41::READDIR4res*);
bool_t xdr_READLINK4resok (XDR *, NFS41::READLINK4resok*);
bool_t xdr_READLINK4res (XDR *, NFS41::READLINK4res*);
bool_t xdr_REMOVE4args (XDR *, NFS41::REMOVE4args*);
bool_t xdr_REMOVE4resok (XDR *, NFS41::REMOVE4resok*);
bool_t xdr_REMOVE4res (XDR *, NFS41::REMOVE4res*);
bool_t xdr_RENAME4args (XDR *, NFS41::RENAME4args*);
bool_t xdr_RENAME4resok (XDR *, NFS41::RENAME4resok*);
bool_t xdr_RENAME4res (XDR *, NFS41::RENAME4res*);
bool_t xdr_RENEW4args (XDR *, NFS41::RENEW4args*);
bool_t xdr_RENEW4res (XDR *, NFS41::RENEW4res*);
bool_t xdr_RESTOREFH4res (XDR *, NFS41::RESTOREFH4res*);
bool_t xdr_SAVEFH4res (XDR *, NFS41::SAVEFH4res*);
bool_t xdr_SECINFO4args (XDR *, NFS41::SECINFO4args*);
bool_t xdr_rpc_gss_svc_t (XDR *, NFS41::rpc_gss_svc_t*);
bool_t xdr_rpcsec_gss_info (XDR *, NFS41::rpcsec_gss_info*);
bool_t xdr_secinfo4 (XDR *, NFS41::secinfo4*);
bool_t xdr_SECINFO4resok (XDR *, NFS41::SECINFO4resok*);
bool_t xdr_SECINFO4res (XDR *, NFS41::SECINFO4res*);
bool_t xdr_SETATTR4args (XDR *, NFS41::SETATTR4args*);
bool_t xdr_SETATTR4res (XDR *, NFS41::SETATTR4res*);
bool_t xdr_SETCLIENTID4args (XDR *, NFS41::SETCLIENTID4args*);
bool_t xdr_SETCLIENTID4resok (XDR *, NFS41::SETCLIENTID4resok*);
bool_t xdr_SETCLIENTID4res (XDR *, NFS41::SETCLIENTID4res*);
bool_t xdr_SETCLIENTID_CONFIRM4args (XDR *, NFS41::SETCLIENTID_CONFIRM4args*);
bool_t xdr_SETCLIENTID_CONFIRM4res (XDR *, NFS41::SETCLIENTID_CONFIRM4res*);
bool_t xdr_VERIFY4args (XDR *, NFS41::VERIFY4args*);
bool_t xdr_VERIFY4res (XDR *, NFS41::VERIFY4res*);
bool_t xdr_stable_how4 (XDR *, NFS41::stable_how4*);
bool_t xdr_WRITE4args (XDR *, NFS41::WRITE4args*);
bool_t xdr_WRITE4resok (XDR *, NFS41::WRITE4resok*);
bool_t xdr_WRITE4res (XDR *, NFS41::WRITE4res*);
bool_t xdr_RELEASE_LOCKOWNER4args (XDR *, NFS41::RELEASE_LOCKOWNER4args*);
bool_t xdr_RELEASE_LOCKOWNER4res (XDR *, NFS41::RELEASE_LOCKOWNER4res*);
bool_t xdr_ILLEGAL4res (XDR *, NFS41::ILLEGAL4res*);
bool_t xdr_gsshandle4_t (XDR *, NFS41::gsshandle4_t*);
bool_t xdr_gss_cb_handles4 (XDR *, NFS41::gss_cb_handles4*);
bool_t xdr_callback_sec_parms4 (XDR *, NFS41::callback_sec_parms4*);
bool_t xdr_BACKCHANNEL_CTL4args (XDR *, NFS41::BACKCHANNEL_CTL4args*);
bool_t xdr_BACKCHANNEL_CTL4res (XDR *, NFS41::BACKCHANNEL_CTL4res*);
bool_t xdr_channel_dir_from_client4 (XDR *, NFS41::channel_dir_from_client4*);
bool_t xdr_BIND_CONN_TO_SESSION4args (XDR *, NFS41::BIND_CONN_TO_SESSION4args*);
bool_t xdr_channel_dir_from_server4 (XDR *, NFS41::channel_dir_from_server4*);
bool_t xdr_BIND_CONN_TO_SESSION4resok (XDR *, NFS41::BIND_CONN_TO_SESSION4resok*);
bool_t xdr_BIND_CONN_TO_SESSION4res (XDR *, NFS41::BIND_CONN_TO_SESSION4res*);
bool_t xdr_state_protect_ops4 (XDR *, NFS41::state_protect_ops4*);
bool_t xdr_ssv_sp_parms4 (XDR *, NFS41::ssv_sp_parms4*);
bool_t xdr_state_protect_how4 (XDR *, NFS41::state_protect_how4*);
bool_t xdr_state_protect4_a (XDR *, NFS41::state_protect4_a*);
bool_t xdr_EXCHANGE_ID4args (XDR *, NFS41::EXCHANGE_ID4args*);
bool_t xdr_ssv_prot_info4 (XDR *, NFS41::ssv_prot_info4*);
bool_t xdr_state_protect4_r (XDR *, NFS41::state_protect4_r*);
bool_t xdr_EXCHANGE_ID4resok (XDR *, NFS41::EXCHANGE_ID4resok*);
bool_t xdr_EXCHANGE_ID4res (XDR *, NFS41::EXCHANGE_ID4res*);
bool_t xdr_channel_attrs4 (XDR *, NFS41::channel_attrs4*);
bool_t xdr_CREATE_SESSION4args (XDR *, NFS41::CREATE_SESSION4args*);
bool_t xdr_CREATE_SESSION4resok (XDR *, NFS41::CREATE_SESSION4resok*);
bool_t xdr_CREATE_SESSION4res (XDR *, NFS41::CREATE_SESSION4res*);
bool_t xdr_DESTROY_SESSION4args (XDR *, NFS41::DESTROY_SESSION4args*);
bool_t xdr_DESTROY_SESSION4res (XDR *, NFS41::DESTROY_SESSION4res*);
bool_t xdr_FREE_STATEID4args (XDR *, NFS41::FREE_STATEID4args*);
bool_t xdr_FREE_STATEID4res (XDR *, NFS41::FREE_STATEID4res*);
bool_t xdr_attr_notice4 (XDR *, NFS41::attr_notice4*);
bool_t xdr_GET_DIR_DELEGATION4args (XDR *, NFS41::GET_DIR_DELEGATION4args*);
bool_t xdr_GET_DIR_DELEGATION4resok (XDR *, NFS41::GET_DIR_DELEGATION4resok*);
bool_t xdr_gddrnf4_status (XDR *, NFS41::gddrnf4_status*);
bool_t xdr_GET_DIR_DELEGATION4res_non_fatal (XDR *, NFS41::GET_DIR_DELEGATION4res_non_fatal*);
bool_t xdr_GET_DIR_DELEGATION4res (XDR *, NFS41::GET_DIR_DELEGATION4res*);
bool_t xdr_GETDEVICEINFO4args (XDR *, NFS41::GETDEVICEINFO4args*);
bool_t xdr_GETDEVICEINFO4resok (XDR *, NFS41::GETDEVICEINFO4resok*);
bool_t xdr_GETDEVICEINFO4res (XDR *, NFS41::GETDEVICEINFO4res*);
bool_t xdr_GETDEVICELIST4args (XDR *, NFS41::GETDEVICELIST4args*);
bool_t xdr_GETDEVICELIST4resok (XDR *, NFS41::GETDEVICELIST4resok*);
bool_t xdr_GETDEVICELIST4res (XDR *, NFS41::GETDEVICELIST4res*);
bool_t xdr_newtime4 (XDR *, NFS41::newtime4*);
bool_t xdr_newoffset4 (XDR *, NFS41::newoffset4*);
bool_t xdr_LAYOUTCOMMIT4args (XDR *, NFS41::LAYOUTCOMMIT4args*);
bool_t xdr_newsize4 (XDR *, NFS41::newsize4*);
bool_t xdr_LAYOUTCOMMIT4resok (XDR *, NFS41::LAYOUTCOMMIT4resok*);
bool_t xdr_LAYOUTCOMMIT4res (XDR *, NFS41::LAYOUTCOMMIT4res*);
bool_t xdr_LAYOUTGET4args (XDR *, NFS41::LAYOUTGET4args*);
bool_t xdr_LAYOUTGET4resok (XDR *, NFS41::LAYOUTGET4resok*);
bool_t xdr_LAYOUTGET4res (XDR *, NFS41::LAYOUTGET4res*);
bool_t xdr_LAYOUTRETURN4args (XDR *, NFS41::LAYOUTRETURN4args*);
bool_t xdr_layoutreturn_stateid (XDR *, NFS41::layoutreturn_stateid*);
bool_t xdr_LAYOUTRETURN4res (XDR *, NFS41::LAYOUTRETURN4res*);
bool_t xdr_secinfo_style4 (XDR *, NFS41::secinfo_style4*);
bool_t xdr_SECINFO_NO_NAME4args (XDR *, NFS41::SECINFO_NO_NAME4args*);
bool_t xdr_SECINFO_NO_NAME4res (XDR *, NFS41::SECINFO_NO_NAME4res*);
bool_t xdr_SEQUENCE4args (XDR *, NFS41::SEQUENCE4args*);
bool_t xdr_SEQUENCE4resok (XDR *, NFS41::SEQUENCE4resok*);
bool_t xdr_SEQUENCE4res (XDR *, NFS41::SEQUENCE4res*);
bool_t xdr_ssa_digest_input4 (XDR *, NFS41::ssa_digest_input4*);
bool_t xdr_SET_SSV4args (XDR *, NFS41::SET_SSV4args*);
bool_t xdr_ssr_digest_input4 (XDR *, NFS41::ssr_digest_input4*);
bool_t xdr_SET_SSV4resok (XDR *, NFS41::SET_SSV4resok*);
bool_t xdr_SET_SSV4res (XDR *, NFS41::SET_SSV4res*);
bool_t xdr_TEST_STATEID4args (XDR *, NFS41::TEST_STATEID4args*);
bool_t xdr_TEST_STATEID4resok (XDR *, NFS41::TEST_STATEID4resok*);
bool_t xdr_TEST_STATEID4res (XDR *, NFS41::TEST_STATEID4res*);
bool_t xdr_deleg_claim4 (XDR *, NFS41::deleg_claim4*);
bool_t xdr_WANT_DELEGATION4args (XDR *, NFS41::WANT_DELEGATION4args*);
bool_t xdr_WANT_DELEGATION4res (XDR *, NFS41::WANT_DELEGATION4res*);
bool_t xdr_DESTROY_CLIENTID4args (XDR *, NFS41::DESTROY_CLIENTID4args*);
bool_t xdr_DESTROY_CLIENTID4res (XDR *, NFS41::DESTROY_CLIENTID4res*);
bool_t xdr_RECLAIM_COMPLETE4args (XDR *, NFS41::RECLAIM_COMPLETE4args*);
bool_t xdr_RECLAIM_COMPLETE4res (XDR *, NFS41::RECLAIM_COMPLETE4res*);
bool_t xdr_nfs_opnum4 (XDR *, NFS41::nfs_opnum4*);
bool_t xdr_nfs_argop4 (XDR *, NFS41::nfs_argop4*);
bool_t xdr_nfs_resop4 (XDR *, NFS41::nfs_resop4*);
bool_t xdr_COMPOUND4args (XDR *, NFS41::COMPOUND4args*);
bool_t xdr_COMPOUND4res (XDR *, NFS41::COMPOUND4res*);
bool_t xdr_CB_GETATTR4args (XDR *, NFS41::CB_GETATTR4args*);
bool_t xdr_CB_GETATTR4resok (XDR *, NFS41::CB_GETATTR4resok*);
bool_t xdr_CB_GETATTR4res (XDR *, NFS41::CB_GETATTR4res*);
bool_t xdr_CB_RECALL4args (XDR *, NFS41::CB_RECALL4args*);
bool_t xdr_CB_RECALL4res (XDR *, NFS41::CB_RECALL4res*);
bool_t xdr_CB_ILLEGAL4res (XDR *, NFS41::CB_ILLEGAL4res*);
bool_t xdr_layoutrecall_type4 (XDR *, NFS41::layoutrecall_type4*);
bool_t xdr_layoutrecall_file4 (XDR *, NFS41::layoutrecall_file4*);
bool_t xdr_layoutrecall4 (XDR *, NFS41::layoutrecall4*);
bool_t xdr_CB_LAYOUTRECALL4args (XDR *, NFS41::CB_LAYOUTRECALL4args*);
bool_t xdr_CB_LAYOUTRECALL4res (XDR *, NFS41::CB_LAYOUTRECALL4res*);
bool_t xdr_notify_type4 (XDR *, NFS41::notify_type4*);
bool_t xdr_notify_entry4 (XDR *, NFS41::notify_entry4*);
bool_t xdr_prev_entry4 (XDR *, NFS41::prev_entry4*);
bool_t xdr_notify_remove4 (XDR *, NFS41::notify_remove4*);
bool_t xdr_notify_add4 (XDR *, NFS41::notify_add4*);
bool_t xdr_notify_attr4 (XDR *, NFS41::notify_attr4*);
bool_t xdr_notify_rename4 (XDR *, NFS41::notify_rename4*);
bool_t xdr_notify_verifier4 (XDR *, NFS41::notify_verifier4*);
bool_t xdr_notifylist4 (XDR *, NFS41::notifylist4*);
bool_t xdr_notify4 (XDR *, NFS41::notify4*);
bool_t xdr_CB_NOTIFY4args (XDR *, NFS41::CB_NOTIFY4args*);
bool_t xdr_CB_NOTIFY4res (XDR *, NFS41::CB_NOTIFY4res*);
bool_t xdr_CB_PUSH_DELEG4args (XDR *, NFS41::CB_PUSH_DELEG4args*);
bool_t xdr_CB_PUSH_DELEG4res (XDR *, NFS41::CB_PUSH_DELEG4res*);
bool_t xdr_CB_RECALL_ANY4args (XDR *, NFS41::CB_RECALL_ANY4args*);
bool_t xdr_CB_RECALL_ANY4res (XDR *, NFS41::CB_RECALL_ANY4res*);
bool_t xdr_CB_RECALLABLE_OBJ_AVAIL4args (XDR *, NFS41::CB_RECALLABLE_OBJ_AVAIL4args*);
bool_t xdr_CB_RECALLABLE_OBJ_AVAIL4res (XDR *, NFS41::CB_RECALLABLE_OBJ_AVAIL4res*);
bool_t xdr_CB_RECALL_SLOT4args (XDR *, NFS41::CB_RECALL_SLOT4args*);
bool_t xdr_CB_RECALL_SLOT4res (XDR *, NFS41::CB_RECALL_SLOT4res*);
bool_t xdr_referring_call4 (XDR *, NFS41::referring_call4*);
bool_t xdr_referring_call_list4 (XDR *, NFS41::referring_call_list4*);
bool_t xdr_CB_SEQUENCE4args (XDR *, NFS41::CB_SEQUENCE4args*);
bool_t xdr_CB_SEQUENCE4resok (XDR *, NFS41::CB_SEQUENCE4resok*);
bool_t xdr_CB_SEQUENCE4res (XDR *, NFS41::CB_SEQUENCE4res*);
bool_t xdr_CB_WANTS_CANCELLED4args (XDR *, NFS41::CB_WANTS_CANCELLED4args*);
bool_t xdr_CB_WANTS_CANCELLED4res (XDR *, NFS41::CB_WANTS_CANCELLED4res*);
bool_t xdr_CB_NOTIFY_LOCK4args (XDR *, NFS41::CB_NOTIFY_LOCK4args*);
bool_t xdr_CB_NOTIFY_LOCK4res (XDR *, NFS41::CB_NOTIFY_LOCK4res*);
bool_t xdr_notify_deviceid_type4 (XDR *, NFS41::notify_deviceid_type4*);
bool_t xdr_notify_deviceid_delete4 (XDR *, NFS41::notify_deviceid_delete4*);
bool_t xdr_notify_deviceid_change4 (XDR *, NFS41::notify_deviceid_change4*);
bool_t xdr_CB_NOTIFY_DEVICEID4args (XDR *, NFS41::CB_NOTIFY_DEVICEID4args*);
bool_t xdr_CB_NOTIFY_DEVICEID4res (XDR *, NFS41::CB_NOTIFY_DEVICEID4res*);
bool_t xdr_nfs_cb_opnum4 (XDR *, NFS41::nfs_cb_opnum4*);
bool_t xdr_nfs_cb_argop4 (XDR *, NFS41::nfs_cb_argop4*);
bool_t xdr_nfs_cb_resop4 (XDR *, NFS41::nfs_cb_resop4*);
bool_t xdr_CB_COMPOUND4args (XDR *, NFS41::CB_COMPOUND4args*);
bool_t xdr_CB_COMPOUND4res (XDR *, NFS41::CB_COMPOUND4res*);
// clang-format on

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(NFS41::NULL4args&) -> decltype(&xdr_NULL4args)
{
    return xdr_NULL4args;
}

inline auto proc_t_of(NFS41::NULL4res&) -> decltype(&xdr_NULL4res)
{
    return &xdr_NULL4res;
}

// Procedure 1: COMPOUND
inline auto proc_t_of(NFS41::COMPOUND4args&) -> decltype(&xdr_COMPOUND4args)
{
    return &xdr_COMPOUND4args;
}

inline auto proc_t_of(NFS41::COMPOUND4res&) -> decltype(&xdr_COMPOUND4res)
{
    return &xdr_COMPOUND4res;
}

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
#endif // NFS41_UTILS_H
//------------------------------------------------------------------------------
