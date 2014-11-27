//------------------------------------------------------------------------------
// Author: Alexey Costroma 
// Description: Definition and fill up NFSv4 procedures.
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
#include "api/nfs4_types_rpcgen.h"
//------------------------------------------------------------------------------
namespace rpcgen
{

bool_t
xdr_int32_t (XDR *xdrs, int32_t *objp)
{
     if (!xdr_int (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_uint32_t (XDR *xdrs, uint32_t *objp)
{
     if (!xdr_u_int (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_int64_t (XDR *xdrs, int64_t *objp)
{
     if (!xdr_longlong_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_uint64_t (XDR *xdrs, uint64_t *objp)
{
     if (!xdr_u_longlong_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_ftype4 (XDR *xdrs, nfs_ftype4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfsstat4 (XDR *xdrs, nfsstat4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_bitmap4 (XDR *xdrs, bitmap4 *objp)
{
     if (!xdr_array (xdrs, (char **)&objp->bitmap4_val, (u_int *) &objp->bitmap4_len, ~0,
        sizeof (uint32_t), (xdrproc_t) xdr_uint32_t))
         return FALSE;
    return TRUE;
}

bool_t
xdr_offset4 (XDR *xdrs, offset4 *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_count4 (XDR *xdrs, count4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_length4 (XDR *xdrs, length4 *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_clientid4 (XDR *xdrs, clientid4 *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_seqid4 (XDR *xdrs, seqid4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_utf8string (XDR *xdrs, utf8string *objp)
{
     if (!xdr_bytes (xdrs, (char **)&objp->utf8string_val, (u_int *) &objp->utf8string_len, ~0))
         return FALSE;
    return TRUE;
}

bool_t
xdr_utf8str_cis (XDR *xdrs, utf8str_cis *objp)
{
     if (!xdr_utf8string (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_utf8str_cs (XDR *xdrs, utf8str_cs *objp)
{
     if (!xdr_utf8string (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_utf8str_mixed (XDR *xdrs, utf8str_mixed *objp)
{
     if (!xdr_utf8string (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_component4 (XDR *xdrs, component4 *objp)
{
     if (!xdr_utf8str_cs (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_pathname4 (XDR *xdrs, pathname4 *objp)
{
     if (!xdr_array (xdrs, (char **)&objp->pathname4_val, (u_int *) &objp->pathname4_len, ~0,
        sizeof (component4), (xdrproc_t) xdr_component4))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_lockid4 (XDR *xdrs, nfs_lockid4 *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_cookie4 (XDR *xdrs, nfs_cookie4 *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_linktext4 (XDR *xdrs, linktext4 *objp)
{
     if (!xdr_utf8str_cs (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_sec_oid4 (XDR *xdrs, sec_oid4 *objp)
{
     if (!xdr_bytes (xdrs, (char **)&objp->sec_oid4_val, (u_int *) &objp->sec_oid4_len, ~0))
         return FALSE;
    return TRUE;
}

bool_t
xdr_qop4 (XDR *xdrs, qop4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_mode4 (XDR *xdrs, mode4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_changeid4 (XDR *xdrs, changeid4 *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_verifier4 (XDR *xdrs, verifier4 objp)
{
     if (!xdr_opaque (xdrs, objp, NFS4_VERIFIER_SIZE))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfstime4 (XDR *xdrs, nfstime4 *objp)
{
     if (!rpcgen::xdr_int64_t (xdrs, &objp->seconds))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->nseconds))
         return FALSE;
    return TRUE;
}

bool_t
xdr_time_how4 (XDR *xdrs, time_how4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_settime4 (XDR *xdrs, settime4 *objp)
{
     if (!xdr_time_how4 (xdrs, &objp->set_it))
         return FALSE;
    switch (objp->set_it) {
    case SET_TO_CLIENT_TIME4:
         if (!xdr_nfstime4 (xdrs, &objp->settime4_u.time))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_nfs_fh4 (XDR *xdrs, nfs_fh4 *objp)
{
     if (!xdr_bytes (xdrs, (char **)&objp->nfs_fh4_val, (u_int *) &objp->nfs_fh4_len, NFS4_FHSIZE))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fsid4 (XDR *xdrs, fsid4 *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, &objp->major))
         return FALSE;
     if (!rpcgen::xdr_uint64_t (xdrs, &objp->minor))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fs_location4 (XDR *xdrs, fs_location4 *objp)
{
     if (!xdr_array (xdrs, (char **)&objp->server.server_val, (u_int *) &objp->server.server_len, ~0,
        sizeof (utf8str_cis), (xdrproc_t) xdr_utf8str_cis))
         return FALSE;
     if (!xdr_pathname4 (xdrs, &objp->rootpath))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fs_locations4 (XDR *xdrs, fs_locations4 *objp)
{
     if (!xdr_pathname4 (xdrs, &objp->fs_root))
         return FALSE;
     if (!xdr_array (xdrs, (char **)&objp->locations.locations_val, (u_int *) &objp->locations.locations_len, ~0,
        sizeof (fs_location4), (xdrproc_t) xdr_fs_location4))
         return FALSE;
    return TRUE;
}

bool_t
xdr_acetype4 (XDR *xdrs, acetype4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_aceflag4 (XDR *xdrs, aceflag4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_acemask4 (XDR *xdrs, acemask4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfsace4 (XDR *xdrs, nfsace4 *objp)
{
     if (!xdr_acetype4 (xdrs, &objp->type))
         return FALSE;
     if (!xdr_aceflag4 (xdrs, &objp->flag))
         return FALSE;
     if (!xdr_acemask4 (xdrs, &objp->access_mask))
         return FALSE;
     if (!xdr_utf8str_mixed (xdrs, &objp->who))
         return FALSE;
    return TRUE;
}

bool_t
xdr_specdata4 (XDR *xdrs, specdata4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->specdata1))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->specdata2))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_supported_attrs (XDR *xdrs, fattr4_supported_attrs *objp)
{
     if (!xdr_bitmap4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_type (XDR *xdrs, fattr4_type *objp)
{
     if (!xdr_nfs_ftype4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_fh_expire_type (XDR *xdrs, fattr4_fh_expire_type *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_change (XDR *xdrs, fattr4_change *objp)
{
     if (!xdr_changeid4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_size (XDR *xdrs, fattr4_size *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_link_support (XDR *xdrs, fattr4_link_support *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_symlink_support (XDR *xdrs, fattr4_symlink_support *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_named_attr (XDR *xdrs, fattr4_named_attr *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_fsid (XDR *xdrs, fattr4_fsid *objp)
{
     if (!xdr_fsid4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_unique_handles (XDR *xdrs, fattr4_unique_handles *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_lease_time (XDR *xdrs, fattr4_lease_time *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_rdattr_error (XDR *xdrs, fattr4_rdattr_error *objp)
{
     if (!xdr_nfsstat4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_acl (XDR *xdrs, fattr4_acl *objp)
{
     if (!xdr_array (xdrs, (char **)&objp->fattr4_acl_val, (u_int *) &objp->fattr4_acl_len, ~0,
        sizeof (nfsace4), (xdrproc_t) xdr_nfsace4))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_aclsupport (XDR *xdrs, fattr4_aclsupport *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_archive (XDR *xdrs, fattr4_archive *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_cansettime (XDR *xdrs, fattr4_cansettime *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_case_insensitive (XDR *xdrs, fattr4_case_insensitive *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_case_preserving (XDR *xdrs, fattr4_case_preserving *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_chown_restricted (XDR *xdrs, fattr4_chown_restricted *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_fileid (XDR *xdrs, fattr4_fileid *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_files_avail (XDR *xdrs, fattr4_files_avail *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_filehandle (XDR *xdrs, fattr4_filehandle *objp)
{
     if (!xdr_nfs_fh4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_files_free (XDR *xdrs, fattr4_files_free *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_files_total (XDR *xdrs, fattr4_files_total *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_fs_locations (XDR *xdrs, fattr4_fs_locations *objp)
{
     if (!xdr_fs_locations4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_hidden (XDR *xdrs, fattr4_hidden *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_homogeneous (XDR *xdrs, fattr4_homogeneous *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_maxfilesize (XDR *xdrs, fattr4_maxfilesize *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_maxlink (XDR *xdrs, fattr4_maxlink *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_maxname (XDR *xdrs, fattr4_maxname *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_maxread (XDR *xdrs, fattr4_maxread *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_maxwrite (XDR *xdrs, fattr4_maxwrite *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_mimetype (XDR *xdrs, fattr4_mimetype *objp)
{
     if (!xdr_utf8str_cs (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_mode (XDR *xdrs, fattr4_mode *objp)
{
     if (!xdr_mode4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_mounted_on_fileid (XDR *xdrs, fattr4_mounted_on_fileid *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_no_trunc (XDR *xdrs, fattr4_no_trunc *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_numlinks (XDR *xdrs, fattr4_numlinks *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_owner (XDR *xdrs, fattr4_owner *objp)
{
     if (!xdr_utf8str_mixed (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_owner_group (XDR *xdrs, fattr4_owner_group *objp)
{
     if (!xdr_utf8str_mixed (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_quota_avail_hard (XDR *xdrs, fattr4_quota_avail_hard *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_quota_avail_soft (XDR *xdrs, fattr4_quota_avail_soft *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_quota_used (XDR *xdrs, fattr4_quota_used *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_rawdev (XDR *xdrs, fattr4_rawdev *objp)
{
     if (!xdr_specdata4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_space_avail (XDR *xdrs, fattr4_space_avail *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_space_free (XDR *xdrs, fattr4_space_free *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_space_total (XDR *xdrs, fattr4_space_total *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_space_used (XDR *xdrs, fattr4_space_used *objp)
{
     if (!rpcgen::xdr_uint64_t (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_system (XDR *xdrs, fattr4_system *objp)
{
     if (!xdr_bool (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_time_access (XDR *xdrs, fattr4_time_access *objp)
{
     if (!xdr_nfstime4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_time_access_set (XDR *xdrs, fattr4_time_access_set *objp)
{
     if (!xdr_settime4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_time_backup (XDR *xdrs, fattr4_time_backup *objp)
{
     if (!xdr_nfstime4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_time_create (XDR *xdrs, fattr4_time_create *objp)
{
     if (!xdr_nfstime4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_time_delta (XDR *xdrs, fattr4_time_delta *objp)
{
     if (!xdr_nfstime4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_time_metadata (XDR *xdrs, fattr4_time_metadata *objp)
{
     if (!xdr_nfstime4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_time_modify (XDR *xdrs, fattr4_time_modify *objp)
{
     if (!xdr_nfstime4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4_time_modify_set (XDR *xdrs, fattr4_time_modify_set *objp)
{
     if (!xdr_settime4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_attrlist4 (XDR *xdrs, attrlist4 *objp)
{
     if (!xdr_bytes (xdrs, (char **)&objp->attrlist4_val, (u_int *) &objp->attrlist4_len, ~0))
         return FALSE;
    return TRUE;
}

bool_t
xdr_fattr4 (XDR *xdrs, fattr4 *objp)
{
     if (!xdr_bitmap4 (xdrs, &objp->attrmask))
         return FALSE;
     if (!xdr_attrlist4 (xdrs, &objp->attr_vals))
         return FALSE;
    return TRUE;
}

bool_t
xdr_change_info4 (XDR *xdrs, change_info4 *objp)
{
     if (!xdr_bool (xdrs, &objp->atomic))
         return FALSE;
     if (!xdr_changeid4 (xdrs, &objp->before))
         return FALSE;
     if (!xdr_changeid4 (xdrs, &objp->after))
         return FALSE;
    return TRUE;
}

bool_t
xdr_clientaddr4 (XDR *xdrs, clientaddr4 *objp)
{
     if (!xdr_string (xdrs, &objp->r_netid, ~0))
         return FALSE;
     if (!xdr_string (xdrs, &objp->r_addr, ~0))
         return FALSE;
    return TRUE;
}

bool_t
xdr_cb_client4 (XDR *xdrs, cb_client4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->cb_program))
         return FALSE;
     if (!xdr_clientaddr4 (xdrs, &objp->cb_location))
         return FALSE;
    return TRUE;
}

bool_t
xdr_stateid4 (XDR *xdrs, stateid4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->seqid))
         return FALSE;
     if (!xdr_opaque (xdrs, objp->other, 12))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_client_id4 (XDR *xdrs, nfs_client_id4 *objp)
{
     if (!xdr_verifier4 (xdrs, objp->verifier))
         return FALSE;
     if (!xdr_bytes (xdrs, (char **)&objp->id.id_val, (u_int *) &objp->id.id_len, NFS4_OPAQUE_LIMIT))
         return FALSE;
    return TRUE;
}

bool_t
xdr_open_owner4 (XDR *xdrs, open_owner4 *objp)
{
     if (!xdr_clientid4 (xdrs, &objp->clientid))
         return FALSE;
     if (!xdr_bytes (xdrs, (char **)&objp->owner.owner_val, (u_int *) &objp->owner.owner_len, NFS4_OPAQUE_LIMIT))
         return FALSE;
    return TRUE;
}

bool_t
xdr_lock_owner4 (XDR *xdrs, lock_owner4 *objp)
{
     if (!xdr_clientid4 (xdrs, &objp->clientid))
         return FALSE;
     if (!xdr_bytes (xdrs, (char **)&objp->owner.owner_val, (u_int *) &objp->owner.owner_len, NFS4_OPAQUE_LIMIT))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_lock_type4 (XDR *xdrs, nfs_lock_type4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

//for compatibility
bool_t
xdr_NULL4args(XDR*, NULL4args*)
{
    return TRUE;
}

bool_t
xdr_NULL4res(XDR*, NULL4res*)
{
    return TRUE;
}

bool_t
xdr_ACCESS4args (XDR *xdrs, ACCESS4args *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->access))
         return FALSE;
    return TRUE;
}

bool_t
xdr_ACCESS4resok (XDR *xdrs, ACCESS4resok *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->supported))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->access))
         return FALSE;
    return TRUE;
}

bool_t
xdr_ACCESS4res (XDR *xdrs, ACCESS4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_ACCESS4resok (xdrs, &objp->ACCESS4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_CLOSE4args (XDR *xdrs, CLOSE4args *objp)
{
     if (!xdr_seqid4 (xdrs, &objp->seqid))
         return FALSE;
     if (!xdr_stateid4 (xdrs, &objp->open_stateid))
         return FALSE;
    return TRUE;
}

bool_t
xdr_CLOSE4res (XDR *xdrs, CLOSE4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_stateid4 (xdrs, &objp->CLOSE4res_u.open_stateid))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_COMMIT4args (XDR *xdrs, COMMIT4args *objp)
{
     if (!xdr_offset4 (xdrs, &objp->offset))
         return FALSE;
     if (!xdr_count4 (xdrs, &objp->count))
         return FALSE;
    return TRUE;
}

bool_t
xdr_COMMIT4resok (XDR *xdrs, COMMIT4resok *objp)
{
     if (!xdr_verifier4 (xdrs, objp->writeverf))
         return FALSE;
    return TRUE;
}

bool_t
xdr_COMMIT4res (XDR *xdrs, COMMIT4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_COMMIT4resok (xdrs, &objp->COMMIT4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_createtype4 (XDR *xdrs, createtype4 *objp)
{
     if (!xdr_nfs_ftype4 (xdrs, &objp->type))
         return FALSE;
    switch (objp->type) {
    case NF4LNK:
         if (!xdr_linktext4 (xdrs, &objp->createtype4_u.linkdata))
             return FALSE;
        break;
    case NF4BLK:
    case NF4CHR:
         if (!xdr_specdata4 (xdrs, &objp->createtype4_u.devdata))
             return FALSE;
        break;
    case NF4SOCK:
    case NF4FIFO:
    case NF4DIR:
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_CREATE4args (XDR *xdrs, CREATE4args *objp)
{
     if (!xdr_createtype4 (xdrs, &objp->objtype))
         return FALSE;
     if (!xdr_component4 (xdrs, &objp->objname))
         return FALSE;
     if (!xdr_fattr4 (xdrs, &objp->createattrs))
         return FALSE;
    return TRUE;
}

bool_t
xdr_CREATE4resok (XDR *xdrs, CREATE4resok *objp)
{
     if (!xdr_change_info4 (xdrs, &objp->cinfo))
         return FALSE;
     if (!xdr_bitmap4 (xdrs, &objp->attrset))
         return FALSE;
    return TRUE;
}

bool_t
xdr_CREATE4res (XDR *xdrs, CREATE4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_CREATE4resok (xdrs, &objp->CREATE4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_DELEGPURGE4args (XDR *xdrs, DELEGPURGE4args *objp)
{
     if (!xdr_clientid4 (xdrs, &objp->clientid))
         return FALSE;
    return TRUE;
}

bool_t
xdr_DELEGPURGE4res (XDR *xdrs, DELEGPURGE4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_DELEGRETURN4args (XDR *xdrs, DELEGRETURN4args *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->deleg_stateid))
         return FALSE;
    return TRUE;
}

bool_t
xdr_DELEGRETURN4res (XDR *xdrs, DELEGRETURN4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_GETATTR4args (XDR *xdrs, GETATTR4args *objp)
{
     if (!xdr_bitmap4 (xdrs, &objp->attr_request))
         return FALSE;
    return TRUE;
}

bool_t
xdr_GETATTR4resok (XDR *xdrs, GETATTR4resok *objp)
{
     if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
         return FALSE;
    return TRUE;
}

bool_t
xdr_GETATTR4res (XDR *xdrs, GETATTR4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_GETATTR4resok (xdrs, &objp->GETATTR4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_notification_types4 (XDR *xdrs, notification_types4 *objp)
{
     if (!xdr_bitmap4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_notification_delay4 (XDR *xdrs, notification_delay4 *objp)
{
     if (!xdr_nfstime4 (xdrs, objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_dir_delegation_status4 (XDR *xdrs, dir_delegation_status4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_GET_DIR_DELEGATION4args (XDR *xdrs, GET_DIR_DELEGATION4args *objp)
{
     if (!xdr_clientid4 (xdrs, &objp->clientid))
         return FALSE;
     if (!xdr_notification_types4 (xdrs, &objp->notif_types))
         return FALSE;
     if (!xdr_notification_delay4 (xdrs, &objp->dir_notif_delay))
         return FALSE;
     if (!xdr_notification_delay4 (xdrs, &objp->dir_entry_notif_delay))
         return FALSE;
    return TRUE;
}

bool_t
xdr_GET_DIR_DELEGATION4resok (XDR *xdrs, GET_DIR_DELEGATION4resok *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->stateid))
         return FALSE;
     if (!xdr_dir_delegation_status4 (xdrs, &objp->status))
         return FALSE;
     if (!xdr_notification_types4 (xdrs, &objp->notif_types))
         return FALSE;
     if (!xdr_bitmap4 (xdrs, &objp->dir_notif_attrs))
         return FALSE;
     if (!xdr_bitmap4 (xdrs, &objp->dir_entry_notif_attrs))
         return FALSE;
    return TRUE;
}

bool_t
xdr_GET_DIR_DELEGATION4res (XDR *xdrs, GET_DIR_DELEGATION4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_GET_DIR_DELEGATION4resok (xdrs, &objp->GET_DIR_DELEGATION4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_GETFH4resok (XDR *xdrs, GETFH4resok *objp)
{
     if (!xdr_nfs_fh4 (xdrs, &objp->object))
         return FALSE;
    return TRUE;
}

bool_t
xdr_GETFH4res (XDR *xdrs, GETFH4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_GETFH4resok (xdrs, &objp->GETFH4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LINK4args (XDR *xdrs, LINK4args *objp)
{
     if (!xdr_component4 (xdrs, &objp->newname))
         return FALSE;
    return TRUE;
}

bool_t
xdr_LINK4resok (XDR *xdrs, LINK4resok *objp)
{
     if (!xdr_change_info4 (xdrs, &objp->cinfo))
         return FALSE;
    return TRUE;
}

bool_t
xdr_LINK4res (XDR *xdrs, LINK4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_LINK4resok (xdrs, &objp->LINK4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_open_to_lock_owner4 (XDR *xdrs, open_to_lock_owner4 *objp)
{
     if (!xdr_seqid4 (xdrs, &objp->open_seqid))
         return FALSE;
     if (!xdr_stateid4 (xdrs, &objp->open_stateid))
         return FALSE;
     if (!xdr_seqid4 (xdrs, &objp->lock_seqid))
         return FALSE;
     if (!xdr_lock_owner4 (xdrs, &objp->lock_owner))
         return FALSE;
    return TRUE;
}

bool_t
xdr_exist_lock_owner4 (XDR *xdrs, exist_lock_owner4 *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->lock_stateid))
         return FALSE;
     if (!xdr_seqid4 (xdrs, &objp->lock_seqid))
         return FALSE;
    return TRUE;
}

bool_t
xdr_locker4 (XDR *xdrs, locker4 *objp)
{
     if (!xdr_bool (xdrs, &objp->new_lock_owner))
         return FALSE;
    switch (objp->new_lock_owner) {
    case TRUE:
         if (!xdr_open_to_lock_owner4 (xdrs, &objp->locker4_u.open_owner))
             return FALSE;
        break;
    case FALSE:
         if (!xdr_exist_lock_owner4 (xdrs, &objp->locker4_u.lock_owner))
             return FALSE;
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOCK4args (XDR *xdrs, LOCK4args *objp)
{
     if (!xdr_nfs_lock_type4 (xdrs, &objp->locktype))
         return FALSE;
     if (!xdr_bool (xdrs, &objp->reclaim))
         return FALSE;
     if (!xdr_offset4 (xdrs, &objp->offset))
         return FALSE;
     if (!xdr_length4 (xdrs, &objp->length))
         return FALSE;
     if (!xdr_locker4 (xdrs, &objp->locker))
         return FALSE;
    return TRUE;
}

bool_t
xdr_LOCK4denied (XDR *xdrs, LOCK4denied *objp)
{
     if (!xdr_offset4 (xdrs, &objp->offset))
         return FALSE;
     if (!xdr_length4 (xdrs, &objp->length))
         return FALSE;
     if (!xdr_nfs_lock_type4 (xdrs, &objp->locktype))
         return FALSE;
     if (!xdr_lock_owner4 (xdrs, &objp->owner))
         return FALSE;
    return TRUE;
}

bool_t
xdr_LOCK4resok (XDR *xdrs, LOCK4resok *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->lock_stateid))
         return FALSE;
    return TRUE;
}

bool_t
xdr_LOCK4res (XDR *xdrs, LOCK4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_LOCK4resok (xdrs, &objp->LOCK4res_u.resok4))
             return FALSE;
        break;
    case NFS4ERR_DENIED:
         if (!xdr_LOCK4denied (xdrs, &objp->LOCK4res_u.denied))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LOCKT4args (XDR *xdrs, LOCKT4args *objp)
{
     if (!xdr_nfs_lock_type4 (xdrs, &objp->locktype))
         return FALSE;
     if (!xdr_offset4 (xdrs, &objp->offset))
         return FALSE;
     if (!xdr_length4 (xdrs, &objp->length))
         return FALSE;
     if (!xdr_lock_owner4 (xdrs, &objp->owner))
         return FALSE;
    return TRUE;
}

bool_t
xdr_LOCKT4res (XDR *xdrs, LOCKT4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4ERR_DENIED:
         if (!xdr_LOCK4denied (xdrs, &objp->LOCKT4res_u.denied))
             return FALSE;
        break;
    case NFS4_OK:
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LOCKU4args (XDR *xdrs, LOCKU4args *objp)
{
     if (!xdr_nfs_lock_type4 (xdrs, &objp->locktype))
         return FALSE;
     if (!xdr_seqid4 (xdrs, &objp->seqid))
         return FALSE;
     if (!xdr_stateid4 (xdrs, &objp->lock_stateid))
         return FALSE;
     if (!xdr_offset4 (xdrs, &objp->offset))
         return FALSE;
     if (!xdr_length4 (xdrs, &objp->length))
         return FALSE;
    return TRUE;
}

bool_t
xdr_LOCKU4res (XDR *xdrs, LOCKU4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_stateid4 (xdrs, &objp->LOCKU4res_u.lock_stateid))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LOOKUP4args (XDR *xdrs, LOOKUP4args *objp)
{
     if (!xdr_component4 (xdrs, &objp->objname))
         return FALSE;
    return TRUE;
}

bool_t
xdr_LOOKUP4res (XDR *xdrs, LOOKUP4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_LOOKUPP4res (XDR *xdrs, LOOKUPP4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_NVERIFY4args (XDR *xdrs, NVERIFY4args *objp)
{
     if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
         return FALSE;
    return TRUE;
}

bool_t
xdr_NVERIFY4res (XDR *xdrs, NVERIFY4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_createmode4 (XDR *xdrs, createmode4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_createhow4 (XDR *xdrs, createhow4 *objp)
{
     if (!xdr_createmode4 (xdrs, &objp->mode))
         return FALSE;
    switch (objp->mode) {
    case UNCHECKED4:
    case GUARDED4:
         if (!xdr_fattr4 (xdrs, &objp->createhow4_u.createattrs))
             return FALSE;
        break;
    case EXCLUSIVE4:
         if (!xdr_verifier4 (xdrs, objp->createhow4_u.createverf))
             return FALSE;
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_opentype4 (XDR *xdrs, opentype4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_openflag4 (XDR *xdrs, openflag4 *objp)
{
     if (!xdr_opentype4 (xdrs, &objp->opentype))
         return FALSE;
    switch (objp->opentype) {
    case OPEN4_CREATE:
         if (!xdr_createhow4 (xdrs, &objp->openflag4_u.how))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_limit_by4 (XDR *xdrs, limit_by4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_modified_limit4 (XDR *xdrs, nfs_modified_limit4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->num_blocks))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->bytes_per_block))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_space_limit4 (XDR *xdrs, nfs_space_limit4 *objp)
{
     if (!xdr_limit_by4 (xdrs, &objp->limitby))
         return FALSE;
    switch (objp->limitby) {
    case NFS_LIMIT_SIZE:
         if (!rpcgen::xdr_uint64_t (xdrs, &objp->nfs_space_limit4_u.filesize))
             return FALSE;
        break;
    case NFS_LIMIT_BLOCKS:
         if (!xdr_nfs_modified_limit4 (xdrs, &objp->nfs_space_limit4_u.mod_blocks))
             return FALSE;
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_open_delegation_type4 (XDR *xdrs, open_delegation_type4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_open_claim_type4 (XDR *xdrs, open_claim_type4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_open_claim_delegate_cur4 (XDR *xdrs, open_claim_delegate_cur4 *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->delegate_stateid))
         return FALSE;
     if (!xdr_component4 (xdrs, &objp->file))
         return FALSE;
    return TRUE;
}

bool_t
xdr_open_claim4 (XDR *xdrs, open_claim4 *objp)
{
     if (!xdr_open_claim_type4 (xdrs, &objp->claim))
         return FALSE;
    switch (objp->claim) {
    case CLAIM_NULL:
         if (!xdr_component4 (xdrs, &objp->open_claim4_u.file))
             return FALSE;
        break;
    case CLAIM_PREVIOUS:
         if (!xdr_open_delegation_type4 (xdrs, &objp->open_claim4_u.delegate_type))
             return FALSE;
        break;
    case CLAIM_DELEGATE_CUR:
         if (!xdr_open_claim_delegate_cur4 (xdrs, &objp->open_claim4_u.delegate_cur_info))
             return FALSE;
        break;
    case CLAIM_DELEGATE_PREV:
         if (!xdr_component4 (xdrs, &objp->open_claim4_u.file_delegate_prev))
             return FALSE;
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN4args (XDR *xdrs, OPEN4args *objp)
{
     if (!xdr_seqid4 (xdrs, &objp->seqid))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->share_access))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->share_deny))
         return FALSE;
     if (!xdr_open_owner4 (xdrs, &objp->owner))
         return FALSE;
     if (!xdr_openflag4 (xdrs, &objp->openhow))
         return FALSE;
     if (!xdr_open_claim4 (xdrs, &objp->claim))
         return FALSE;
    return TRUE;
}

bool_t
xdr_open_read_delegation4 (XDR *xdrs, open_read_delegation4 *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->stateid))
         return FALSE;
     if (!xdr_bool (xdrs, &objp->recall))
         return FALSE;
     if (!xdr_nfsace4 (xdrs, &objp->permissions))
         return FALSE;
    return TRUE;
}

bool_t
xdr_open_write_delegation4 (XDR *xdrs, open_write_delegation4 *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->stateid))
         return FALSE;
     if (!xdr_bool (xdrs, &objp->recall))
         return FALSE;
     if (!xdr_nfs_space_limit4 (xdrs, &objp->space_limit))
         return FALSE;
     if (!xdr_nfsace4 (xdrs, &objp->permissions))
         return FALSE;
    return TRUE;
}

bool_t
xdr_open_delegation4 (XDR *xdrs, open_delegation4 *objp)
{
     if (!xdr_open_delegation_type4 (xdrs, &objp->delegation_type))
         return FALSE;
    switch (objp->delegation_type) {
    case OPEN_DELEGATE_NONE:
        break;
    case OPEN_DELEGATE_READ:
         if (!xdr_open_read_delegation4 (xdrs, &objp->open_delegation4_u.read))
             return FALSE;
        break;
    case OPEN_DELEGATE_WRITE:
         if (!xdr_open_write_delegation4 (xdrs, &objp->open_delegation4_u.write))
             return FALSE;
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN4resok (XDR *xdrs, OPEN4resok *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->stateid))
         return FALSE;
     if (!xdr_change_info4 (xdrs, &objp->cinfo))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->rflags))
         return FALSE;
     if (!xdr_bitmap4 (xdrs, &objp->attrset))
         return FALSE;
     if (!xdr_open_delegation4 (xdrs, &objp->delegation))
         return FALSE;
    return TRUE;
}

bool_t
xdr_OPEN4res (XDR *xdrs, OPEN4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_OPEN4resok (xdrs, &objp->OPEN4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_OPENATTR4args (XDR *xdrs, OPENATTR4args *objp)
{
     if (!xdr_bool (xdrs, &objp->createdir))
         return FALSE;
    return TRUE;
}

bool_t
xdr_OPENATTR4res (XDR *xdrs, OPENATTR4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_OPEN_CONFIRM4args (XDR *xdrs, OPEN_CONFIRM4args *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->open_stateid))
         return FALSE;
     if (!xdr_seqid4 (xdrs, &objp->seqid))
         return FALSE;
    return TRUE;
}

bool_t
xdr_OPEN_CONFIRM4resok (XDR *xdrs, OPEN_CONFIRM4resok *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->open_stateid))
         return FALSE;
    return TRUE;
}

bool_t
xdr_OPEN_CONFIRM4res (XDR *xdrs, OPEN_CONFIRM4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_OPEN_CONFIRM4resok (xdrs, &objp->OPEN_CONFIRM4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_OPEN_DOWNGRADE4args (XDR *xdrs, OPEN_DOWNGRADE4args *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->open_stateid))
         return FALSE;
     if (!xdr_seqid4 (xdrs, &objp->seqid))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->share_access))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->share_deny))
         return FALSE;
    return TRUE;
}

bool_t
xdr_OPEN_DOWNGRADE4resok (XDR *xdrs, OPEN_DOWNGRADE4resok *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->open_stateid))
         return FALSE;
    return TRUE;
}

bool_t
xdr_OPEN_DOWNGRADE4res (XDR *xdrs, OPEN_DOWNGRADE4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_OPEN_DOWNGRADE4resok (xdrs, &objp->OPEN_DOWNGRADE4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_PUTFH4args (XDR *xdrs, PUTFH4args *objp)
{
     if (!xdr_nfs_fh4 (xdrs, &objp->object))
         return FALSE;
    return TRUE;
}

bool_t
xdr_PUTFH4res (XDR *xdrs, PUTFH4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_PUTPUBFH4res (XDR *xdrs, PUTPUBFH4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_PUTROOTFH4res (XDR *xdrs, PUTROOTFH4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_READ4args (XDR *xdrs, READ4args *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->stateid))
         return FALSE;
     if (!xdr_offset4 (xdrs, &objp->offset))
         return FALSE;
     if (!xdr_count4 (xdrs, &objp->count))
         return FALSE;
    return TRUE;
}

bool_t
xdr_READ4resok (XDR *xdrs, READ4resok *objp)
{
     if (!xdr_bool (xdrs, &objp->eof))
         return FALSE;
     if (!xdr_bytes (xdrs, (char **)&objp->data.data_val, (u_int *) &objp->data.data_len, ~0))
         return FALSE;
    return TRUE;
}

bool_t
xdr_READ4res (XDR *xdrs, READ4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_READ4resok (xdrs, &objp->READ4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_READDIR4args (XDR *xdrs, READDIR4args *objp)
{
     if (!xdr_nfs_cookie4 (xdrs, &objp->cookie))
         return FALSE;
     if (!xdr_verifier4 (xdrs, objp->cookieverf))
         return FALSE;
     if (!xdr_count4 (xdrs, &objp->dircount))
         return FALSE;
     if (!xdr_count4 (xdrs, &objp->maxcount))
         return FALSE;
     if (!xdr_bitmap4 (xdrs, &objp->attr_request))
         return FALSE;
    return TRUE;
}

bool_t
xdr_entry4 (XDR *xdrs, entry4 *objp)
{
     if (!xdr_nfs_cookie4 (xdrs, &objp->cookie))
         return FALSE;
     if (!xdr_component4 (xdrs, &objp->name))
         return FALSE;
     if (!xdr_fattr4 (xdrs, &objp->attrs))
         return FALSE;
     if (!xdr_pointer (xdrs, (char **)&objp->nextentry, sizeof (entry4), (xdrproc_t) xdr_entry4))
         return FALSE;
    return TRUE;
}

bool_t
xdr_dirlist4 (XDR *xdrs, dirlist4 *objp)
{
     if (!xdr_pointer (xdrs, (char **)&objp->entries, sizeof (entry4), (xdrproc_t) xdr_entry4))
         return FALSE;
     if (!xdr_bool (xdrs, &objp->eof))
         return FALSE;
    return TRUE;
}

bool_t
xdr_READDIR4resok (XDR *xdrs, READDIR4resok *objp)
{
     if (!xdr_verifier4 (xdrs, objp->cookieverf))
         return FALSE;
     if (!xdr_dirlist4 (xdrs, &objp->reply))
         return FALSE;
    return TRUE;
}

bool_t
xdr_READDIR4res (XDR *xdrs, READDIR4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_READDIR4resok (xdrs, &objp->READDIR4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_READLINK4resok (XDR *xdrs, READLINK4resok *objp)
{
     if (!xdr_linktext4 (xdrs, &objp->link))
         return FALSE;
    return TRUE;
}

bool_t
xdr_READLINK4res (XDR *xdrs, READLINK4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_READLINK4resok (xdrs, &objp->READLINK4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_REMOVE4args (XDR *xdrs, REMOVE4args *objp)
{
     if (!xdr_component4 (xdrs, &objp->target))
         return FALSE;
    return TRUE;
}

bool_t
xdr_REMOVE4resok (XDR *xdrs, REMOVE4resok *objp)
{
     if (!xdr_change_info4 (xdrs, &objp->cinfo))
         return FALSE;
    return TRUE;
}

bool_t
xdr_REMOVE4res (XDR *xdrs, REMOVE4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_REMOVE4resok (xdrs, &objp->REMOVE4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_RENAME4args (XDR *xdrs, RENAME4args *objp)
{
     if (!xdr_component4 (xdrs, &objp->oldname))
         return FALSE;
     if (!xdr_component4 (xdrs, &objp->newname))
         return FALSE;
    return TRUE;
}

bool_t
xdr_RENAME4resok (XDR *xdrs, RENAME4resok *objp)
{
     if (!xdr_change_info4 (xdrs, &objp->source_cinfo))
         return FALSE;
     if (!xdr_change_info4 (xdrs, &objp->target_cinfo))
         return FALSE;
    return TRUE;
}

bool_t
xdr_RENAME4res (XDR *xdrs, RENAME4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_RENAME4resok (xdrs, &objp->RENAME4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_RENEW4args (XDR *xdrs, RENEW4args *objp)
{
     if (!xdr_clientid4 (xdrs, &objp->clientid))
         return FALSE;
    return TRUE;
}

bool_t
xdr_RENEW4res (XDR *xdrs, RENEW4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_RESTOREFH4res (XDR *xdrs, RESTOREFH4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_SAVEFH4res (XDR *xdrs, SAVEFH4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_SECINFO4args (XDR *xdrs, SECINFO4args *objp)
{
     if (!xdr_component4 (xdrs, &objp->name))
         return FALSE;
    return TRUE;
}

bool_t
xdr_rpc_gss_svc_t (XDR *xdrs, rpc_gss_svc_t *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_rpcsec_gss_info (XDR *xdrs, rpcsec_gss_info *objp)
{
     if (!xdr_sec_oid4 (xdrs, &objp->oid))
         return FALSE;
     if (!xdr_qop4 (xdrs, &objp->qop))
         return FALSE;
     if (!xdr_rpc_gss_svc_t (xdrs, &objp->service))
         return FALSE;
    return TRUE;
}

bool_t
xdr_secinfo4 (XDR *xdrs, secinfo4 *objp)
{
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->flavor))
         return FALSE;
    switch (objp->flavor) {
    case RPCSEC_GSS:
         if (!xdr_rpcsec_gss_info (xdrs, &objp->secinfo4_u.flavor_info))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_SECINFO4resok (XDR *xdrs, SECINFO4resok *objp)
{
     if (!xdr_array (xdrs, (char **)&objp->SECINFO4resok_val, (u_int *) &objp->SECINFO4resok_len, ~0,
        sizeof (secinfo4), (xdrproc_t) xdr_secinfo4))
         return FALSE;
    return TRUE;
}

bool_t
xdr_SECINFO4res (XDR *xdrs, SECINFO4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_SECINFO4resok (xdrs, &objp->SECINFO4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_SETATTR4args (XDR *xdrs, SETATTR4args *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->stateid))
         return FALSE;
     if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
         return FALSE;
    return TRUE;
}

bool_t
xdr_SETATTR4res (XDR *xdrs, SETATTR4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
     if (!xdr_bitmap4 (xdrs, &objp->attrsset))
         return FALSE;
    return TRUE;
}

bool_t
xdr_SETCLIENTID4args (XDR *xdrs, SETCLIENTID4args *objp)
{
     if (!xdr_nfs_client_id4 (xdrs, &objp->client))
         return FALSE;
     if (!xdr_cb_client4 (xdrs, &objp->callback))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->callback_ident))
         return FALSE;
    return TRUE;
}

bool_t
xdr_SETCLIENTID4resok (XDR *xdrs, SETCLIENTID4resok *objp)
{
     if (!xdr_clientid4 (xdrs, &objp->clientid))
         return FALSE;
     if (!xdr_verifier4 (xdrs, objp->setclientid_confirm))
         return FALSE;
    return TRUE;
}

bool_t
xdr_SETCLIENTID4res (XDR *xdrs, SETCLIENTID4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_SETCLIENTID4resok (xdrs, &objp->SETCLIENTID4res_u.resok4))
             return FALSE;
        break;
    case NFS4ERR_CLID_INUSE:
         if (!xdr_clientaddr4 (xdrs, &objp->SETCLIENTID4res_u.client_using))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_SETCLIENTID_CONFIRM4args (XDR *xdrs, SETCLIENTID_CONFIRM4args *objp)
{
     if (!xdr_clientid4 (xdrs, &objp->clientid))
         return FALSE;
     if (!xdr_verifier4 (xdrs, objp->setclientid_confirm))
         return FALSE;
    return TRUE;
}

bool_t
xdr_SETCLIENTID_CONFIRM4res (XDR *xdrs, SETCLIENTID_CONFIRM4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_VERIFY4args (XDR *xdrs, VERIFY4args *objp)
{
     if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
         return FALSE;
    return TRUE;
}

bool_t
xdr_VERIFY4res (XDR *xdrs, VERIFY4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_stable_how4 (XDR *xdrs, stable_how4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_WRITE4args (XDR *xdrs, WRITE4args *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->stateid))
         return FALSE;
     if (!xdr_offset4 (xdrs, &objp->offset))
         return FALSE;
     if (!xdr_stable_how4 (xdrs, &objp->stable))
         return FALSE;
     if (!xdr_bytes (xdrs, (char **)&objp->data.data_val, (u_int *) &objp->data.data_len, ~0))
         return FALSE;
    return TRUE;
}

bool_t
xdr_WRITE4resok (XDR *xdrs, WRITE4resok *objp)
{
     if (!xdr_count4 (xdrs, &objp->count))
         return FALSE;
     if (!xdr_stable_how4 (xdrs, &objp->committed))
         return FALSE;
     if (!xdr_verifier4 (xdrs, objp->writeverf))
         return FALSE;
    return TRUE;
}

bool_t
xdr_WRITE4res (XDR *xdrs, WRITE4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_WRITE4resok (xdrs, &objp->WRITE4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_RELEASE_LOCKOWNER4args (XDR *xdrs, RELEASE_LOCKOWNER4args *objp)
{
     if (!xdr_lock_owner4 (xdrs, &objp->lock_owner))
         return FALSE;
    return TRUE;
}

bool_t
xdr_RELEASE_LOCKOWNER4res (XDR *xdrs, RELEASE_LOCKOWNER4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_ILLEGAL4res (XDR *xdrs, ILLEGAL4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_opnum4 (XDR *xdrs, nfs_opnum4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_argop4 (XDR *xdrs, nfs_argop4 *objp)
{
     if (!xdr_nfs_opnum4 (xdrs, &objp->argop))
         return FALSE;
    switch (objp->argop) {
    case OP_ACCESS:
         if (!xdr_ACCESS4args (xdrs, &objp->nfs_argop4_u.opaccess))
             return FALSE;
        break;
    case OP_CLOSE:
         if (!xdr_CLOSE4args (xdrs, &objp->nfs_argop4_u.opclose))
             return FALSE;
        break;
    case OP_COMMIT:
         if (!xdr_COMMIT4args (xdrs, &objp->nfs_argop4_u.opcommit))
             return FALSE;
        break;
    case OP_CREATE:
         if (!xdr_CREATE4args (xdrs, &objp->nfs_argop4_u.opcreate))
             return FALSE;
        break;
    case OP_DELEGPURGE:
         if (!xdr_DELEGPURGE4args (xdrs, &objp->nfs_argop4_u.opdelegpurge))
             return FALSE;
        break;
    case OP_DELEGRETURN:
         if (!xdr_DELEGRETURN4args (xdrs, &objp->nfs_argop4_u.opdelegreturn))
             return FALSE;
        break;
    case OP_GETATTR:
         if (!xdr_GETATTR4args (xdrs, &objp->nfs_argop4_u.opgetattr))
             return FALSE;
        break;
    case OP_GETFH:
        break;
    case OP_LINK:
         if (!xdr_LINK4args (xdrs, &objp->nfs_argop4_u.oplink))
             return FALSE;
        break;
    case OP_LOCK:
         if (!xdr_LOCK4args (xdrs, &objp->nfs_argop4_u.oplock))
             return FALSE;
        break;
    case OP_LOCKT:
         if (!xdr_LOCKT4args (xdrs, &objp->nfs_argop4_u.oplockt))
             return FALSE;
        break;
    case OP_LOCKU:
         if (!xdr_LOCKU4args (xdrs, &objp->nfs_argop4_u.oplocku))
             return FALSE;
        break;
    case OP_LOOKUP:
         if (!xdr_LOOKUP4args (xdrs, &objp->nfs_argop4_u.oplookup))
             return FALSE;
        break;
    case OP_LOOKUPP:
        break;
    case OP_NVERIFY:
         if (!xdr_NVERIFY4args (xdrs, &objp->nfs_argop4_u.opnverify))
             return FALSE;
        break;
    case OP_OPEN:
         if (!xdr_OPEN4args (xdrs, &objp->nfs_argop4_u.opopen))
             return FALSE;
        break;
    case OP_OPENATTR:
         if (!xdr_OPENATTR4args (xdrs, &objp->nfs_argop4_u.opopenattr))
             return FALSE;
        break;
    case OP_OPEN_CONFIRM:
         if (!xdr_OPEN_CONFIRM4args (xdrs, &objp->nfs_argop4_u.opopen_confirm))
             return FALSE;
        break;
    case OP_OPEN_DOWNGRADE:
         if (!xdr_OPEN_DOWNGRADE4args (xdrs, &objp->nfs_argop4_u.opopen_downgrade))
             return FALSE;
        break;
    case OP_PUTFH:
         if (!xdr_PUTFH4args (xdrs, &objp->nfs_argop4_u.opputfh))
             return FALSE;
        break;
    case OP_PUTPUBFH:
        break;
    case OP_PUTROOTFH:
        break;
    case OP_READ:
         if (!xdr_READ4args (xdrs, &objp->nfs_argop4_u.opread))
             return FALSE;
        break;
    case OP_READDIR:
         if (!xdr_READDIR4args (xdrs, &objp->nfs_argop4_u.opreaddir))
             return FALSE;
        break;
    case OP_READLINK:
        break;
    case OP_REMOVE:
         if (!xdr_REMOVE4args (xdrs, &objp->nfs_argop4_u.opremove))
             return FALSE;
        break;
    case OP_RENAME:
         if (!xdr_RENAME4args (xdrs, &objp->nfs_argop4_u.oprename))
             return FALSE;
        break;
    case OP_RENEW:
         if (!xdr_RENEW4args (xdrs, &objp->nfs_argop4_u.oprenew))
             return FALSE;
        break;
    case OP_RESTOREFH:
        break;
    case OP_SAVEFH:
        break;
    case OP_SECINFO:
         if (!xdr_SECINFO4args (xdrs, &objp->nfs_argop4_u.opsecinfo))
             return FALSE;
        break;
    case OP_SETATTR:
         if (!xdr_SETATTR4args (xdrs, &objp->nfs_argop4_u.opsetattr))
             return FALSE;
        break;
    case OP_SETCLIENTID:
         if (!xdr_SETCLIENTID4args (xdrs, &objp->nfs_argop4_u.opsetclientid))
             return FALSE;
        break;
    case OP_SETCLIENTID_CONFIRM:
         if (!xdr_SETCLIENTID_CONFIRM4args (xdrs, &objp->nfs_argop4_u.opsetclientid_confirm))
             return FALSE;
        break;
    case OP_VERIFY:
         if (!xdr_VERIFY4args (xdrs, &objp->nfs_argop4_u.opverify))
             return FALSE;
        break;
    case OP_WRITE:
         if (!xdr_WRITE4args (xdrs, &objp->nfs_argop4_u.opwrite))
             return FALSE;
        break;
    case OP_RELEASE_LOCKOWNER:
         if (!xdr_RELEASE_LOCKOWNER4args (xdrs, &objp->nfs_argop4_u.oprelease_lockowner))
             return FALSE;
        break;
    case OP_GET_DIR_DELEGATION:
         if (!xdr_GET_DIR_DELEGATION4args (xdrs, &objp->nfs_argop4_u.opget_dir_delegation))
             return FALSE;
        break;
    case OP_ILLEGAL:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_resop4 (XDR *xdrs, nfs_resop4 *objp)
{
     if (!xdr_nfs_opnum4 (xdrs, &objp->resop))
         return FALSE;
    switch (objp->resop) {
    case OP_ACCESS:
         if (!xdr_ACCESS4res (xdrs, &objp->nfs_resop4_u.opaccess))
             return FALSE;
        break;
    case OP_CLOSE:
         if (!xdr_CLOSE4res (xdrs, &objp->nfs_resop4_u.opclose))
             return FALSE;
        break;
    case OP_COMMIT:
         if (!xdr_COMMIT4res (xdrs, &objp->nfs_resop4_u.opcommit))
             return FALSE;
        break;
    case OP_CREATE:
         if (!xdr_CREATE4res (xdrs, &objp->nfs_resop4_u.opcreate))
             return FALSE;
        break;
    case OP_DELEGPURGE:
         if (!xdr_DELEGPURGE4res (xdrs, &objp->nfs_resop4_u.opdelegpurge))
             return FALSE;
        break;
    case OP_DELEGRETURN:
         if (!xdr_DELEGRETURN4res (xdrs, &objp->nfs_resop4_u.opdelegreturn))
             return FALSE;
        break;
    case OP_GETATTR:
         if (!xdr_GETATTR4res (xdrs, &objp->nfs_resop4_u.opgetattr))
             return FALSE;
         break;
    case OP_GETFH:
         if (!xdr_GETFH4res (xdrs, &objp->nfs_resop4_u.opgetfh))
             return FALSE;
        break;
    case OP_LINK:
         if (!xdr_LINK4res (xdrs, &objp->nfs_resop4_u.oplink))
             return FALSE;
        break;
    case OP_LOCK:
         if (!xdr_LOCK4res (xdrs, &objp->nfs_resop4_u.oplock))
             return FALSE;
        break;
    case OP_LOCKT:
         if (!xdr_LOCKT4res (xdrs, &objp->nfs_resop4_u.oplockt))
             return FALSE;
        break;
    case OP_LOCKU:
         if (!xdr_LOCKU4res (xdrs, &objp->nfs_resop4_u.oplocku))
             return FALSE;
        break;
    case OP_LOOKUP:
         if (!xdr_LOOKUP4res (xdrs, &objp->nfs_resop4_u.oplookup))
             return FALSE;
        break;
    case OP_LOOKUPP:
         if (!xdr_LOOKUPP4res (xdrs, &objp->nfs_resop4_u.oplookupp))
             return FALSE;
        break;
    case OP_NVERIFY:
         if (!xdr_NVERIFY4res (xdrs, &objp->nfs_resop4_u.opnverify))
             return FALSE;
        break;
    case OP_OPEN:
         if (!xdr_OPEN4res (xdrs, &objp->nfs_resop4_u.opopen))
             return FALSE;
        break;
    case OP_OPENATTR:
         if (!xdr_OPENATTR4res (xdrs, &objp->nfs_resop4_u.opopenattr))
             return FALSE;
        break;
    case OP_OPEN_CONFIRM:
         if (!xdr_OPEN_CONFIRM4res (xdrs, &objp->nfs_resop4_u.opopen_confirm))
             return FALSE;
        break;
    case OP_OPEN_DOWNGRADE:
         if (!xdr_OPEN_DOWNGRADE4res (xdrs, &objp->nfs_resop4_u.opopen_downgrade))
             return FALSE;
        break;
    case OP_PUTFH:
         if (!xdr_PUTFH4res (xdrs, &objp->nfs_resop4_u.opputfh))
             return FALSE;
        break;
    case OP_PUTPUBFH:
         if (!xdr_PUTPUBFH4res (xdrs, &objp->nfs_resop4_u.opputpubfh))
             return FALSE;
        break;
    case OP_PUTROOTFH:
         if (!xdr_PUTROOTFH4res (xdrs, &objp->nfs_resop4_u.opputrootfh))
             return FALSE;
        break;
    case OP_READ:
         if (!xdr_READ4res (xdrs, &objp->nfs_resop4_u.opread))
             return FALSE;
        break;
    case OP_READDIR:
         if (!xdr_READDIR4res (xdrs, &objp->nfs_resop4_u.opreaddir))
             return FALSE;
        break;
    case OP_READLINK:
         if (!xdr_READLINK4res (xdrs, &objp->nfs_resop4_u.opreadlink))
             return FALSE;
        break;
    case OP_REMOVE:
         if (!xdr_REMOVE4res (xdrs, &objp->nfs_resop4_u.opremove))
             return FALSE;
        break;
    case OP_RENAME:
         if (!xdr_RENAME4res (xdrs, &objp->nfs_resop4_u.oprename))
             return FALSE;
        break;
    case OP_RENEW:
         if (!xdr_RENEW4res (xdrs, &objp->nfs_resop4_u.oprenew))
             return FALSE;
        break;
    case OP_RESTOREFH:
         if (!xdr_RESTOREFH4res (xdrs, &objp->nfs_resop4_u.oprestorefh))
             return FALSE;
        break;
    case OP_SAVEFH:
         if (!xdr_SAVEFH4res (xdrs, &objp->nfs_resop4_u.opsavefh))
             return FALSE;
        break;
    case OP_SECINFO:
         if (!xdr_SECINFO4res (xdrs, &objp->nfs_resop4_u.opsecinfo))
             return FALSE;
        break;
    case OP_SETATTR:
         if (!xdr_SETATTR4res (xdrs, &objp->nfs_resop4_u.opsetattr))
             return FALSE;
        break;
    case OP_SETCLIENTID:
         if (!xdr_SETCLIENTID4res (xdrs, &objp->nfs_resop4_u.opsetclientid))
             return FALSE;
        break;
    case OP_SETCLIENTID_CONFIRM:
         if (!xdr_SETCLIENTID_CONFIRM4res (xdrs, &objp->nfs_resop4_u.opsetclientid_confirm))
             return FALSE;
        break;
    case OP_VERIFY:
         if (!xdr_VERIFY4res (xdrs, &objp->nfs_resop4_u.opverify))
             return FALSE;
        break;
    case OP_WRITE:
         if (!xdr_WRITE4res (xdrs, &objp->nfs_resop4_u.opwrite))
             return FALSE;
        break;
    case OP_RELEASE_LOCKOWNER:
         if (!xdr_RELEASE_LOCKOWNER4res (xdrs, &objp->nfs_resop4_u.oprelease_lockowner))
             return FALSE;
        break;
    case OP_GET_DIR_DELEGATION:
         if (!xdr_GET_DIR_DELEGATION4res (xdrs, &objp->nfs_resop4_u.opget_dir_delegation))
             return FALSE;
        break;
    case OP_ILLEGAL:
         if (!xdr_ILLEGAL4res (xdrs, &objp->nfs_resop4_u.opillegal))
             return FALSE;
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_COMPOUND4args (XDR *xdrs, COMPOUND4args *objp)
{
     if (!xdr_utf8str_cs (xdrs, &objp->tag))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->minorversion))
         return FALSE;
     if (!xdr_array (xdrs, (char **)&objp->argarray.argarray_val, (u_int *) &objp->argarray.argarray_len, ~0,
        sizeof (nfs_argop4), (xdrproc_t) xdr_nfs_argop4))
         return FALSE;
    return TRUE;
}

bool_t
xdr_COMPOUND4res (XDR *xdrs, COMPOUND4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
     if (!xdr_utf8str_cs (xdrs, &objp->tag))
         return FALSE;
     if (!xdr_array (xdrs, (char **)&objp->resarray.resarray_val, (u_int *) &objp->resarray.resarray_len, ~0,
        sizeof (nfs_resop4), (xdrproc_t) xdr_nfs_resop4))
         return FALSE;
    return TRUE;
}

bool_t
xdr_CB_GETATTR4args (XDR *xdrs, CB_GETATTR4args *objp)
{
     if (!xdr_nfs_fh4 (xdrs, &objp->fh))
         return FALSE;
     if (!xdr_bitmap4 (xdrs, &objp->attr_request))
         return FALSE;
    return TRUE;
}

bool_t
xdr_CB_GETATTR4resok (XDR *xdrs, CB_GETATTR4resok *objp)
{
     if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
         return FALSE;
    return TRUE;
}

bool_t
xdr_CB_GETATTR4res (XDR *xdrs, CB_GETATTR4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    switch (objp->status) {
    case NFS4_OK:
         if (!xdr_CB_GETATTR4resok (xdrs, &objp->CB_GETATTR4res_u.resok4))
             return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_CB_RECALL4args (XDR *xdrs, CB_RECALL4args *objp)
{
     if (!xdr_stateid4 (xdrs, &objp->stateid))
         return FALSE;
     if (!xdr_bool (xdrs, &objp->truncate))
         return FALSE;
     if (!xdr_nfs_fh4 (xdrs, &objp->fh))
         return FALSE;
    return TRUE;
}

bool_t
xdr_CB_RECALL4res (XDR *xdrs, CB_RECALL4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_CB_ILLEGAL4res (XDR *xdrs, CB_ILLEGAL4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_cb_opnum4 (XDR *xdrs, nfs_cb_opnum4 *objp)
{
     if (!xdr_enum (xdrs, (enum_t *) objp))
         return FALSE;
    return TRUE;
}

bool_t
xdr_nfs_cb_argop4 (XDR *xdrs, nfs_cb_argop4 *objp)
{
     if (!xdr_u_int (xdrs, &objp->argop))
         return FALSE;
    switch (objp->argop) {
    case OP_CB_GETATTR:
         if (!xdr_CB_GETATTR4args (xdrs, &objp->nfs_cb_argop4_u.opcbgetattr))
             return FALSE;
        break;
    case OP_CB_RECALL:
         if (!xdr_CB_RECALL4args (xdrs, &objp->nfs_cb_argop4_u.opcbrecall))
             return FALSE;
        break;
    case OP_CB_ILLEGAL:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_cb_resop4 (XDR *xdrs, nfs_cb_resop4 *objp)
{
     if (!xdr_u_int (xdrs, &objp->resop))
         return FALSE;
    switch (objp->resop) {
    case OP_CB_GETATTR:
         if (!xdr_CB_GETATTR4res (xdrs, &objp->nfs_cb_resop4_u.opcbgetattr))
             return FALSE;
        break;
    case OP_CB_RECALL:
         if (!xdr_CB_RECALL4res (xdrs, &objp->nfs_cb_resop4_u.opcbrecall))
             return FALSE;
        break;
    case OP_CB_ILLEGAL:
         if (!xdr_CB_ILLEGAL4res (xdrs, &objp->nfs_cb_resop4_u.opcbillegal))
             return FALSE;
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_COMPOUND4args (XDR *xdrs, CB_COMPOUND4args *objp)
{
     if (!xdr_utf8str_cs (xdrs, &objp->tag))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->minorversion))
         return FALSE;
     if (!rpcgen::xdr_uint32_t (xdrs, &objp->callback_ident))
         return FALSE;
     if (!xdr_array (xdrs, (char **)&objp->argarray.argarray_val, (u_int *) &objp->argarray.argarray_len, ~0,
        sizeof (nfs_cb_argop4), (xdrproc_t) xdr_nfs_cb_argop4))
         return FALSE;
    return TRUE;
}

bool_t
xdr_CB_COMPOUND4res (XDR *xdrs, CB_COMPOUND4res *objp)
{
     if (!xdr_nfsstat4 (xdrs, &objp->status))
         return FALSE;
     if (!xdr_utf8str_cs (xdrs, &objp->tag))
         return FALSE;
     if (!xdr_array (xdrs, (char **)&objp->resarray.resarray_val, (u_int *) &objp->resarray.resarray_len, ~0,
        sizeof (nfs_cb_resop4), (xdrproc_t) xdr_nfs_cb_resop4))
         return FALSE;
    return TRUE;
}

}// namespace rpcgen
