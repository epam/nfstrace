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
#include <iomanip>

#include "protocols/nfs/nfs_utils.h"
#include "protocols/nfs4/nfs4_utils.h"
//------------------------------------------------------------------------------
using namespace NST::API::NFS4;
using namespace NST::protocols::NFS;  // NFS helpers
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS4
{

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS4::NFSProcedure proc)
{
    return out << print_nfs4_procedures(proc);
}

const char* print_nfs4_procedures(const ProcEnumNFS4::NFSProcedure proc)
{
    // In all cases we suppose, that NFSv4 operation ILLEGAL(10044)
    // has the second position in ProcEnumNFS4
    uint32_t i = proc;
    if(proc == ProcEnumNFS4::ILLEGAL) i = 2;

    static const char* const NFS4ProcedureTitles[ProcEnumNFS4::count] =
    {
    "NULL","COMPOUND","ILLEGAL",  "ACCESS",            "CLOSE",
    "COMMIT",         "CREATE",   "DELEGPURGE",        "DELEGRETURN",
    "GETATTR",        "GETFH",    "LINK",              "LOCK",
    "LOCKT",          "LOCKU",    "LOOKUP",            "LOOKUPP",
    "NVERIFY",        "OPEN",     "OPENATTR",          "OPEN_CONFIRM",
    "OPEN_DOWNGRADE", "PUTFH",    "PUTPUBFH",          "PUTROOTFH",
    "READ",           "READDIR",  "READLINK",          "REMOVE",
    "RENAME",         "RENEW",    "RESTOREFH",         "SAVEFH",
    "SECINFO",        "SETATTR",  "SETCLIENTID",       "SETCLIENTID_CONFIRM",
    "VERIFY",         "WRITE",    "RELEASE_LOCKOWNER", "GET_DIR_DELEGATION"
    };

    return NFS4ProcedureTitles[i];
}

std::ostream& operator<<(std::ostream& out, const nfs_ftype4& obj)
{
    switch(obj)
    {
    case nfs_ftype4::NF4REG:       return out << "REG";
    case nfs_ftype4::NF4DIR:       return out << "DIR";
    case nfs_ftype4::NF4BLK:       return out << "BLK";
    case nfs_ftype4::NF4CHR:       return out << "CHR";
    case nfs_ftype4::NF4LNK:       return out << "LNK";
    case nfs_ftype4::NF4SOCK:      return out << "SOCK";
    case nfs_ftype4::NF4FIFO:      return out << "FIFO";
    case nfs_ftype4::NF4ATTRDIR:   return out << "ATTRDIR";
    case nfs_ftype4::NF4NAMEDATTR: return out << "NAMEDATTR";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfsstat4& obj)
{
    switch(obj)
    {
    case nfsstat4::NFS4_OK:
        return out << "OK";
    case nfsstat4::NFS4ERR_PERM:
        return out << "ERROR_PERM";
    case nfsstat4::NFS4ERR_NOENT:
        return out << "ERROR_NOENT";
    case nfsstat4::NFS4ERR_IO:
        return out << "ERROR_IO";
    case nfsstat4::NFS4ERR_NXIO:
        return out << "ERROR_NXIO";
    case nfsstat4::NFS4ERR_ACCESS:
        return out << "ERROR_ACCESS";
    case nfsstat4::NFS4ERR_EXIST:
        return out << "ERROR_EXIST";
    case nfsstat4::NFS4ERR_XDEV:
        return out << "ERROR_XDEV";
    case nfsstat4::NFS4ERR_NOTDIR:
        return out << "ERROR_NOTDIR";
    case nfsstat4::NFS4ERR_ISDIR:
        return out << "ERROR_ISDIR";
    case nfsstat4::NFS4ERR_INVAL:
        return out << "ERROR_INVAL";
    case nfsstat4::NFS4ERR_FBIG:
        return out << "ERROR_FBIG";
    case nfsstat4::NFS4ERR_NOSPC:
        return out << "ERROR_NOSPC";
    case nfsstat4::NFS4ERR_ROFS:
        return out << "ERROR_ROFS";
    case nfsstat4::NFS4ERR_MLINK:
        return out << "ERROR_MLINK";
    case nfsstat4::NFS4ERR_NAMETOOLONG:
        return out << "ERROR_NAMETOOLONG";
    case nfsstat4::NFS4ERR_NOTEMPTY:
        return out << "ERROR_NOTEMPTY";
    case nfsstat4::NFS4ERR_DQUOT:
        return out << "ERROR_DQUOT";
    case nfsstat4::NFS4ERR_STALE:
        return out << "ERROR_STALE";
    case nfsstat4::NFS4ERR_BADHANDLE:
        return out << "ERROR_BADHANDLE";
    case nfsstat4::NFS4ERR_BAD_COOKIE:
        return out << "ERROR_BAD_COOKIE";
    case nfsstat4::NFS4ERR_NOTSUPP:
        return out << "ERROR_NOTSUPP";
    case nfsstat4::NFS4ERR_TOOSMALL:
        return out << "ERROR_TOOSMALL";
    case nfsstat4::NFS4ERR_SERVERFAULT:
        return out << "ERROR_SERVERFAULT";
    case nfsstat4::NFS4ERR_BADTYPE:
        return out << "ERROR_BADTYPE";
    case nfsstat4::NFS4ERR_DELAY:
        return out << "ERROR_DELAY";
    case nfsstat4::NFS4ERR_SAME:
        return out << "ERROR_SAME";
    case nfsstat4::NFS4ERR_DENIED:
        return out << "ERROR_DENIED";
    case nfsstat4::NFS4ERR_EXPIRED:
        return out << "ERROR_EXPIRED";
    case nfsstat4::NFS4ERR_LOCKED:
        return out << "ERROR_LOCKED";
    case nfsstat4::NFS4ERR_GRACE:
        return out << "ERROR_GRACE";
    case nfsstat4::NFS4ERR_FHEXPIRED:
        return out << "ERROR_FHEXPIRED";
    case nfsstat4::NFS4ERR_SHARE_DENIED:
        return out << "ERROR_SHARE_DENIED";
    case nfsstat4::NFS4ERR_WRONGSEC:
        return out << "ERROR_WRONGSEC";
    case nfsstat4::NFS4ERR_CLID_INUSE:
        return out << "ERROR_CLID_INUSE";
    case nfsstat4::NFS4ERR_RESOURCE:
        return out << "ERROR_RESOURCE";
    case nfsstat4::NFS4ERR_MOVED:
        return out << "ERROR_MOVED";
    case nfsstat4::NFS4ERR_NOFILEHANDLE:
        return out << "ERROR_NOFILEHANDLE";
    case nfsstat4::NFS4ERR_MINOR_VERS_MISMATCH:
        return out << "ERROR_MINOR_VERS_MISMATCH";
    case nfsstat4::NFS4ERR_STALE_CLIENTID:
        return out << "ERROR_STALE_CLIENTID";
    case nfsstat4::NFS4ERR_STALE_STATEID:
        return out << "ERROR_STALE_STATEID";
    case nfsstat4::NFS4ERR_OLD_STATEID:
        return out << "ERROR_OLD_STATEID";
    case nfsstat4::NFS4ERR_BAD_STATEID:
        return out << "ERROR_BAD_STATEID";
    case nfsstat4::NFS4ERR_BAD_SEQID:
        return out << "ERROR_BAD_SEQID";
    case nfsstat4::NFS4ERR_NOT_SAME:
        return out << "ERROR_NOT_SAME";
    case nfsstat4::NFS4ERR_LOCK_RANGE:
        return out << "ERROR_LOCK_RANGE";
    case nfsstat4::NFS4ERR_SYMLINK:
        return out << "ERROR_SYMLINK";
    case nfsstat4::NFS4ERR_RESTOREFH:
        return out << "ERROR_RESTOREFH";
    case nfsstat4::NFS4ERR_LEASE_MOVED:
        return out << "ERROR_LEASE_MOVED";
    case nfsstat4::NFS4ERR_ATTRNOTSUPP:
        return out << "ERROR_ATTRNOTSUPP";
    case nfsstat4::NFS4ERR_NO_GRACE:
        return out << "ERROR_NO_GRACE";
    case nfsstat4::NFS4ERR_RECLAIM_BAD:
        return out << "ERROR_RECLAIM_BAD";
    case nfsstat4::NFS4ERR_RECLAIM_CONFLICT:
        return out << "ERROR_RECLAIM_CONFLICT";
    case nfsstat4::NFS4ERR_BADXDR:
        return out << "ERROR_BADXDR";
    case nfsstat4::NFS4ERR_LOCKS_HELD:
        return out << "ERROR_LOCKS_HELD";
    case nfsstat4::NFS4ERR_OPENMODE:
        return out << "ERROR_OPENMODE";
    case nfsstat4::NFS4ERR_BADOWNER:
        return out << "ERROR_BADOWNER";
    case nfsstat4::NFS4ERR_BADCHAR:
        return out << "ERROR_BADCHAR";
    case nfsstat4::NFS4ERR_BADNAME:
        return out << "ERROR_BADNAME";
    case nfsstat4::NFS4ERR_BAD_RANGE:
        return out << "ERROR_BAD_RANGE";
    case nfsstat4::NFS4ERR_LOCK_NOTSUPP:
        return out << "ERROR_LOCK_NOTSUPP";
    case nfsstat4::NFS4ERR_OP_ILLEGAL:
        return out << "ERROR_OP_ILLEGAL";
    case nfsstat4::NFS4ERR_DEADLOCK:
        return out << "ERROR_DEADLOCK";
    case nfsstat4::NFS4ERR_FILE_OPEN:
        return out << "ERROR_FILE_OPEN";
    case nfsstat4::NFS4ERR_ADMIN_REVOKED:
        return out << "ERROR_ADMIN_REVOKED";
    case nfsstat4::NFS4ERR_CB_PATH_DOWN:
        return out << "ERROR_CB_PATH_DOWN";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const bitmap4& obj)
{
    if(obj.bitmap4_len)
    {
        out << "mask: ";
        print_hex(out, obj.bitmap4_val, obj.bitmap4_len);
        const size_t nbits {obj.bitmap4_len << 5}; // obj.bitmap4_len * 32

        static const char* const FATTR4Attributes[] =
        {
            "SUPPORTED_ATTRS", "TYPE",           "FH_EXPIRE_TYPE",  "CHANGE",
            "SIZE",            "LINK_SUPPORT",   "SYMLINK_SUPPORT", "NAMED_ATTR",
            "FSID",            "UNIQUE_HANDLES", "LEASE_TIME",      "RDATTR_ERROR",
            "ACL",             "ACLSUPPORT",     "ARCHIVE",         "CANSETTIME",
            "CASE_INSENSITIVE","CASE_PRESERVING","CHOWN_RESTRICTED","FILEHANDLE",
            "FILEID",          "FILES_AVAIL",    "FILES_FREE",      "FILES_TOTAL",
            "FS_LOCATIONS",    "HIDDEN",         "HOMOGENEOUS",     "MAXFILESIZE",
            "MAXLINK",         "MAXNAME",        "MAXREAD",         "MAXWRITE",
            "MIMETYPE",        "MODE",           "NO_TRUNC",        "NUMLINKS",
            "OWNER",           "OWNER_GROUP",    "QUOTA_AVAIL_HARD","QUOTA_AVAIL_SOFT",
            "QUOTA_USED",      "RAWDEV",         "SPACE_AVAIL",     "SPACE_FREE",
            "SPACE_TOTAL",     "SPACE_USED",     "SYSTEM",          "TIME_ACCESS",
            "TIME_ACCESS_SET", "TIME_BACKUP",    "TIME_CREATE",     "TIME_DELTA",
            "TIME_METADATA",   "TIME_MODIFY",    "TIME_MODIFY_SET", "MOUNTED_ON_FILEID",
        };
        for(size_t i {0}; i<nbits; i++)
        {
            //obj.bitmap4_val[i / 32] >> (i % 32)) & 0x1;
            const int bit = (obj.bitmap4_val[i >> 5] >> (i & 31)) & 0x1;
            if( bit !=0 && i < ( sizeof(FATTR4Attributes)/
                                 sizeof(FATTR4Attributes[0]) ) )
                out << ' ' << FATTR4Attributes[i];
        }
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const utf8string& obj)
{
    if(obj.utf8string_len)
    {
        out.write(obj.utf8string_val,
                  obj.utf8string_len);
    }
    else
    {
        out << "void";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const pathname4& obj)
{
    component4 *current_el = obj.pathname4_val;
    for(size_t i {0}; i<obj.pathname4_len; i++,current_el++)
    {
        out.write(current_el->utf8string_val,
                  current_el->utf8string_len);
        out << ' ';
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const sec_oid4& obj)
{
    print_hex(out,
              obj.sec_oid4_val,
              obj.sec_oid4_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfstime4& obj)
{
    return out <<  "sec: "  << obj.seconds
               << " nsec: " << obj.nseconds;
}

std::ostream& operator<<(std::ostream& out, const time_how4& obj)
{
    switch(obj)
    {
    case time_how4::SET_TO_SERVER_TIME4:
        return out << "server time";
    case time_how4::SET_TO_CLIENT_TIME4:
        return out << "client time";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const settime4& obj)
{
    return out << obj.set_it << ": " << obj.settime4_u.time;
}

std::ostream& operator<<(std::ostream& out, const nfs_fh4& obj)
{
    NFS::print_nfs_fh(out,
                      obj.nfs_fh4_val,
                      obj.nfs_fh4_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const fsid4& obj)
{
    return out <<  "major: "  << obj.major
               << " minor: "  << obj.minor;
}

std::ostream& operator<<(std::ostream& out, const fs_location4& obj)
{
    out <<  "root path: " << obj.rootpath;
    utf8str_cis *current_el {obj.server.server_val};
    for(size_t i {0}; i<obj.server.server_len; i++,current_el++)
    {
        out.write(current_el->utf8string_val,
                  current_el->utf8string_len);
        out << ' ';
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const fs_locations4& obj)
{
    out <<  "root: " << obj.fs_root;
    if(obj.locations.locations_len)
    {
        fs_location4* current_el {obj.locations.locations_val};
        for(u_int i {0}; i<obj.locations.locations_len; i++,current_el++)
        {
           out << current_el;
        }
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfsace4& obj)
{
    return out <<  "type: "        << obj.type
               << " flag: "        << obj.flag
               << " access mask: " << obj.access_mask
               << " who: "         << obj.who;
}

std::ostream& operator<<(std::ostream& out, const specdata4& obj)
{
    return out <<  "specdata 1: " << obj.specdata1
               << " specdata 2: " << obj.specdata2;
}

std::ostream& operator<<(std::ostream& out, const fattr4_acl& obj)
{
    if(obj.fattr4_acl_len) return out << *obj.fattr4_acl_val;
    else                   return out << "void";
}

std::ostream& operator<<(std::ostream& out, const fattr4& obj)
{
    return out << obj.attrmask;
}

std::ostream& operator<<(std::ostream& out, const change_info4& obj)
{
    out <<  " atomic: ";
    if(obj.atomic) out << "YES";
    else           out << "NO";

    return out << " change id before: " << obj.before
               << " change id after: "  << obj.after;
}

std::ostream& operator<<(std::ostream& out, const clientaddr4& obj)
{
    return out <<  "netid: " << obj.r_netid
               << " addr: "  << obj.r_addr;
}

std::ostream& operator<<(std::ostream& out, const cb_client4& obj)
{
    return out <<  "program: "  << std::hex << obj.cb_program
               << " location: " << obj.cb_location;
}

std::ostream& operator<<(std::ostream& out, const stateid4& obj)
{
    out << " seqid: " << std::hex << obj.seqid << " data: ";
    print_hex(out,
              obj.other,
              12);
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfs_client_id4& obj)
{
    out <<  "verifier: ";
    print_hex(out,
              obj.verifier,
              NFS4_VERIFIER_SIZE);
    out << " client id: ";
    if(obj.id.id_len) out.write(obj.id.id_val,
                                obj.id.id_len);
    else out << " void";

    return out;
}

std::ostream& operator<<(std::ostream& out, const open_owner4& obj)
{
    out <<  "client id: " << std::hex << obj.clientid << " owner: ";
    print_hex(out,
              obj.owner.owner_val,
              obj.owner.owner_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const lock_owner4& obj)
{
    out <<  "client id: " << std::hex << obj.clientid << " owner: ";
    print_hex(out,
              obj.owner.owner_val,
              obj.owner.owner_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfs_lock_type4& obj)
{
    switch(obj)
    {
    case nfs_lock_type4::READ_LT:   return out << "READ_LOCK_TYPE";
    case nfs_lock_type4::WRITE_LT:  return out << "WRITE_LOCK_TYPE";
    case nfs_lock_type4::READW_LT:  return out << "READW_LOCK_TYPE";
    case nfs_lock_type4::WRITEW_LT: return out << "WRITEW_LOCK_TYPE";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const createtype4& obj)
{
    out <<  "type: "      << obj.type;
    switch(obj.type)
    {
    case nfs_ftype4::NF4BLK:
    case nfs_ftype4::NF4CHR:
        return out << " dev data: "  << obj.createtype4_u.devdata;
    case nfs_ftype4::NF4LNK:
        return out << " link data: " << obj.createtype4_u.linkdata;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const dir_delegation_status4& obj)
{
    switch(obj)
    {
    case dir_delegation_status4::NFS4_DIR_DELEGATION_NONE:
        return out << "NONE";
    case dir_delegation_status4::NFS4_DIR_DELEGATION_READ:
        return out << "READ";
    case dir_delegation_status4::NFS4_DIR_DELEGATION_DENIED:
        return out << "DENIED";
    case dir_delegation_status4::NFS4_DIR_DELEGATION_UNAVAIL:
        return out << "UNAVAILABLE";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const open_to_lock_owner4& obj)
{
    return out <<  "open seqid: "    << obj.open_seqid
               << " open state id: " << obj.open_stateid
               << " lock seqid: "    << obj.lock_seqid
               << " lock owner: "    << obj.lock_owner;
}

std::ostream& operator<<(std::ostream& out, const exist_lock_owner4& obj)
{
    return out <<  "lock state id: " << obj.lock_stateid
               << " lock seqid: "    << obj.lock_seqid;
}

std::ostream& operator<<(std::ostream& out, const locker4& obj)
{
    out <<  "new lock owner: " << obj.new_lock_owner;
    if(obj.new_lock_owner)
        return out << " open owner: " << obj.locker4_u.open_owner;
    else 
        return out << " lock owner: " << obj.locker4_u.lock_owner;
}

std::ostream& operator<<(std::ostream& out, const createmode4& obj)
{
    switch(obj)
    {
    case createmode4::UNCHECKED4: return out << "UNCHECKED";
    case createmode4::GUARDED4:   return out << "GUARDED";
    case createmode4::EXCLUSIVE4: return out << "EXCLUSIVE";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const opentype4& obj)
{
    switch(obj)
    {
    case opentype4::OPEN4_NOCREATE: return out << "NO CREATE";
    case opentype4::OPEN4_CREATE:   return out << "CREATE";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const limit_by4& obj)
{
    switch(obj)
    {
    case limit_by4::NFS_LIMIT_SIZE:   return out << "SIZE";
    case limit_by4::NFS_LIMIT_BLOCKS: return out << "BLOCKS";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const open_delegation_type4& obj)
{
    switch(obj)
    {
    case open_delegation_type4::OPEN_DELEGATE_NONE:
        return out << "NONE";
    case open_delegation_type4::OPEN_DELEGATE_READ:
        return out << "READ";
    case open_delegation_type4::OPEN_DELEGATE_WRITE:
        return out << "WRITE";
    }
    return out;
}


std::ostream& operator<<(std::ostream& out, const open_claim_type4& obj)
{
    switch(obj)
    {
    case open_claim_type4::CLAIM_NULL:
        return out << "NULL";
    case open_claim_type4::CLAIM_PREVIOUS:
        return out << "PREVIOUS";
    case open_claim_type4::CLAIM_DELEGATE_CUR:
        return out << "DELEGATE CURRENT";
    case open_claim_type4::CLAIM_DELEGATE_PREV:
        return out << "DELEGATE PREVIOUS";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpc_gss_svc_t& obj)
{
    switch(obj)
    {
    case rpc_gss_svc_t::RPC_GSS_SVC_NONE:
        return out << "NONE";
    case rpc_gss_svc_t::RPC_GSS_SVC_INTEGRITY:
        return out << "INTEGRITY";
    case rpc_gss_svc_t::RPC_GSS_SVC_PRIVACY:
        return out << "PRIVACY";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const stable_how4& obj)
{
    switch(obj)
    {
    case stable_how4::UNSTABLE4:  return out << "UNSTABLE";
    case stable_how4::DATA_SYNC4: return out << "DATA SYNC";
    case stable_how4::FILE_SYNC4: return out << "FILE SYNC";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const createhow4& obj)
{
    out <<  " mode: " << obj.mode;
    switch(obj.mode)
    {
    case createmode4::UNCHECKED4:
    case createmode4::GUARDED4:
        return out << " attributes: " << obj.createhow4_u.createattrs;
    case createmode4::EXCLUSIVE4:
        out << " verifier: ";
        print_hex(out, obj.createhow4_u.createverf, NFS4_VERIFIER_SIZE);
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const openflag4& obj)
{
    out <<  "open type: " << obj.opentype;
    if(obj.opentype == opentype4::OPEN4_CREATE)
        return out << obj.openflag4_u.how;
    else
        return out;
}

std::ostream& operator<<(std::ostream& out, const nfs_modified_limit4& obj)
{
    return out <<  "blocks number: "   << obj.num_blocks
               << " bytes per block: " << obj.bytes_per_block;
}

std::ostream& operator<<(std::ostream& out, const nfs_space_limit4& obj)
{
    out <<  "limit by: " << obj.limitby;
    switch(obj.limitby)
    {
    case limit_by4::NFS_LIMIT_SIZE:
        return out << " filesize: "
                   << obj.nfs_space_limit4_u.filesize;
    case limit_by4::NFS_LIMIT_BLOCKS:
        return out << " modified blocks: "
                   << obj.nfs_space_limit4_u.mod_blocks;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const open_claim_delegate_cur4& obj)
{
    return out <<  "delegate state id: " << obj.delegate_stateid
               << " file: "              << obj.file;
}

std::ostream& operator<<(std::ostream& out, const open_claim4& obj)
{
    out <<  "claim: " << obj.claim;
    switch(obj.claim)
    {
    case open_claim_type4::CLAIM_NULL:
        out << " file: ";
        return out.write(obj.open_claim4_u.file.utf8string_val,
                         obj.open_claim4_u.file.utf8string_len);
    case open_claim_type4::CLAIM_PREVIOUS:
                           return out << " delegate type: "
                                      << obj.open_claim4_u.delegate_type;
    case open_claim_type4::CLAIM_DELEGATE_CUR:
                   return out << " delegate current info: "
                              << obj.open_claim4_u.delegate_cur_info;
    case open_claim_type4::CLAIM_DELEGATE_PREV:
                  return out << " file delegate previous: "
                             << obj.open_claim4_u.file_delegate_prev;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const open_read_delegation4& obj)
{
    return out <<  "stateid: "     << obj.stateid
               << " recall: "      << obj.recall
               << " permissions: " << obj.permissions;
}

std::ostream& operator<<(std::ostream& out, const open_write_delegation4& obj)
{
    return out <<  "stateid: "     << obj.stateid
               << " recall: "      << obj.recall
               << " space limit: " << obj.space_limit
               << " permissions: " << obj.permissions;
}

std::ostream& operator<<(std::ostream& out, const open_delegation4& obj)
{
    out <<  "delegation type: " << obj.delegation_type;
    switch(obj.delegation_type)
    {
    case open_delegation_type4::OPEN_DELEGATE_NONE:
        break;
    case open_delegation_type4::OPEN_DELEGATE_READ:
        return out << ": "  << obj.open_delegation4_u.read;
    case open_delegation_type4::OPEN_DELEGATE_WRITE:
        return out << ": " << obj.open_delegation4_u.write;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const entry4& obj)
{
    out <<  "cookie: "     << obj.cookie
        << " name: "       << obj.name
        << " attributes: " << obj.attrs << '\n';
    if(obj.nextentry) return out << ' ' << *obj.nextentry;
    else              return out;
}

std::ostream& operator<<(std::ostream& out, const dirlist4& obj)
{
    out <<  "eof: " << obj.eof;
    if(obj.entries) return out << " entries:\n"
                               << *obj.entries;
    else            return out;
}

std::ostream& operator<<(std::ostream& out, const rpcsec_gss_info& obj)
{
    return out <<  "oid: "     << obj.oid
               << " qop: "     << obj.qop
               << " service: " << obj.service;
}

std::ostream& operator<<(std::ostream& out, const secinfo4& obj)
{
    out <<  "flavor: " << obj.flavor;
    if(obj.flavor == RPCSEC_GSS) return out << " info: "
                                            << obj.secinfo4_u.flavor_info;
    else                         return out;
}

} // namespace NFS4
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
