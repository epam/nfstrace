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
#include <iomanip>

#include "protocols/nfs4/nfs4_utils.h"
//------------------------------------------------------------------------------
using namespace rpcgen;
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

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_ftype4& obj)
{
    switch(obj)
    {
    case rpcgen::nfs_ftype4::NF4REG:       return out << "REG";
    case rpcgen::nfs_ftype4::NF4DIR:       return out << "DIR";
    case rpcgen::nfs_ftype4::NF4BLK:       return out << "BLK";
    case rpcgen::nfs_ftype4::NF4CHR:       return out << "CHR";
    case rpcgen::nfs_ftype4::NF4LNK:       return out << "LNK";
    case rpcgen::nfs_ftype4::NF4SOCK:      return out << "SOCK";
    case rpcgen::nfs_ftype4::NF4FIFO:      return out << "FIFO";
    case rpcgen::nfs_ftype4::NF4ATTRDIR:   return out << "ATTRDIR";
    case rpcgen::nfs_ftype4::NF4NAMEDATTR: return out << "NAMEDATTR";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfsstat4& obj)
{
    switch(obj)
    {
    case rpcgen::nfsstat4::NFS4_OK:                     return out << "OK";
    case rpcgen::nfsstat4::NFS4ERR_PERM:                return out << "ERROR_PERM";
    case rpcgen::nfsstat4::NFS4ERR_NOENT:               return out << "ERROR_NOENT";
    case rpcgen::nfsstat4::NFS4ERR_IO:                  return out << "ERROR_IO";
    case rpcgen::nfsstat4::NFS4ERR_NXIO:                return out << "ERROR_NXIO";
    case rpcgen::nfsstat4::NFS4ERR_ACCESS:              return out << "ERROR_ACCESS";
    case rpcgen::nfsstat4::NFS4ERR_EXIST:               return out << "ERROR_EXIST";
    case rpcgen::nfsstat4::NFS4ERR_XDEV:                return out << "ERROR_XDEV";
    case rpcgen::nfsstat4::NFS4ERR_NOTDIR:              return out << "ERROR_NOTDIR";
    case rpcgen::nfsstat4::NFS4ERR_ISDIR:               return out << "ERROR_ISDIR";
    case rpcgen::nfsstat4::NFS4ERR_INVAL:               return out << "ERROR_INVAL";
    case rpcgen::nfsstat4::NFS4ERR_FBIG:                return out << "ERROR_FBIG";
    case rpcgen::nfsstat4::NFS4ERR_NOSPC:               return out << "ERROR_NOSPC";
    case rpcgen::nfsstat4::NFS4ERR_ROFS:                return out << "ERROR_ROFS";
    case rpcgen::nfsstat4::NFS4ERR_MLINK:               return out << "ERROR_MLINK";
    case rpcgen::nfsstat4::NFS4ERR_NAMETOOLONG:         return out << "ERROR_NAMETOOLONG";
    case rpcgen::nfsstat4::NFS4ERR_NOTEMPTY:            return out << "ERROR_NOTEMPTY";
    case rpcgen::nfsstat4::NFS4ERR_DQUOT:               return out << "ERROR_DQUOT";
    case rpcgen::nfsstat4::NFS4ERR_STALE:               return out << "ERROR_STALE";
    case rpcgen::nfsstat4::NFS4ERR_BADHANDLE:           return out << "ERROR_BADHANDLE";
    case rpcgen::nfsstat4::NFS4ERR_BAD_COOKIE:          return out << "ERROR_BAD_COOKIE";
    case rpcgen::nfsstat4::NFS4ERR_NOTSUPP:             return out << "ERROR_NOTSUPP";
    case rpcgen::nfsstat4::NFS4ERR_TOOSMALL:            return out << "ERROR_TOOSMALL";
    case rpcgen::nfsstat4::NFS4ERR_SERVERFAULT:         return out << "ERROR_SERVERFAULT";
    case rpcgen::nfsstat4::NFS4ERR_BADTYPE:             return out << "ERROR_BADTYPE";
    case rpcgen::nfsstat4::NFS4ERR_DELAY:               return out << "ERROR_DELAY";
    case rpcgen::nfsstat4::NFS4ERR_SAME:                return out << "ERROR_SAME";
    case rpcgen::nfsstat4::NFS4ERR_DENIED:              return out << "ERROR_DENIED";
    case rpcgen::nfsstat4::NFS4ERR_EXPIRED:             return out << "ERROR_EXPIRED";
    case rpcgen::nfsstat4::NFS4ERR_LOCKED:              return out << "ERROR_LOCKED";
    case rpcgen::nfsstat4::NFS4ERR_GRACE:               return out << "ERROR_GRACE";
    case rpcgen::nfsstat4::NFS4ERR_FHEXPIRED:           return out << "ERROR_FHEXPIRED";
    case rpcgen::nfsstat4::NFS4ERR_SHARE_DENIED:        return out << "ERROR_SHARE_DENIED";
    case rpcgen::nfsstat4::NFS4ERR_WRONGSEC:            return out << "ERROR_WRONGSEC";
    case rpcgen::nfsstat4::NFS4ERR_CLID_INUSE:          return out << "ERROR_CLID_INUSE";
    case rpcgen::nfsstat4::NFS4ERR_RESOURCE:            return out << "ERROR_RESOURCE";
    case rpcgen::nfsstat4::NFS4ERR_MOVED:               return out << "ERROR_MOVED";
    case rpcgen::nfsstat4::NFS4ERR_NOFILEHANDLE:        return out << "ERROR_NOFILEHANDLE";
    case rpcgen::nfsstat4::NFS4ERR_MINOR_VERS_MISMATCH: return out << "ERROR_MINOR_VERS_MISMATCH";
    case rpcgen::nfsstat4::NFS4ERR_STALE_CLIENTID:      return out << "ERROR_STALE_CLIENTID";
    case rpcgen::nfsstat4::NFS4ERR_STALE_STATEID:       return out << "ERROR_STALE_STATEID";
    case rpcgen::nfsstat4::NFS4ERR_OLD_STATEID:         return out << "ERROR_OLD_STATEID";
    case rpcgen::nfsstat4::NFS4ERR_BAD_STATEID:         return out << "ERROR_BAD_STATEID";
    case rpcgen::nfsstat4::NFS4ERR_BAD_SEQID:           return out << "ERROR_BAD_SEQID";
    case rpcgen::nfsstat4::NFS4ERR_NOT_SAME:            return out << "ERROR_NOT_SAME";
    case rpcgen::nfsstat4::NFS4ERR_LOCK_RANGE:          return out << "ERROR_LOCK_RANGE";
    case rpcgen::nfsstat4::NFS4ERR_SYMLINK:             return out << "ERROR_SYMLINK";
    case rpcgen::nfsstat4::NFS4ERR_RESTOREFH:           return out << "ERROR_RESTOREFH";
    case rpcgen::nfsstat4::NFS4ERR_LEASE_MOVED:         return out << "ERROR_LEASE_MOVED";
    case rpcgen::nfsstat4::NFS4ERR_ATTRNOTSUPP:         return out << "ERROR_ATTRNOTSUPP";
    case rpcgen::nfsstat4::NFS4ERR_NO_GRACE:            return out << "ERROR_NO_GRACE";
    case rpcgen::nfsstat4::NFS4ERR_RECLAIM_BAD:         return out << "ERROR_RECLAIM_BAD";
    case rpcgen::nfsstat4::NFS4ERR_RECLAIM_CONFLICT:    return out << "ERROR_RECLAIM_CONFLICT";
    case rpcgen::nfsstat4::NFS4ERR_BADXDR:              return out << "ERROR_BADXDR";
    case rpcgen::nfsstat4::NFS4ERR_LOCKS_HELD:          return out << "ERROR_LOCKS_HELD";
    case rpcgen::nfsstat4::NFS4ERR_OPENMODE:            return out << "ERROR_OPENMODE";
    case rpcgen::nfsstat4::NFS4ERR_BADOWNER:            return out << "ERROR_BADOWNER";
    case rpcgen::nfsstat4::NFS4ERR_BADCHAR:             return out << "ERROR_BADCHAR";
    case rpcgen::nfsstat4::NFS4ERR_BADNAME:             return out << "ERROR_BADNAME";
    case rpcgen::nfsstat4::NFS4ERR_BAD_RANGE:           return out << "ERROR_BAD_RANGE";
    case rpcgen::nfsstat4::NFS4ERR_LOCK_NOTSUPP:        return out << "ERROR_LOCK_NOTSUPP";
    case rpcgen::nfsstat4::NFS4ERR_OP_ILLEGAL:          return out << "ERROR_OP_ILLEGAL";
    case rpcgen::nfsstat4::NFS4ERR_DEADLOCK:            return out << "ERROR_DEADLOCK";
    case rpcgen::nfsstat4::NFS4ERR_FILE_OPEN:           return out << "ERROR_FILE_OPEN";
    case rpcgen::nfsstat4::NFS4ERR_ADMIN_REVOKED:       return out << "ERROR_ADMIN_REVOKED";
    case rpcgen::nfsstat4::NFS4ERR_CB_PATH_DOWN:        return out << "ERROR_CB_PATH_DOWN";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::verifier4& obj)
{
    out << std::hex << std::setfill('0') << std::setw(2);

    for(uint32_t i = 0; i < NFS4_VERIFIER_SIZE; i++)
    {
        out << std::setw(2) << (uint32_t) (obj[i]);
    }
    return out << std::dec << std::setfill(' ');
}

std::ostream& operator<<(std::ostream& out, const rpcgen::bitmap4& obj)
{
    if(obj.bitmap4_len) return out << *obj.bitmap4_val;
    else                return out << "void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::utf8string& obj)
{
    if(obj.utf8string_len) return out << *obj.utf8string_val;
    else                   return out << "void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::pathname4& obj)
{
    if(obj.pathname4_len) return out << *obj.pathname4_val;
    else                  return out << "void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::sec_oid4& obj)
{
    if(obj.sec_oid4_len) return out << *obj.sec_oid4_val;
    else                 return out << "void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfstime4& obj)
{
    return out <<  "sec: "  << obj.seconds
               << " nsec: " << obj.nseconds;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::time_how4& obj)
{
    switch(obj)
    {
    case rpcgen::time_how4::SET_TO_SERVER_TIME4: return out << "server time";
    case rpcgen::time_how4::SET_TO_CLIENT_TIME4: return out << "client time";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::settime4& obj)
{
    return out << obj.set_it << ": " << obj.settime4_u.time;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_fh4& obj)
{
    if(obj.nfs_fh4_len) return out << *obj.nfs_fh4_val;
    else                return out << "void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fsid4& obj)
{
    return out <<  "major: "  << obj.major
               << " minor: "  << obj.minor;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fs_location4& obj)
{
    out <<  "root path: " << obj.rootpath
        << " locations: ";
    if(obj.server.server_len) return out << *obj.server.server_val;
    else                      return out << "void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fs_locations4& obj)
{
    out <<  "root: " << obj.fs_root
        << " locations: ";
    if(obj.locations.locations_len) return out << *obj.locations.locations_val;
    else                            return out << "void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfsace4& obj)
{
    return out <<  "type: "        << obj.type
               << " flag: "        << obj.flag
               << " access mask: " << obj.access_mask
               << " who: "         << obj.who;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::specdata4& obj)
{
    return out <<  "specdata 1: " << obj.specdata1
               << " specdata 2: " << obj.specdata2;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fattr4_acl& obj)
{
    if(obj.fattr4_acl_len) return out << *obj.fattr4_acl_val;
    else                   return out << "void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::attrlist4& obj)
{
    if(obj.attrlist4_len) return out << *obj.attrlist4_val;
    else                  return out << "void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fattr4& obj)
{
    return out <<  "mask: " << obj.attrmask
               << " val: "  << obj.attr_vals;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::change_info4& obj)
{
    return out <<  "atomic: " << obj.atomic
               << " before: " << obj.before
               << " after: "  << obj.after;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::clientaddr4& obj)
{
    return out <<  "netid: " << *obj.r_netid
               << " addr: "  << *obj.r_addr;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::cb_client4& obj)
{
    return out <<  "program: "  << obj.cb_program
               << " location: " << obj.cb_location;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::stateid4& obj)
{
    return out << obj.seqid << " other: " << obj.other;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_client_id4& obj)
{
    out <<  "verifier: "  <<  obj.verifier;
    if(obj.id.id_len) return out << " " << *obj.id.id_val;
    else              return out << " void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_owner4& obj)
{
    out <<  "client id: " <<  obj.clientid;
    if(obj.owner.owner_len) return out << " " <<  *obj.owner.owner_val;
    else                    return out << " void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::lock_owner4& obj)
{
    out <<  "client id: " <<  obj.clientid;
    if(obj.owner.owner_len) return out << " " << *obj.owner.owner_val;
    else                    return out << " void";
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_lock_type4& obj)
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

std::ostream& operator<<(std::ostream& out, const rpcgen::createtype4& obj)
{
    out <<  "type: "      << obj.type;
    switch(obj.type)
    {
    case rpcgen::nfs_ftype4::NF4BLK:
    case rpcgen::nfs_ftype4::NF4CHR: return out << " dev data: "  << obj.createtype4_u.devdata;
    case rpcgen::nfs_ftype4::NF4LNK: return out << " link data: " << obj.createtype4_u.linkdata;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::dir_delegation_status4& obj)
{
    switch(obj)
    {
    case dir_delegation_status4::NFS4_DIR_DELEGATION_NONE:    return out << "none";
    case dir_delegation_status4::NFS4_DIR_DELEGATION_READ:    return out << "read";
    case dir_delegation_status4::NFS4_DIR_DELEGATION_DENIED:  return out << "denied";
    case dir_delegation_status4::NFS4_DIR_DELEGATION_UNAVAIL: return out << "unavailable";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_to_lock_owner4& obj)
{
    return out <<  "open seqid: "    << obj.open_seqid
               << " open state id: " << obj.open_stateid
               << " lock seqid: "    << obj.lock_seqid
               << " lock owner: "    << obj.lock_owner;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::exist_lock_owner4& obj)
{
    return out <<  "lock state id: " << obj.lock_stateid
               << " lock seqid: "    << obj.lock_seqid;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::locker4& obj)
{
    out <<  "new lock owner: " << obj.new_lock_owner;
    if(obj.new_lock_owner)
        return out << " open owner: " << obj.locker4_u.open_owner;
    else 
        return out << " lock owner: " << obj.locker4_u.lock_owner;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::createmode4& obj)
{
    switch(obj)
    {
    case rpcgen::createmode4::UNCHECKED4: return out << "unchecked";
    case rpcgen::createmode4::GUARDED4:   return out << "guarded";
    case rpcgen::createmode4::EXCLUSIVE4: return out << "exclusive";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::opentype4& obj)
{
    switch(obj)
    {
    case rpcgen::opentype4::OPEN4_NOCREATE: return out << "no create";
    case rpcgen::opentype4::OPEN4_CREATE:   return out << "create";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::limit_by4& obj)
{
    switch(obj)
    {
    case rpcgen::limit_by4::NFS_LIMIT_SIZE:   return out << "size";
    case rpcgen::limit_by4::NFS_LIMIT_BLOCKS: return out << "blocks";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_delegation_type4& obj)
{
    switch(obj)
    {
    case rpcgen::open_delegation_type4::OPEN_DELEGATE_NONE:  return out << "none";
    case rpcgen::open_delegation_type4::OPEN_DELEGATE_READ:  return out << "read";
    case rpcgen::open_delegation_type4::OPEN_DELEGATE_WRITE: return out << "write";
    }
    return out;
}


std::ostream& operator<<(std::ostream& out, const rpcgen::open_claim_type4& obj)
{
    switch(obj)
    {
    case rpcgen::open_claim_type4::CLAIM_NULL:          return out << "null";
    case rpcgen::open_claim_type4::CLAIM_PREVIOUS:      return out << "previous";
    case rpcgen::open_claim_type4::CLAIM_DELEGATE_CUR:  return out << "delegate current";
    case rpcgen::open_claim_type4::CLAIM_DELEGATE_PREV: return out << "delegate previous";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::rpc_gss_svc_t& obj)
{
    switch(obj)
    {
    case rpcgen::rpc_gss_svc_t::RPC_GSS_SVC_NONE:      return out << "none";
    case rpcgen::rpc_gss_svc_t::RPC_GSS_SVC_INTEGRITY: return out << "integrity";
    case rpcgen::rpc_gss_svc_t::RPC_GSS_SVC_PRIVACY:   return out << "privacy";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::stable_how4& obj)
{
    switch(obj)
    {
    case rpcgen::stable_how4::UNSTABLE4:  return out << "unstable";
    case rpcgen::stable_how4::DATA_SYNC4: return out << "data sync";
    case rpcgen::stable_how4::FILE_SYNC4: return out << "file sync";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::createhow4& obj)
{
    out <<  "mode: "       << obj.mode;
    switch(obj.mode)
    {
    case rpcgen::createmode4::UNCHECKED4:
    case rpcgen::createmode4::GUARDED4:
        return out << " attributes: " << obj.createhow4_u.createattrs;
    case rpcgen::createmode4::EXCLUSIVE4:
        return out << " verifier: "   << obj.createhow4_u.createverf;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::openflag4& obj)
{
    out <<  "open type: " << obj.opentype;
    if(obj.opentype == rpcgen::opentype4::OPEN4_CREATE)
         return out << " how: " << obj.openflag4_u.how;
    else return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_modified_limit4& obj)
{
    return out <<  "blocks number: "   << obj.num_blocks
               << " bytes per block: " << obj.bytes_per_block;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_space_limit4& obj)
{
    out <<  "limit by: "        << obj.limitby;
    switch(obj.limitby)
    {
    case rpcgen::limit_by4::NFS_LIMIT_SIZE:
        return out << " filesize: "        << obj.nfs_space_limit4_u.filesize;
    case rpcgen::limit_by4::NFS_LIMIT_BLOCKS:
        return out << " modified blocks: " << obj.nfs_space_limit4_u.mod_blocks;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_claim_delegate_cur4& obj)
{
    return out <<  "delegate state id: " << obj.delegate_stateid
               << " file: "              << obj.file;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_claim4& obj)
{
    out <<  "claim: " << obj.claim;
    switch(obj.claim)
    {
    case rpcgen::open_claim_type4::CLAIM_NULL:
                                    return out << " file: " << obj.open_claim4_u.file;
    case rpcgen::open_claim_type4::CLAIM_PREVIOUS:
                           return out << " delegate type: " << obj.open_claim4_u.delegate_type;
    case rpcgen::open_claim_type4::CLAIM_DELEGATE_CUR:
                   return out << " delegate current info: " << obj.open_claim4_u.delegate_cur_info;
    case rpcgen::open_claim_type4::CLAIM_DELEGATE_PREV:
                  return out << " file delegate previous: " << obj.open_claim4_u.file_delegate_prev;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_read_delegation4& obj)
{
    return out <<  "stateid: "     << obj.stateid
               << " recall: "      << obj.recall
               << " permissions: " << obj.permissions;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_write_delegation4& obj)
{
    return out <<  "stateid: "     << obj.stateid
               << " recall: "      << obj.recall
               << " space limit: " << obj.space_limit
               << " permissions: " << obj.permissions;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_delegation4& obj)
{
    out <<  "type: "  << obj.delegation_type;
    switch(obj.delegation_type)
    {
    case rpcgen::open_delegation_type4::OPEN_DELEGATE_NONE:
        return out << " none";
    case rpcgen::open_delegation_type4::OPEN_DELEGATE_READ:
        return out << " read: "  << obj.open_delegation4_u.read;
    case rpcgen::open_delegation_type4::OPEN_DELEGATE_WRITE:
        return out << " write: " << obj.open_delegation4_u.write;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::entry4& obj)
{
    out <<  "cookie: "     << obj.cookie
        << " name: "       << obj.name
        << " attributes: " << obj.attrs;
    if(obj.nextentry) return out << " " << *obj.nextentry;
    else              return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::dirlist4& obj)
{
    out <<  "eof: " << obj.eof;
    if(obj.entries) return out << " entries: "
                               << *obj.entries;
    else            return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::rpcsec_gss_info& obj)
{
    return out <<  "oid: "     << obj.oid
               << " qop: "     << obj.qop
               << " service: " << obj.service;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::secinfo4& obj)
{
    out <<  "flavor: " << obj.flavor;
    if(obj.flavor == RPCSEC_GSS) return out << " info: " << obj.secinfo4_u.flavor_info;
    else                         return out;
}

} // namespace NFS4
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
