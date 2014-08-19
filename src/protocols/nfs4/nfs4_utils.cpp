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
        case nfs_ftype4::NF4REG:       out << "REG";       break;
        case nfs_ftype4::NF4DIR:       out << "DIR";       break;
        case nfs_ftype4::NF4BLK:       out << "BLK";       break;
        case nfs_ftype4::NF4CHR:       out << "CHR";       break;
        case nfs_ftype4::NF4LNK:       out << "LNK";       break;
        case nfs_ftype4::NF4SOCK:      out << "SOCK";      break;
        case nfs_ftype4::NF4FIFO:      out << "FIFO";      break;
        case nfs_ftype4::NF4ATTRDIR:   out << "ATTRDIR";   break;
        case nfs_ftype4::NF4NAMEDATTR: out << "NAMEDATTR"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfsstat4& obj)
{
    switch(obj)
    {
        case nfsstat4::NFS4_OK:                     out << "OK";                         break;
        case nfsstat4::NFS4ERR_PERM:                out << "ERROR_PERM";                 break;
        case nfsstat4::NFS4ERR_NOENT:               out << "ERROR_NOENT";                break;
        case nfsstat4::NFS4ERR_IO:                  out << "ERROR_IO";                   break;
        case nfsstat4::NFS4ERR_NXIO:                out << "ERROR_NXIO";                 break;
        case nfsstat4::NFS4ERR_ACCESS:              out << "ERROR_ACCESS";               break;
        case nfsstat4::NFS4ERR_EXIST:               out << "ERROR_EXIST";                break;
        case nfsstat4::NFS4ERR_XDEV:                out << "ERROR_XDEV";                 break;
        case nfsstat4::NFS4ERR_NOTDIR:              out << "ERROR_NOTDIR";               break;
        case nfsstat4::NFS4ERR_ISDIR:               out << "ERROR_ISDIR";                break;
        case nfsstat4::NFS4ERR_INVAL:               out << "ERROR_INVAL";                break;
        case nfsstat4::NFS4ERR_FBIG:                out << "ERROR_FBIG";                 break;
        case nfsstat4::NFS4ERR_NOSPC:               out << "ERROR_NOSPC";                break;
        case nfsstat4::NFS4ERR_ROFS:                out << "ERROR_ROFS";                 break;
        case nfsstat4::NFS4ERR_MLINK:               out << "ERROR_MLINK";                break;
        case nfsstat4::NFS4ERR_NAMETOOLONG:         out << "ERROR_NAMETOOLONG";          break;
        case nfsstat4::NFS4ERR_NOTEMPTY:            out << "ERROR_NOTEMPTY";             break;
        case nfsstat4::NFS4ERR_DQUOT:               out << "ERROR_DQUOT";                break;
        case nfsstat4::NFS4ERR_STALE:               out << "ERROR_STALE";                break;
        case nfsstat4::NFS4ERR_BADHANDLE:           out << "ERROR_BADHANDLE";            break;
        case nfsstat4::NFS4ERR_BAD_COOKIE:          out << "ERROR_BAD_COOKIE";           break;
        case nfsstat4::NFS4ERR_NOTSUPP:             out << "ERROR_NOTSUPP";              break;
        case nfsstat4::NFS4ERR_TOOSMALL:            out << "ERROR_TOOSMALL";             break;
        case nfsstat4::NFS4ERR_SERVERFAULT:         out << "ERROR_SERVERFAULT";          break;
        case nfsstat4::NFS4ERR_BADTYPE:             out << "ERROR_BADTYPE";              break;
        case nfsstat4::NFS4ERR_DELAY:               out << "ERROR_DELAY";                break;
        case nfsstat4::NFS4ERR_SAME:                out << "ERROR_SAME";                 break;
        case nfsstat4::NFS4ERR_DENIED:              out << "ERROR_DENIED";               break;
        case nfsstat4::NFS4ERR_EXPIRED:             out << "ERROR_EXPIRED";              break;
        case nfsstat4::NFS4ERR_LOCKED:              out << "ERROR_LOCKED";               break;
        case nfsstat4::NFS4ERR_GRACE:               out << "ERROR_GRACE";                break;
        case nfsstat4::NFS4ERR_FHEXPIRED:           out << "ERROR_FHEXPIRED";            break;
        case nfsstat4::NFS4ERR_SHARE_DENIED:        out << "ERROR_SHARE_DENIED";         break;
        case nfsstat4::NFS4ERR_WRONGSEC:            out << "ERROR_WRONGSEC";             break;
        case nfsstat4::NFS4ERR_CLID_INUSE:          out << "ERROR_CLID_INUSE";           break;
        case nfsstat4::NFS4ERR_RESOURCE:            out << "ERROR_RESOURCE";             break;
        case nfsstat4::NFS4ERR_MOVED:               out << "ERROR_MOVED";                break;
        case nfsstat4::NFS4ERR_NOFILEHANDLE:        out << "ERROR_NOFILEHANDLE";         break;
        case nfsstat4::NFS4ERR_MINOR_VERS_MISMATCH: out << "ERROR_MINOR_VERS_MISMATCH";  break;
        case nfsstat4::NFS4ERR_STALE_CLIENTID:      out << "ERROR_STALE_CLIENTID";       break;
        case nfsstat4::NFS4ERR_STALE_STATEID:       out << "ERROR_STALE_STATEID";        break;
        case nfsstat4::NFS4ERR_OLD_STATEID:         out << "ERROR_OLD_STATEID";          break;
        case nfsstat4::NFS4ERR_BAD_STATEID:         out << "ERROR_BAD_STATEID";          break;
        case nfsstat4::NFS4ERR_BAD_SEQID:           out << "ERROR_BAD_SEQID";            break;
        case nfsstat4::NFS4ERR_NOT_SAME:            out << "ERROR_NOT_SAME";             break;
        case nfsstat4::NFS4ERR_LOCK_RANGE:          out << "ERROR_LOCK_RANGE";           break;
        case nfsstat4::NFS4ERR_SYMLINK:             out << "ERROR_SYMLINK";              break;
        case nfsstat4::NFS4ERR_RESTOREFH:           out << "ERROR_RESTOREFH";            break;
        case nfsstat4::NFS4ERR_LEASE_MOVED:         out << "ERROR_LEASE_MOVED";          break;
        case nfsstat4::NFS4ERR_ATTRNOTSUPP:         out << "ERROR_ATTRNOTSUPP";          break;
        case nfsstat4::NFS4ERR_NO_GRACE:            out << "ERROR_NO_GRACE";             break;
        case nfsstat4::NFS4ERR_RECLAIM_BAD:         out << "ERROR_RECLAIM_BAD";          break;
        case nfsstat4::NFS4ERR_RECLAIM_CONFLICT:    out << "ERROR_RECLAIM_CONFLICT";     break;
        case nfsstat4::NFS4ERR_BADXDR:              out << "ERROR_BADXDR";               break;
        case nfsstat4::NFS4ERR_LOCKS_HELD:          out << "ERROR_LOCKS_HELD";           break;
        case nfsstat4::NFS4ERR_OPENMODE:            out << "ERROR_OPENMODE";             break;
        case nfsstat4::NFS4ERR_BADOWNER:            out << "ERROR_BADOWNER";             break;
        case nfsstat4::NFS4ERR_BADCHAR:             out << "ERROR_BADCHAR";              break;
        case nfsstat4::NFS4ERR_BADNAME:             out << "ERROR_BADNAME";              break;
        case nfsstat4::NFS4ERR_BAD_RANGE:           out << "ERROR_BAD_RANGE";            break;
        case nfsstat4::NFS4ERR_LOCK_NOTSUPP:        out << "ERROR_LOCK_NOTSUPP";         break;
        case nfsstat4::NFS4ERR_OP_ILLEGAL:          out << "ERROR_OP_ILLEGAL";           break;
        case nfsstat4::NFS4ERR_DEADLOCK:            out << "ERROR_DEADLOCK";             break;
        case nfsstat4::NFS4ERR_FILE_OPEN:           out << "ERROR_FILE_OPEN";            break;
        case nfsstat4::NFS4ERR_ADMIN_REVOKED:       out << "ERROR_ADMIN_REVOKED";        break;
        case nfsstat4::NFS4ERR_CB_PATH_DOWN:        out << "ERROR_CB_PATH_DOWN";         break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::bitmap4& obj)
{
    if(obj.bitmap4_len) out << *obj.bitmap4_val;
    else out << "(empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::utf8string& obj)
{
    if(obj.utf8string_len) out << *obj.utf8string_val;
    else out << "(empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::pathname4& obj)
{
    if(obj.pathname4_len) out << *obj.pathname4_val;
    else out << "(empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::sec_oid4& obj)
{
    if(obj.sec_oid4_len) out << *obj.sec_oid4_val;
    else out << "(empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfstime4& obj)
{
    out <<  "sec: "  << obj.seconds
        << " nsec: " << obj.nseconds;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::time_how4& obj)
{
    switch(obj)
    {
    case time_how4::SET_TO_SERVER_TIME4: out << "server time"; break;
    case time_how4::SET_TO_CLIENT_TIME4: out << "client time"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::settime4& obj)
{
    out << obj.set_it << ": " << obj.settime4_u.time;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_fh4& obj)
{
    if(obj.nfs_fh4_len) out << *obj.nfs_fh4_val;
    else out << "(empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fsid4& obj)
{
    out <<  "major: "  << obj.major
        << " minor: "  << obj.minor;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fs_location4& obj)
{
    out <<  "root path: " << obj.rootpath
        << " locations: ";
    if(obj.server.server_len) out << *obj.server.server_val;
    else out << "(empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fs_locations4& obj)
{
    out <<  "root: " << obj.fs_root
        << " locations: ";
    if(obj.locations.locations_len) out << *obj.locations.locations_val;
    else out << "(empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfsace4& obj)
{
    out <<  "type: "        << obj.type
        << " flag: "        << obj.flag
        << " access mask: " << obj.access_mask
        << " who: "         << obj.who;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::specdata4& obj)
{
    out <<  "specdata 1: " << obj.specdata1
        << " specdata 2: " << obj.specdata2;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fattr4_acl& obj)
{
    if(obj.fattr4_acl_len) out << *obj.fattr4_acl_val;
    else out << "(empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::attrlist4& obj)
{
    if(obj.attrlist4_len) out << *obj.attrlist4_val;
    else out << "(empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::fattr4& obj)
{
    out <<  "mask: " << obj.attrmask
        << " val: "  << obj.attr_vals;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::change_info4& obj)
{
    out <<  "atomic: " << obj.atomic
        << " before: " << obj.before
        << " after: "  << obj.after;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::clientaddr4& obj)
{
    out <<  "netid: " << *obj.r_netid
        << " addr: "  << *obj.r_addr;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::cb_client4& obj)
{
    out <<  "program: "  << obj.cb_program
        << " location: " << obj.cb_location;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::stateid4& obj)
{
    out << obj.seqid
        << " other: " << obj.other;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_client_id4& obj)
{
    out <<  "verifier: "  <<  obj.verifier;
    if(obj.id.id_len) out << " " << *obj.id.id_val;
    else out << " (empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_owner4& obj)
{
    out <<  "client id: " <<  obj.clientid;
    if(obj.owner.owner_len) out << " " <<  *obj.owner.owner_val;
    else out << " (empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::lock_owner4& obj)
{
    out <<  "client id: " <<  obj.clientid;
    if(obj.owner.owner_len) out << " " << *obj.owner.owner_val;
    else out << " (empty)";
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_lock_type4& obj)
{
    switch(obj)
    {
    case nfs_lock_type4::READ_LT:   out << "READ_LOCK_TYPE";   break;
    case nfs_lock_type4::WRITE_LT:  out << "WRITE_LOCK_TYPE";  break;
    case nfs_lock_type4::READW_LT:  out << "READW_LOCK_TYPE";  break;
    case nfs_lock_type4::WRITEW_LT: out << "WRITEW_LOCK_TYPE"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::createtype4& obj)
{
    out <<  "type: "      << obj.type;
    switch(obj.type)
    {
        case nfs_ftype4::NF4BLK:
        case nfs_ftype4::NF4CHR: out << " dev data: "  << obj.createtype4_u.devdata;  break;
        case nfs_ftype4::NF4LNK: out << " link data: " << obj.createtype4_u.linkdata; break;
        default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::dir_delegation_status4& obj)
{
    switch(obj)
    {
    case dir_delegation_status4::NFS4_DIR_DELEGATION_NONE:    out << "none";        break;
    case dir_delegation_status4::NFS4_DIR_DELEGATION_READ:    out << "read";        break;
    case dir_delegation_status4::NFS4_DIR_DELEGATION_DENIED:  out << "denied";      break;
    case dir_delegation_status4::NFS4_DIR_DELEGATION_UNAVAIL: out << "unavailable"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_to_lock_owner4& obj)
{
    out <<  "open seqid: "    << obj.open_seqid
        << " open state id: " << obj.open_stateid
        << " lock seqid: "    << obj.lock_seqid
        << " lock owner: "    << obj.lock_owner;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::exist_lock_owner4& obj)
{
    out <<  "lock state id: " << obj.lock_stateid
        << " lock seqid: "    << obj.lock_seqid;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::locker4& obj)
{
    out <<  "new lock owner: " << obj.new_lock_owner;
    switch (obj.new_lock_owner)
    {
    case TRUE:
        out << " open owner: " << obj.locker4_u.open_owner; break;
    case FALSE:
        out << " lock owner: " << obj.locker4_u.lock_owner; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::createmode4& obj)
{
    switch(obj)
    {
    case createmode4::UNCHECKED4: out << "unchecked"; break;
    case createmode4::GUARDED4:   out << "guarded";   break;
    case createmode4::EXCLUSIVE4: out << "exclusive"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::opentype4& obj)
{
    switch(obj)
    {
    case opentype4::OPEN4_NOCREATE: out << "no create"; break;
    case opentype4::OPEN4_CREATE:   out << "create";    break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::limit_by4& obj)
{
    switch(obj)
    {
    case limit_by4::NFS_LIMIT_SIZE:   out << "size";   break;
    case limit_by4::NFS_LIMIT_BLOCKS: out << "blocks"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_delegation_type4& obj)
{
    switch(obj)
    {
    case open_delegation_type4::OPEN_DELEGATE_NONE:  out << "none";  break;
    case open_delegation_type4::OPEN_DELEGATE_READ:  out << "read";  break;
    case open_delegation_type4::OPEN_DELEGATE_WRITE: out << "write"; break;
    }
    return out;
}


std::ostream& operator<<(std::ostream& out, const rpcgen::open_claim_type4& obj)
{
    switch(obj)
    {
    case open_claim_type4::CLAIM_NULL:          out << "null";              break;
    case open_claim_type4::CLAIM_PREVIOUS:      out << "previous";          break;
    case open_claim_type4::CLAIM_DELEGATE_CUR:  out << "delegate current";  break;
    case open_claim_type4::CLAIM_DELEGATE_PREV: out << "delegate previous"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::rpc_gss_svc_t& obj)
{
    switch(obj)
    {
    case rpc_gss_svc_t::RPC_GSS_SVC_NONE:      out << "none";      break;
    case rpc_gss_svc_t::RPC_GSS_SVC_INTEGRITY: out << "integrity"; break;
    case rpc_gss_svc_t::RPC_GSS_SVC_PRIVACY:   out << "privacy";   break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::stable_how4& obj)
{
    switch(obj)
    {
    case stable_how4::UNSTABLE4:  out << "unstable";  break;
    case stable_how4::DATA_SYNC4: out << "data sync"; break;
    case stable_how4::FILE_SYNC4: out << "file sync"; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::createhow4& obj)
{
    out <<  "mode: "       << obj.mode;
    switch(obj.mode)
    {
    case createmode4::UNCHECKED4:
    case createmode4::GUARDED4:
        out << " attributes: " << obj.createhow4_u.createattrs; break;
    case createmode4::EXCLUSIVE4:
        out << " verifier: "   << obj.createhow4_u.createverf;  break;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::openflag4& obj)
{
    out <<  "open type: " << obj.opentype;
    switch(obj.opentype)
    {
    case opentype4::OPEN4_CREATE:
        out << " how: "       << obj.openflag4_u.how; break;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_modified_limit4& obj)
{
    out <<  "blocks number: "   << obj.num_blocks
        << " bytes per block: " << obj.bytes_per_block;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::nfs_space_limit4& obj)
{
    out <<  "limit by: "        << obj.limitby;
    switch(obj.limitby)
    {
    case limit_by4::NFS_LIMIT_SIZE:
        out << " filesize: "        << obj.nfs_space_limit4_u.filesize;   break;
    case limit_by4::NFS_LIMIT_BLOCKS:
        out << " modified blocks: " << obj.nfs_space_limit4_u.mod_blocks; break;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_claim_delegate_cur4& obj)
{
    out <<  "delegate state id: " << obj.delegate_stateid
        << " file: "              << obj.file;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_claim4& obj)
{
    out <<  "claim: " << obj.claim;
    switch(obj.claim)
    {
    case open_claim_type4::CLAIM_NULL:
                               out << " file: " << obj.open_claim4_u.file;               break;
    case open_claim_type4::CLAIM_PREVIOUS:
                      out << " delegate type: " << obj.open_claim4_u.delegate_type;      break;
    case open_claim_type4::CLAIM_DELEGATE_CUR:
              out << " delegate current info: " << obj.open_claim4_u.delegate_cur_info;  break;
    case open_claim_type4::CLAIM_DELEGATE_PREV:
             out << " file delegate previous: " << obj.open_claim4_u.file_delegate_prev; break;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_read_delegation4& obj)
{
    out <<  "stateid: "     << obj.stateid
        << " recall: "      << obj.recall
        << " permissions: " << obj.permissions;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_write_delegation4& obj)
{
    out <<  "stateid: "     << obj.stateid
        << " recall: "      << obj.recall
        << " space limit: " << obj.space_limit
        << " permissions: " << obj.permissions;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::open_delegation4& obj)
{
    out <<  "type: "  << obj.delegation_type;
    switch(obj.delegation_type)
    {
    case open_delegation_type4::OPEN_DELEGATE_NONE:  out << " none";  break;
    case open_delegation_type4::OPEN_DELEGATE_READ:  out << " read: "
                                      << obj.open_delegation4_u.read; break;
    case open_delegation_type4::OPEN_DELEGATE_WRITE: out << " write: "
                                     << obj.open_delegation4_u.write; break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::entry4& obj)
{
    out <<  "cookie: "     << obj.cookie
        << " name: "       << obj.name
        << " attributes: " << obj.attrs;
    if(obj.nextentry)  out << " " << *obj.nextentry;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::dirlist4& obj)
{
    out <<  "eof: " << obj.eof;
    if(obj.entries)
    {
        out << " entries: ";
        out << *obj.entries;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::rpcsec_gss_info& obj)
{
    out <<  "oid: " << obj.oid
        << " qop: " << obj.qop
        << " service: " << obj.service;
    return out;
}

std::ostream& operator<<(std::ostream& out, const rpcgen::secinfo4& obj)
{
    out <<  "flavor: " << obj.flavor;
    switch(obj.flavor)
    {
    case RPCSEC_GSS:
      out << " info: " << obj.secinfo4_u.flavor_info; break;
    default: break;
    }
    return out;
}

} // namespace NFS4
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
