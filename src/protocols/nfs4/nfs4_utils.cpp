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
#include <cassert>

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
    print_nfs4_procedures(out, proc);
    return out;
}

void print_nfs4_procedures(std::ostream& out, const ProcEnumNFS4::NFSProcedure proc)
{
    out << NFS4ProcedureTitles[proc];
}

std::ostream& operator<<(std::ostream& out, const nfs_ftype4& obj)
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

std::ostream& operator<<(std::ostream& out, const nfsstat4& obj)
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

std::ostream& operator<<(std::ostream& out, const bitmap4& obj)
{
    out <<  "len: " <<  obj.bitmap4_len;
    out << " val: " << *obj.bitmap4_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const utf8string& obj)
{
    out <<  "len: " <<  obj.utf8string_len;
    out << " val: " << *obj.utf8string_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const pathname4& obj)
{
    out <<  "len: " <<  obj.pathname4_len;
    out << " val: " << *obj.pathname4_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const sec_oid4& obj)
{
    out <<  "len: " <<  obj.sec_oid4_len;
    out << " val: " << *obj.sec_oid4_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfstime4& obj)
{
    out <<  "sec: "  << obj.seconds;
    out << " nsec: " << obj.nseconds;
    return out;
}

std::ostream& operator<<(std::ostream& out, const time_how4& obj)
{
    switch(obj)
    {
    case time_how4::SET_TO_SERVER_TIME4:    out << "SET_TO_SERVER_TIME";    break;
    case time_how4::SET_TO_CLIENT_TIME4:    out << "SET_TO_CLIENT_TIME";    break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const settime4& obj)
{
    out << obj.set_it << ": " << obj.settime4_u.time;
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfs_fh4& obj)
{
    out <<  "len: " <<  obj.nfs_fh4_len;
    out << " val: " << *obj.nfs_fh4_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const fsid4& obj)
{
    out <<  "major: "  << obj.major;
    out << " minor: "  << obj.minor;
    return out;
}

std::ostream& operator<<(std::ostream& out, const fs_location4& obj)
{
    out <<  "root path: "      <<  obj.rootpath;
    out << " locations: len: " <<  obj.server.server_len; 
    out << " val: "            << *obj.server.server_val; 
    return out;
}

std::ostream& operator<<(std::ostream& out, const fs_locations4& obj)
{
    out <<  "root: "           << obj.fs_root;
    out << " locations: len: " << obj.locations.locations_len; 
    out << " val: "            << *obj.locations.locations_val; 
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfsace4& obj)
{
    out <<  "type: "        << obj.type;
    out << " flag: "        << obj.flag;
    out << " access mask: " << obj.access_mask;
    out << " who: "         << obj.who;
    return out;
}

std::ostream& operator<<(std::ostream& out, const specdata4& obj)
{
    out <<  "specdata 1: " << obj.specdata1; 
    out << " specdata 2: " << obj.specdata2; 
    return out;
}

std::ostream& operator<<(std::ostream& out, const fattr4_acl& obj)
{
    out <<  "len: " <<  obj.fattr4_acl_len;
    out << " val: " << *obj.fattr4_acl_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const attrlist4& obj)
{
    out <<  "len: " <<  obj.attrlist4_len;
    out << " val: " << *obj.attrlist4_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const fattr4& obj)
{
    out <<  "mask: " << obj.attrmask;
    out << " val: "  << obj.attr_vals;
    return out;
}

std::ostream& operator<<(std::ostream& out, const change_info4& obj)
{
    out <<  "atomic: " << obj.atomic;
    out << " before: " << obj.before;
    out << " after: "  << obj.after;
    return out;
}

std::ostream& operator<<(std::ostream& out, const clientaddr4& obj)
{
    out <<  "netid: " << *obj.r_netid;
    out << " addr: "  << *obj.r_addr;
    return out;
}

std::ostream& operator<<(std::ostream& out, const cb_client4& obj)
{
    out <<  "program: "  << obj.cb_program;
    out << " location: " << obj.cb_location;
    return out;
}

std::ostream& operator<<(std::ostream& out, const stateid4& obj)
{
    out <<  "id: "    << obj.seqid;
    out << " other: " << obj.other;
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfs_client_id4& obj)
{
    out <<  "verifier: " <<  obj.verifier;
    out << " len: "      <<  obj.id.id_len;
    out << " val: "      << *obj.id.id_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const open_owner4& obj)
{
    out <<  "client id: " <<  obj.clientid;
    out << " len: "       <<  obj.owner.owner_len;
    out << " val: "       << *obj.owner.owner_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const lock_owner4& obj)
{
    out <<  "client id: " <<  obj.clientid;
    out << " len: "       <<  obj.owner.owner_len;
    out << " val: "       << *obj.owner.owner_val;
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfs_lock_type4& obj)
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

} // namespace NFS4
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
