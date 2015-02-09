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

#include "protocols/nfs/nfs_utils.h"
#include "protocols/nfs4/nfs41_utils.h"
//------------------------------------------------------------------------------
using namespace NST::API::NFS41;
using namespace NST::protocols::NFS;  // NFS helpers
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS41
{

std::ostream& operator<<(std::ostream& out, const ProcEnumNFS41::NFSProcedure proc)
{
    return out << print_nfs41_procedures(proc);
}

const char* print_nfs41_procedures(const ProcEnumNFS41::NFSProcedure proc)
{
    // In all cases we suppose, that NFSv4 operation ILLEGAL(10044)
    // has the second position in ProcEnumNFS41
    uint32_t i = proc;
    if(proc == ProcEnumNFS41::ILLEGAL) i = 2;

    static const char* const NFS41ProcedureTitles[(ProcEnumNFS41::count+1)] =
    {
    "NULL","COMPOUND",      "ILLEGAL",            "ACCESS",           "CLOSE",
    "COMMIT",               "CREATE",             "DELEGPURGE",       "DELEGRETURN",
    "GETATTR",              "GETFH",              "LINK",             "LOCK",
    "LOCKT",                "LOCKU",              "LOOKUP",           "LOOKUPP",
    "NVERIFY",              "OPEN",               "OPENATTR",         "OPEN_CONFIRM",
    "OPEN_DOWNGRADE",       "PUTFH",              "PUTPUBFH",         "PUTROOTFH",
    "READ",                 "READDIR",            "READLINK",         "REMOVE",
    "RENAME",               "RENEW",              "RESTOREFH",        "SAVEFH",
    "SECINFO",              "SETATTR",            "SETCLIENTID",      "SETCLIENTID_CONFIRM",
    "VERIFY",               "WRITE",              "RELEASE_LOCKOWNER","BACKCHANNEL_CTL",
    "BIND_CONN_TO_SESSION", "EXCHANGE_ID",        "CREATE_SESSION",   "DESTROY_SESSION",
    "FREE_STATEID",         "GET_DIR_DELEGATION", "GETDEVICEINFO",    "GETDEVICELIST",
    "LAYOUTCOMMIT",         "LAYOUTGET",          "LAYOUTRETURN",     "SECINFO_NO_NAME",
    "SEQUENCE",             "SET_SSV",            "TEST_STATEID",     "WANT_DELEGATION",
    "DESTROY_CLIENTID",     "RECLAIM_COMPLETE"
    };

    return NFS41ProcedureTitles[i];
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
    case nfsstat4::NFS4ERR_BADIOMODE:
        return out << "NFS4ERR_BADIOMODE";
    case nfsstat4::NFS4ERR_BADLAYOUT:
        return out << "NFS4ERR_BADLAYOUT";
    case nfsstat4::NFS4ERR_BAD_SESSION_DIGEST:
        return out << "NFS4ERR_BAD_SESSION_DIGEST";
    case nfsstat4::NFS4ERR_BADSESSION:
        return out << "NFS4ERR_BADSESSION";
    case nfsstat4::NFS4ERR_BADSLOT:
        return out << "NFS4ERR_BADSLOT";
    case nfsstat4::NFS4ERR_COMPLETE_ALREADY:
        return out << "NFS4ERR_COMPLETE_ALREADY";
    case nfsstat4::NFS4ERR_CONN_NOT_BOUND_TO_SESSION:
        return out << "NFS4ERR_CONN_NOT_BOUND_TO_SESSION";
    case nfsstat4::NFS4ERR_DELEG_ALREADY_WANTED:
        return out << "NFS4ERR_DELEG_ALREADY_WANTED";
    case nfsstat4::NFS4ERR_BACK_CHAN_BUSY:
        return out << "NFS4ERR_BACK_CHAN_BUSY";
    case nfsstat4::NFS4ERR_LAYOUTTRYLATER:
        return out << "NFS4ERR_LAYOUTTRYLATER";
    case nfsstat4::NFS4ERR_LAYOUTUNAVAILABLE:
        return out << "NFS4ERR_LAYOUTUNAVAILABLE";
    case nfsstat4::NFS4ERR_NOMATCHING_LAYOUT:
        return out << "NFS4ERR_NOMATCHING_LAYOUT";
    case nfsstat4::NFS4ERR_RECALLCONFLICT:
        return out << "NFS4ERR_RECALLCONFLICT";
    case nfsstat4::NFS4ERR_UNKNOWN_LAYOUTTYPE:
        return out << "NFS4ERR_UNKNOWN_LAYOUTTYPE";
    case nfsstat4::NFS4ERR_SEQ_MISORDERED:
        return out << "NFS4ERR_SEQ_MISORDERED";
    case nfsstat4::NFS4ERR_SEQUENCE_POS:
        return out << "NFS4ERR_SEQUENCE_POS";
    case nfsstat4::NFS4ERR_REQ_TOO_BIG:
        return out << "NFS4ERR_REQ_TOO_BIG";
    case nfsstat4::NFS4ERR_REP_TOO_BIG:
        return out << "NFS4ERR_REP_TOO_BIG";
    case nfsstat4::NFS4ERR_REP_TOO_BIG_TO_CACHE:
        return out << "NFS4ERR_REP_TOO_BIG_TO_CACHE";
    case nfsstat4::NFS4ERR_RETRY_UNCACHED_REP:
        return out << "NFS4ERR_RETRY_UNCACHED_REP";
    case nfsstat4::NFS4ERR_UNSAFE_COMPOUND:
        return out << "NFS4ERR_UNSAFE_COMPOUND";
    case nfsstat4::NFS4ERR_TOO_MANY_OPS:
        return out << "NFS4ERR_TOO_MANY_OPS";
    case nfsstat4::NFS4ERR_OP_NOT_IN_SESSION:
        return out << "NFS4ERR_OP_NOT_IN_SESSION";
    case nfsstat4::NFS4ERR_HASH_ALG_UNSUPP:
        return out << "NFS4ERR_HASH_ALG_UNSUPP";
    case nfsstat4::NFS4ERR_CLIENTID_BUSY:
        return out << "NFS4ERR_CLIENTID_BUSY";
    case nfsstat4::NFS4ERR_PNFS_IO_HOLE:
        return out << "NFS4ERR_PNFS_IO_HOLE";
    case nfsstat4::NFS4ERR_SEQ_FALSE_RETRY:
        return out << "NFS4ERR_SEQ_FALSE_RETRY";
    case nfsstat4::NFS4ERR_BAD_HIGH_SLOT:
        return out << "NFS4ERR_BAD_HIGH_SLOT";
    case nfsstat4::NFS4ERR_DEADSESSION:
        return out << "NFS4ERR_DEADSESSION";
    case nfsstat4::NFS4ERR_ENCR_ALG_UNSUPP:
        return out << "NFS4ERR_ENCR_ALG_UNSUPP";
    case nfsstat4::NFS4ERR_PNFS_NO_LAYOUT:
        return out << "NFS4ERR_PNFS_NO_LAYOUT";
    case nfsstat4::NFS4ERR_NOT_ONLY_OP:
        return out << "NFS4ERR_NOT_ONLY_OP";
    case nfsstat4::NFS4ERR_WRONG_CRED:
        return out << "NFS4ERR_WRONG_CRED";
    case nfsstat4::NFS4ERR_WRONG_TYPE:
        return out << "NFS4ERR_WRONG_TYPE";
    case nfsstat4::NFS4ERR_DIRDELEG_UNAVAIL:
        return out << "NFS4ERR_DIRDELEG_UNAVAIL";
    case nfsstat4::NFS4ERR_REJECT_DELEG:
        return out << "NFS4ERR_REJECT_DELEG";
    case nfsstat4::NFS4ERR_RETURNCONFLICT:
        return out << "NFS4ERR_RETURNCONFLICT";
    case nfsstat4::NFS4ERR_DELEG_REVOKED:
        return out << "NFS4ERR_DELEG_REVOKED";
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
            "SUPPORTED_ATTRS", "TYPE",              "FH_EXPIRE_TYPE",  "CHANGE",
            "SIZE",            "LINK_SUPPORT",      "SYMLINK_SUPPORT", "NAMED_ATTR",
            "FSID",            "UNIQUE_HANDLES",    "LEASE_TIME",      "RDATTR_ERROR",
            "ACL",             "ACLSUPPORT",        "ARCHIVE",         "CANSETTIME",
            "CASE_INSENSITIVE","CASE_PRESERVING",   "CHOWN_RESTRICTED","FILEHANDLE",
            "FILEID",          "FILES_AVAIL",       "FILES_FREE",      "FILES_TOTAL",
            "FS_LOCATIONS",    "HIDDEN",            "HOMOGENEOUS",     "MAXFILESIZE",
            "MAXLINK",         "MAXNAME",           "MAXREAD",         "MAXWRITE",
            "MIMETYPE",        "MODE",              "NO_TRUNC",        "NUMLINKS",
            "OWNER",           "OWNER_GROUP",       "QUOTA_AVAIL_HARD","QUOTA_AVAIL_SOFT",
            "QUOTA_USED",      "RAWDEV",            "SPACE_AVAIL",     "SPACE_FREE",
            "SPACE_TOTAL",     "SPACE_USED",        "SYSTEM",          "TIME_ACCESS",
            "TIME_ACCESS_SET", "TIME_BACKUP",       "TIME_CREATE",     "TIME_DELTA",
            "TIME_METADATA",   "TIME_MODIFY",       "TIME_MODIFY_SET", "MOUNTED_ON_FILEID",
            "DIR_NOTIF_DELAY", "DIRENT_NOTIF_DELAY","DACL",            "SACL",
            "CHANGE_POLICY",   "FS_STATUS",         "FS_LAYOUT_TYPES", "LAYOUT_HINT",
            "LAYOUT_TYPES",    "LAYOUT_BLKSIZE",    "LAYOUT_ALIGNMENT","FS_LOCATIONS_INFO",
            "MDSTHRESHOLD",    "RETENTION_GET",     "RETENTION_SET",   "RETENTEVT_GET",
            "RETENTEVT_SET",   "RETENTION_HOLD",    "MODE_SET_MASKED", "SUPPATTR_EXCLCREAT",
            "FS_CHARSET_CAP"
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

std::ostream& operator<<(std::ostream& out, const nfs_fh4& obj)
{
    NFS::print_nfs_fh(out,
                      obj.nfs_fh4_val,
                      obj.nfs_fh4_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const sec_oid4& obj)
{
    print_hex(out,
              obj.sec_oid4_val,
              obj.sec_oid4_len);
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

std::ostream& operator<<(std::ostream& out, const change_policy4& obj)
{
    return out <<  "major: " << obj.cp_major
               << " minor: " << obj.cp_minor;
}

std::ostream& operator<<(std::ostream& out, const nfsacl41& obj)
{
    out <<  "flag: " << obj.na41_flag;
    if(obj.na41_aces.na41_aces_len)
    {
        nfsace4* current_el {obj.na41_aces.na41_aces_val};
        for(u_int i {0}; i<obj.na41_aces.na41_aces_len; i++,current_el++)
        {
           out << ' ' << current_el;
        }
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const mode_masked4& obj)
{
    return out <<  "value to set: " << obj.mm_value_to_set
               << " mask bits: "    << obj.mm_mask_bits;
}

std::ostream& operator<<(std::ostream& out, const specdata4& obj)
{
    return out <<  "specdata 1: " << obj.specdata1
               << " specdata 2: " << obj.specdata2;
}

std::ostream& operator<<(std::ostream& out, const netaddr4& obj)
{
    return out <<  "netid: " << obj.na_r_netid
               << " addr: "  << obj.na_r_addr;
}

std::ostream& operator<<(std::ostream& out, const nfs_impl_id4& obj)
{
    out << "domain: ";
    out.write(obj.nii_domain.utf8string_val,
              obj.nii_domain.utf8string_len);

    out << " name: ";
    out.write(obj.nii_name.utf8string_val,
              obj.nii_name.utf8string_len);

    out << " date: " << obj.nii_date;

    return out;
}

std::ostream& operator<<(std::ostream& out, const stateid4& obj)
{
    out << " seqid: " << std::hex << obj.seqid << " data: ";
    print_hex(out,
              obj.other,
              12);
    return out;
}

std::ostream& operator<<(std::ostream& out, const layouttype4& obj)
{
    switch(obj)
    {
    case layouttype4::LAYOUT4_NFSV4_1_FILES: return out << "NFSV4_1_FILES";
    case layouttype4::LAYOUT4_OSD2_OBJECTS:  return out << "OSD2_OBJECTS";
    case layouttype4::LAYOUT4_BLOCK_VOLUME:  return out << "BLOCK_VOLUME";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const layout_content4& obj)
{
    out << "type: " << obj.loc_type;
    out.write(obj.loc_body.loc_body_val,
              obj.loc_body.loc_body_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const layouthint4& obj)
{
    out << "type: " << obj.loh_type;
    out.write(obj.loh_body.loh_body_val,
              obj.loh_body.loh_body_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const layoutiomode4& obj)
{
    switch(obj)
    {
    case layoutiomode4::LAYOUTIOMODE4_READ: return out << "READ";
    case layoutiomode4::LAYOUTIOMODE4_RW:   return out << "RW";
    case layoutiomode4::LAYOUTIOMODE4_ANY:  return out << "ANYE";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const layout4& obj)
{
    out <<  "offset: "  << obj.lo_offset
        << " length: "  << obj.lo_length
        << " iomode: "  << obj.lo_iomode
        << " content: " << obj.lo_content;
    return out;
}

std::ostream& operator<<(std::ostream& out, const device_addr4& obj)
{
    out <<  "layout type: " << obj.da_layout_type;
    out.write(obj.da_addr_body.da_addr_body_val,
              obj.da_addr_body.da_addr_body_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const layoutupdate4& obj)
{
    out << "type: " << obj.lou_type;
    out.write(obj.lou_body.lou_body_val,
              obj.lou_body.lou_body_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const layoutreturn_type4& obj)
{
    switch(obj)
    {
    case layoutreturn_type4::LAYOUTRETURN4_FILE: return out << "FILE";
    case layoutreturn_type4::LAYOUTRETURN4_FSID: return out << "FSID";
    case layoutreturn_type4::LAYOUTRETURN4_ALL:  return out << "ALL";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const layoutreturn_file4& obj)
{
    out <<  "offset: "  << obj.lrf_offset
        << " length: "  << obj.lrf_length
        << " stateid: " << obj.lrf_stateid
        << " content: ";
    out.write(obj.lrf_body.lrf_body_val,
              obj.lrf_body.lrf_body_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const layoutreturn4& obj)
{
    out << "type: " << obj.lr_returntype;
    if(obj.lr_returntype == layoutreturn_type4::LAYOUTRETURN4_FILE)
        out << " layout: " << obj.layoutreturn4_u.lr_layout; 
    return out;
}

std::ostream& operator<<(std::ostream& out, const fs4_status_type& obj)
{
    switch(obj)
    {
    case fs4_status_type::STATUS4_FIXED:     return out << "FIXED";
    case fs4_status_type::STATUS4_UPDATED:   return out << "UPDATED";
    case fs4_status_type::STATUS4_VERSIONED: return out << "VERSIONED";
    case fs4_status_type::STATUS4_WRITABLE:  return out << "WRITABLE";
    case fs4_status_type::STATUS4_REFERRAL:  return out << "REFERRAL";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const fs4_status& obj)
{
    out <<  "absent: "  << obj.fss_absent
        << " status: "  << obj.fss_type
        << " source: "  << obj.fss_source
        << " current: " << obj.fss_current
        << " age: "     << obj.fss_age
        << " version: " << obj.fss_version;
    return out;
}

std::ostream& operator<<(std::ostream& out, const threshold_item4& obj)
{
    out <<  "layout type: " << obj.thi_layout_type
        << " hint set: "    << obj.thi_hintset
        << " content: ";
    out.write(obj.thi_hintlist.thi_hintlist_val,
              obj.thi_hintlist.thi_hintlist_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const mdsthreshold4& obj)
{
    threshold_item4 *current_el = obj.mth_hints.mth_hints_val;
    for(size_t i {0}; i<obj.mth_hints.mth_hints_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const retention_get4& obj)
{
    out << "duration: " << obj.rg_duration;
    nfstime4 *current_el = obj.rg_begin_time.rg_begin_time_val;
    for(size_t i {0}; i<obj.rg_begin_time.rg_begin_time_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const retention_set4& obj)
{
    out << "enable: " << obj.rs_enable;
    uint64_t *current_el = obj.rs_duration.rs_duration_val;
    for(size_t i {0}; i<obj.rs_duration.rs_duration_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const fattr4_acl& obj)
{
    if(obj.fattr4_acl_len) return out << *obj.fattr4_acl_val;
    else                   return out << "void";
}

std::ostream& operator<<(std::ostream& out, const fattr4_fs_layout_types& obj)
{
    layouttype4 *current_el = obj.fattr4_fs_layout_types_val;
    for(size_t i {0}; i<obj.fattr4_fs_layout_types_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const fattr4_layout_types& obj)
{
    layouttype4 *current_el = obj.fattr4_layout_types_val;
    for(size_t i {0}; i<obj.fattr4_layout_types_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const fattr4& obj)
{
    return out << obj.attrmask;
}

std::ostream& operator<<(std::ostream& out, const change_info4& obj)
{
    out << " atomic: ";
    if(obj.atomic) out << "YES";
    else           out << "NO";

    return out << " change id before: " << obj.before
               << " change id after: "  << obj.after;
}

std::ostream& operator<<(std::ostream& out, const cb_client4& obj)
{
    return out <<  "program: "  << std::hex << obj.cb_program
               << " location: " << obj.cb_location;
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

std::ostream& operator<<(std::ostream& out, const client_owner4& obj)
{
    out <<  "verifier: ";
    print_hex(out,
              obj.co_verifier,
              NFS4_VERIFIER_SIZE);
    out << " client id: ";
    if(obj.co_ownerid.co_ownerid_len)
        out.write(obj.co_ownerid.co_ownerid_val,
                  obj.co_ownerid.co_ownerid_len);
    else out << " void";

    return out;
}

std::ostream& operator<<(std::ostream& out, const server_owner4& obj)
{
    out <<  "minor id: " << obj.so_minor_id;
    out << " major id: ";
    if(obj.so_major_id.so_major_id_len)
        out.write(obj.so_major_id.so_major_id_val,
                  obj.so_major_id.so_major_id_len);
    else out << " void";

    return out;
}

std::ostream& operator<<(std::ostream& out, const state_owner4& obj)
{
    out <<  "client id: 0x" << std::hex << obj.clientid << " owner: 0x";
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

std::ostream& operator<<(std::ostream& out, const ssv_subkey4& obj)
{
    out << "SSV4_SUBKEY_";
    switch(obj)
    {
    case ssv_subkey4::SSV4_SUBKEY_MIC_I2T:  return out << "MIC_I2T";
    case ssv_subkey4::SSV4_SUBKEY_MIC_T2I:  return out << "MIC_T2I";
    case ssv_subkey4::SSV4_SUBKEY_SEAL_I2T: return out << "MIC_I2T";
    case ssv_subkey4::SSV4_SUBKEY_SEAL_T2I: return out << "MIC_T2I";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const ssv_mic_plain_tkn4& obj)
{
    out << "ssv seq: " << obj.smpt_ssv_seq << ' ';
    out.write(obj.smpt_orig_plain.smpt_orig_plain_val,
              obj.smpt_orig_plain.smpt_orig_plain_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const ssv_mic_tkn4& obj)
{
    out << "ssv seq: " << obj.smt_ssv_seq << ' ';
    out.write(obj.smt_hmac.smt_hmac_val,
              obj.smt_hmac.smt_hmac_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const ssv_seal_plain_tkn4& obj)
{
    out << "confounder: ";
    out.write(obj.sspt_confounder.sspt_confounder_val,
              obj.sspt_confounder.sspt_confounder_len);
    out << " ssv seq: " << obj.sspt_ssv_seq
        << " orig plain: ";
    out.write(obj.sspt_orig_plain.sspt_orig_plain_val,
              obj.sspt_orig_plain.sspt_orig_plain_len);
    out << " pad: ";
    out.write(obj.sspt_pad.sspt_pad_val,
              obj.sspt_pad.sspt_pad_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const ssv_seal_cipher_tkn4& obj)
{
    out <<  "ssv seq: " << obj.ssct_ssv_seq
        << " iv: ";
    out.write(obj.ssct_iv.ssct_iv_val,
              obj.ssct_iv.ssct_iv_len);
    out << " encrypted data: ";
    out.write(obj.ssct_encr_data.ssct_encr_data_val,
              obj.ssct_encr_data.ssct_encr_data_len);
    out << " hmac: ";
    out.write(obj.ssct_hmac.ssct_hmac_val,
              obj.ssct_hmac.ssct_hmac_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const fs_locations_server4& obj)
{
    out <<  "currency: " << obj.fls_currency
        << " info: ";
    out.write(obj.fls_info.fls_info_val,
              obj.fls_info.fls_info_len);
    out << " server: " << obj.fls_server;
    return out;
}

std::ostream& operator<<(std::ostream& out, const fs_locations_item4& obj)
{
    fs_locations_server4 *current_el = obj.fli_entries.fli_entries_val;
    for(size_t i {0}; i<obj.fli_entries.fli_entries_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    out << " rootpath: " << obj.fli_rootpath;
    return out;
}

std::ostream& operator<<(std::ostream& out, const fs_locations_info4& obj)
{
    out <<  "flags: "     << obj.fli_flags
        << " valid for: " << obj.fli_valid_for
        << " fs root: "   << obj.fli_fs_root
        << " items:";
    fs_locations_item4 *current_el = obj.fli_items.fli_items_val;
    for(size_t i {0}; i<obj.fli_items.fli_items_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const filelayout_hint_care4& obj)
{
    switch(obj)
    {
    case filelayout_hint_care4::NFLH4_CARE_DENSE:
        return out << "DENSE";
    case filelayout_hint_care4::NFLH4_CARE_COMMIT_THRU_MDS:
        return out << "COMMIT_THRU_MDS";
    case filelayout_hint_care4::NFLH4_CARE_STRIPE_UNIT_SIZE:
        return out << "STRIPE_UNIT_SIZE";
    case filelayout_hint_care4::NFLH4_CARE_STRIPE_COUNT:
        return out << "STRIPE_COUNT";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfsv4_1_file_layouthint4& obj)
{
    out <<  "nflh care: "    << obj.nflh_care
        << " nflh util: "    << obj.nflh_util
        << " stripe count: " << obj.nflh_stripe_count;
    return out;
}

std::ostream& operator<<(std::ostream& out, const multipath_list4& obj)
{
    netaddr4 *current_el = obj.multipath_list4_val;
    for(size_t i {0}; i<obj.multipath_list4_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfsv4_1_file_layout_ds_addr4& obj)
{
    out << "stripe indices: ";
    print_hex(out,
              obj.nflda_stripe_indices.nflda_stripe_indices_val,
              obj.nflda_stripe_indices.nflda_stripe_indices_len);
    out << " multipath ds list: ";
    multipath_list4 *current_el = obj.nflda_multipath_ds_list.nflda_multipath_ds_list_val;
    for(size_t i {0}; i<obj.nflda_multipath_ds_list.nflda_multipath_ds_list_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const nfsv4_1_file_layout4& obj)
{
    out <<  "device id: "        << obj.nfl_deviceid
        << " nfl util: "         << obj.nfl_util
        << " 1st stripe index: " << obj.nfl_first_stripe_index
        << " pattern offset: "   << obj.nfl_pattern_offset
        << " fh list:";
    nfs_fh4 *current_el = obj.nfl_fh_list.nfl_fh_list_val;
    for(size_t i {0}; i<obj.nfl_fh_list.nfl_fh_list_len; i++,current_el++)
    {
        out << ' ';
        print_nfs_fh(out,
                     current_el->nfs_fh4_val,
                     current_el->nfs_fh4_len);
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
    case createmode4::UNCHECKED4:   return out << "UNCHECKED";
    case createmode4::GUARDED4:     return out << "GUARDED";
    case createmode4::EXCLUSIVE4:   return out << "EXCLUSIVE4";
    case createmode4::EXCLUSIVE4_1: return out << "EXCLUSIVE4_1";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const creatverfattr& obj)
{
    out <<  "verf: ";
    print_hex(out, obj.cva_verf, NFS4_VERIFIER_SIZE);
    out << " attrs: " << obj.cva_attrs;
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
    case createmode4::EXCLUSIVE4_1:
        out << " verifier: ";
        print_hex(out, obj.createhow4_u.ch_createboth.cva_verf, NFS4_VERIFIER_SIZE);
    default: break;
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

std::ostream& operator<<(std::ostream& out, const openflag4& obj)
{
    out <<  "open type: " << obj.opentype;
    if(obj.opentype == opentype4::OPEN4_CREATE)
        return out << obj.openflag4_u.how;
    else
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
    case open_delegation_type4::OPEN_DELEGATE_NONE_EXT:
        return out << "NONE_EXT";
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
    case open_claim_type4::CLAIM_FH:
        return out << "FH";
    case open_claim_type4::CLAIM_DELEG_CUR_FH:
        return out << "DELEGATE CURRENT FH";
    case open_claim_type4::CLAIM_DELEG_PREV_FH:
        return out << "DELEGATE PREVIOUS FH";
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
    case open_claim_type4::CLAIM_FH:
    case open_claim_type4::CLAIM_DELEG_PREV_FH:
        break;
    case open_claim_type4::CLAIM_DELEG_CUR_FH:
                  return out << " oc delegate stateid: "
                             << obj.open_claim4_u.oc_delegate_stateid;
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

std::ostream& operator<<(std::ostream& out, const why_no_delegation4& obj)
{
    switch(obj)
    {
    case why_no_delegation4::WND4_NOT_WANTED:
        return out << "NOT WANTED";
    case why_no_delegation4::WND4_CONTENTION:
        return out << "CONTENTION";
    case why_no_delegation4::WND4_RESOURCE:
        return out << "RESOURCE";
    case why_no_delegation4::WND4_NOT_SUPP_FTYPE:
        return out << "NOT_SUPP_FTYPE";
    case why_no_delegation4::WND4_WRITE_DELEG_NOT_SUPP_FTYPE:
        return out << "WRITE_DELEG_NOT_SUPP_FTYPE";
    case why_no_delegation4::WND4_NOT_SUPP_UPGRADE:
        return out << "NOT_SUPP_UPGRADE";
    case why_no_delegation4::WND4_NOT_SUPP_DOWNGRADE:
        return out << "NOT_SUPP_DOWNGRADE";
    case why_no_delegation4::WND4_CANCELLED:
        return out << "CANCELLED";
    case why_no_delegation4::WND4_IS_DIR:
        return out << "IS_DIR";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const open_none_delegation4& obj)
{
    out << "why: " << obj.ond_why;
    switch(obj.ond_why)
    {
    case why_no_delegation4::WND4_CONTENTION:
        out << " server will push deleg: "
            << obj.open_none_delegation4_u.ond_server_will_push_deleg;
    case why_no_delegation4::WND4_RESOURCE:
        out << " server will signal available: "
            << obj.open_none_delegation4_u.ond_server_will_signal_avail;
    default: break;
    }
    return out;
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
    case open_delegation_type4::OPEN_DELEGATE_NONE_EXT:
        return out << ": " << obj.open_delegation4_u.od_whynone;
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

std::ostream& operator<<(std::ostream& out, const rpcsec_gss_info& obj)
{
    return out <<  "oid: "     << obj.oid
               << " qop: "     << obj.qop
               << " service: " << obj.service;
}

std::ostream& operator<<(std::ostream& out, const secinfo4& obj)
{
    out << " flavor: " << obj.flavor;
    if(obj.flavor == RPCSEC_GSS) return out << " info: "
                                            << obj.secinfo4_u.flavor_info;
    else                         return out;
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

std::ostream& operator<<(std::ostream& out, const gsshandle4_t& obj)
{
    print_hex(out,
              obj.gsshandle4_t_val,
              obj.gsshandle4_t_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const gss_cb_handles4& obj)
{
    out <<  "service: " << obj.gcbp_service
        << " server: "  << obj.gcbp_handle_from_server
        << " client: "  << obj.gcbp_handle_from_client;
    return out;
}

std::ostream& operator<<(std::ostream& out, const authunix_parms& obj)
{
    out <<  "time: "         << obj.aup_time
        << " machine name: " << obj.aup_machname
        << " uid: "          << obj.aup_uid
        << " gid: "          << obj.aup_gid;
    __gid_t *current_el = obj.aup_gids;
    for(size_t i {0}; i<obj.aup_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}
/*
std::ostream& operator<<(std::ostream& out, const authsys_parms& obj)
{
    out <<  "timestamp: "    << obj.stamp
        << " machine name: " << obj.machinename
        << " uid: "          << obj.uid
        << " gid: "          << obj.gid;
    u_int *current_el = obj.gids.gids_val;
    for(size_t i {0}; i<obj.gids.gids_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}
*/
std::ostream& operator<<(std::ostream& out, const callback_sec_parms4& obj)
{
    out << " sec flavor: " << obj.cb_secflavor;
    switch(obj.cb_secflavor)
    {
    case AUTH_NONE:
        break;
    case AUTH_SYS:
        out << obj.callback_sec_parms4_u.cbsp_sys_cred;
    case RPCSEC_GSS:
        out << obj.callback_sec_parms4_u.cbsp_gss_handles;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const channel_dir_from_client4& obj)
{
    switch(obj)
    {
    case channel_dir_from_client4::CDFC4_FORE:         return out << "FORE";
    case channel_dir_from_client4::CDFC4_BACK:         return out << "BACK";
    case channel_dir_from_client4::CDFC4_FORE_OR_BOTH: return out << "FORE_OR_BOTH";
    case channel_dir_from_client4::CDFC4_BACK_OR_BOTH: return out << "BACK_OR_BOTH";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const channel_dir_from_server4& obj)
{
    switch(obj)
    {
    case channel_dir_from_server4::CDFS4_FORE: return out << "FORE";
    case channel_dir_from_server4::CDFS4_BACK: return out << "BACK";
    case channel_dir_from_server4::CDFS4_BOTH: return out << "BOTH";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const state_protect_ops4& obj)
{
    out <<  "must enforce: " << obj.spo_must_enforce
        << " must allow: "   << obj.spo_must_allow;
    return out;
}

std::ostream& operator<<(std::ostream& out, const ssv_sp_parms4& obj)
{
    out << "ops: " << obj.ssp_ops;
    sec_oid4 *current_el = obj.ssp_hash_algs.ssp_hash_algs_val;
    for(size_t i {0}; i<obj.ssp_hash_algs.ssp_hash_algs_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    out << " encr algs: ";
    current_el = obj.ssp_encr_algs.ssp_encr_algs_val;
    for(size_t i {0}; i<obj.ssp_encr_algs.ssp_encr_algs_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    out << " window: "          << obj.ssp_window
        << " num_gss_handles: " << obj.ssp_num_gss_handles;
    return out;
}

std::ostream& operator<<(std::ostream& out, const state_protect_how4& obj)
{
    switch(obj)
    {
    case state_protect_how4::SP4_NONE:      return out << "NONE";
    case state_protect_how4::SP4_MACH_CRED: return out << "MACH_CRED";
    case state_protect_how4::SP4_SSV:       return out << "SSV";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const state_protect4_a& obj)
{
    out <<  "how: " << obj.spa_how;
    switch(obj.spa_how)
    {
    case state_protect_how4::SP4_NONE: break;
    case state_protect_how4::SP4_MACH_CRED:
        return out << " mach ops: " << obj.state_protect4_a_u.spa_mach_ops;
    case state_protect_how4::SP4_SSV:
        return out << " ssv ops: " << obj.state_protect4_a_u.spa_ssv_parms;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const ssv_prot_info4& obj)
{
    out <<  "ops: "      << obj.spi_ops
        << " hash alg: " << obj.spi_hash_alg
        << " encr alg: " << obj.spi_encr_alg
        << " ssv len: "  << obj.spi_ssv_len
        << " window: "   << obj.spi_window
        << " handles:";
    gsshandle4_t *current_el = obj.spi_handles.spi_handles_val;
    for(size_t i {0}; i<obj.spi_handles.spi_handles_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const state_protect4_r& obj)
{
    out <<  "how: " << obj.spr_how;
    switch(obj.spr_how)
    {
    case state_protect_how4::SP4_NONE: break;
    case state_protect_how4::SP4_MACH_CRED:
        return out << " mach ops: " << obj.state_protect4_r_u.spr_mach_ops;
    case state_protect_how4::SP4_SSV:
        return out << " ssv ops: " << obj.state_protect4_r_u.spr_ssv_info;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const channel_attrs4& obj)
{
    out << "header pad size: "           << obj.ca_headerpadsize
        << "; max request size: "         << obj.ca_maxrequestsize
        << "; max response size: "        << obj.ca_maxresponsesize
        << "; max response size cached: " << obj.ca_maxresponsesize_cached
        << "; max operations: "           << obj.ca_maxoperations
        << "; max requests: "             << obj.ca_maxrequests
        << "; rdma ird: ";
    print_hex(out,
              obj.ca_rdma_ird.ca_rdma_ird_val,
              obj.ca_rdma_ird.ca_rdma_ird_len);
    return out;
}

std::ostream& operator<<(std::ostream& out, const gddrnf4_status& obj)
{
    switch(obj)
    {
    case gddrnf4_status::GDD4_OK:      return out << "OK";
    case gddrnf4_status::GDD4_UNAVAIL: return out << "UNAVAIL";
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const newtime4& obj)
{
    out << "time changed: " << obj.nt_timechanged;
    switch(obj.nt_timechanged)
    {
    case TRUE: return out << " time: " << obj.newtime4_u.nt_time;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const newoffset4& obj)
{
    out << "no new offset: " << obj.no_newoffset;
    switch(obj.no_newoffset)
    {
    case TRUE: return out << " offset: " << obj.newoffset4_u.no_offset;
    default: break;
    }
    return out;
}


std::ostream& operator<<(std::ostream& out, const newsize4& obj)
{
    out << "size changed: " << obj.ns_sizechanged;
    switch(obj.ns_sizechanged)
    {
    case TRUE: return out << " size: " << obj.newsize4_u.ns_size;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const layoutreturn_stateid& obj)
{
    out << "present: " << obj.lrs_present;
    switch(obj.lrs_present)
    {
    case TRUE: return out << " stateid: " << obj.layoutreturn_stateid_u.lrs_stateid;
    default: break;
    }
    return out;
}


std::ostream& operator<<(std::ostream& out, const secinfo_style4& obj)
{
    switch(obj)
    {
    case secinfo_style4::SECINFO_STYLE4_CURRENT_FH:
        return out << "CURRENT_FH";   
    case secinfo_style4::SECINFO_STYLE4_PARENT:
        return out << "PARENT";   
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const SEQUENCE4args& obj)
{
    out <<  "sessionid: "    << obj.sa_sessionid
        << " sequenceid: 0x" << obj.sa_sequenceid
        << " slotid: "       << obj.sa_slotid
        << " cache this: "   << obj.sa_cachethis;
    return out;
}

std::ostream& operator<<(std::ostream& out, const SEQUENCE4resok& obj)
{
    out <<  "session: "               << obj.sr_sessionid
        << " sequenceid: 0x"          << obj.sr_sequenceid
        << " slotid: "                << obj.sr_slotid
        << " highest slotid: "        << obj.sr_highest_slotid
        << " target highest slotid: " << obj.sr_target_highest_slotid
        << " status flags: "          << obj.sr_status_flags;
    return out;
}

std::ostream& operator<<(std::ostream& out, const SEQUENCE4res& obj)
{
    out << "status: " << obj.sr_status;
    if(obj.sr_status == nfsstat4::NFS4_OK)
    {
        out << obj.SEQUENCE4res_u.sr_resok4;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const ssa_digest_input4& obj)
{
    return out << obj.sdi_seqargs;
}

std::ostream& operator<<(std::ostream& out, const ssr_digest_input4& obj)
{
    return out << obj.sdi_seqres;
}

std::ostream& operator<<(std::ostream& out, const deleg_claim4& obj)
{
    out << "claim: " << obj.dc_claim;
    switch(obj.dc_claim)
    {
    case open_claim_type4::CLAIM_PREVIOUS:
        return out << " delegate type: " << obj.deleg_claim4_u.dc_delegate_type;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const layoutrecall_type4& obj)
{
    switch(obj)
    {
    case layoutrecall_type4::LAYOUTRECALL4_FILE:
        return out << "FILE";
    case layoutrecall_type4::LAYOUTRECALL4_FSID:
        return out << "FSID";
    case layoutrecall_type4::LAYOUTRECALL4_ALL:
        return out << "ALL";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const layoutrecall_file4& obj)
{
    out << "fh: ";
    print_nfs_fh(out,
                 obj.lor_fh.nfs_fh4_val, 
                 obj.lor_fh.nfs_fh4_len);
    out << " offset: "  << obj.lor_offset;
    out << " length: "  << obj.lor_length;
    out << " stateid: " << obj.lor_stateid;
    return out;
}
 
std::ostream& operator<<(std::ostream& out, const layoutrecall4& obj)
{
    out << "type: ";
    switch(obj.lor_recalltype)
    {
    case layoutrecall_type4::LAYOUTRECALL4_FILE:
        return out << " layout: " << obj.layoutrecall4_u.lor_layout;
    case layoutrecall_type4::LAYOUTRECALL4_FSID:
        return out << " fsid: "   << obj.layoutrecall4_u.lor_fsid;
    default: break;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const notify_type4& obj)
{
    switch(obj)
    {
    case notify_type4::NOTIFY4_CHANGE_CHILD_ATTRS:
        return out << "CHANGE_CHILD_ATTRS";
    case notify_type4::NOTIFY4_CHANGE_DIR_ATTRS:
        return out << "CHANGE_DIR_ATTRS";
    case notify_type4::NOTIFY4_REMOVE_ENTRY:
        return out << "REMOVE_ENTRY";
    case notify_type4::NOTIFY4_ADD_ENTRY:
        return out << "ADD_ENTRY";
    case notify_type4::NOTIFY4_RENAME_ENTRY:
        return out << "RENAME_ENTRY";
    case notify_type4::NOTIFY4_CHANGE_COOKIE_VERIFIER:
        return out << "CHANGE_COOKIE_VERIFIER";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const notify_entry4& obj)
{
    out <<  "file: "  << obj.ne_file
        << " attrs: " << obj.ne_attrs;
    return out;
}

std::ostream& operator<<(std::ostream& out, const prev_entry4& obj)
{
    out <<  "prev entry: "        << obj.pe_prev_entry
        << " prev entry cookie: " << obj.pe_prev_entry_cookie;
    return out;
}

std::ostream& operator<<(std::ostream& out, const notify_remove4& obj)
{
    out <<  "old entry: "        << obj.nrm_old_entry
        << " old entry cookie: " << obj.nrm_old_entry_cookie;
    return out;
}

std::ostream& operator<<(std::ostream& out, const notify_add4& obj)
{
    out << "old entries: ";
    notify_remove4 *current_el = obj.nad_old_entry.nad_old_entry_val;
    for(size_t i {0}; i<obj.nad_old_entry.nad_old_entry_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    out << " new entry: " << obj.nad_new_entry 
        << " new entry cookie:";
    nfs_cookie4 *current_el2 = obj.nad_new_entry_cookie.nad_new_entry_cookie_val;
    for(size_t i {0}; i<obj.nad_new_entry_cookie.nad_new_entry_cookie_len; i++,current_el2++)
    {
        out << ' ' << current_el2;
    }
    out << " prev entry:";
    prev_entry4 *current_el3 = obj.nad_prev_entry.nad_prev_entry_val;
    for(size_t i {0}; i<obj.nad_prev_entry.nad_prev_entry_len; i++,current_el3++)
    {
        out << ' ' << current_el3;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const notify_attr4& obj)
{
    return out << "changed entry: " << obj.na_changed_entry;
}

std::ostream& operator<<(std::ostream& out, const notify_rename4& obj)
{
    return out <<  "old entry: " << obj.nrn_old_entry
               << " new entry: " << obj.nrn_new_entry;
}

std::ostream& operator<<(std::ostream& out, const notify_verifier4& obj)
{
    return out <<  "old cookieverf: " << obj.nv_old_cookieverf
               << " new cookieverf: " << obj.nv_new_cookieverf;
}

std::ostream& operator<<(std::ostream& out, const notifylist4& obj)
{
    return out.write(obj.notifylist4_val,
                     obj.notifylist4_len);
}

std::ostream& operator<<(std::ostream& out, const notify4& obj)
{
    return out <<  "mask: " << obj.notify_mask
               << " vals: " << obj.notify_vals;
}

std::ostream& operator<<(std::ostream& out, const referring_call4& obj)
{
    return out <<  "sequenceid: 0x" << std::hex << obj.rc_sequenceid << std::dec
               << " slotid: "       << obj.rc_slotid;
}

std::ostream& operator<<(std::ostream& out, const referring_call_list4& obj)
{
    out <<  "sessionid: ";
    print_hex(out,
              obj.rcl_sessionid,
              NFS4_SESSIONID_SIZE);
    out << " referring calls:";
    referring_call4 *current_el = obj.rcl_referring_calls.rcl_referring_calls_val;
    for(size_t i {0}; i<obj.rcl_referring_calls.rcl_referring_calls_len; i++,current_el++)
    {
        out << ' ' << current_el;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const notify_deviceid_type4& obj)
{
    switch(obj)
    {
    case notify_deviceid_type4::NOTIFY_DEVICEID4_CHANGE:
        return out << "CHANGE";
    case notify_deviceid_type4::NOTIFY_DEVICEID4_DELETE:
        return out << "DELETE";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const notify_deviceid_delete4& obj)
{
    return out <<  "layout type: " << obj.ndd_layouttype
               << " deviceid: "    << obj.ndd_deviceid;
}

std::ostream& operator<<(std::ostream& out, const notify_deviceid_change4& obj)
{
    return out <<  "layout type: " << obj.ndc_layouttype
               << " deviceid: "    << obj.ndc_deviceid
               << " immediate: "   << obj.ndc_immediate;
}

bool_t
xdr_nfs_ftype4 (XDR* xdrs, nfs_ftype4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfsstat4 (XDR* xdrs, nfsstat4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_attrlist4 (XDR* xdrs, attrlist4* objp)
{
    if (!xdr_bytes (xdrs, (char**)&objp->attrlist4_val, (u_int*) &objp->attrlist4_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_bitmap4 (XDR* xdrs, bitmap4* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->bitmap4_val, (u_int*) &objp->bitmap4_len, ~0,
                    sizeof (uint32_t), (xdrproc_t) xdr_uint32_t))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_changeid4 (XDR* xdrs, changeid4* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_clientid4 (XDR* xdrs, clientid4* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_count4 (XDR* xdrs, count4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_length4 (XDR* xdrs, length4* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_mode4 (XDR* xdrs, mode4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_cookie4 (XDR* xdrs, nfs_cookie4* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_fh4 (XDR* xdrs, nfs_fh4* objp)
{
    if (!xdr_bytes (xdrs, (char**)&objp->nfs_fh4_val, (u_int*) &objp->nfs_fh4_len, NFS4_FHSIZE))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_offset4 (XDR* xdrs, offset4* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_qop4 (XDR* xdrs, qop4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_sec_oid4 (XDR* xdrs, sec_oid4* objp)
{
    if (!xdr_bytes (xdrs, (char**)&objp->sec_oid4_val, (u_int*) &objp->sec_oid4_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_sequenceid4 (XDR* xdrs, sequenceid4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_seqid4 (XDR* xdrs, seqid4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_sessionid4 (XDR* xdrs, sessionid4 objp)
{
    if (!xdr_opaque (xdrs, objp, NFS4_SESSIONID_SIZE))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_slotid4 (XDR* xdrs, slotid4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_utf8string (XDR* xdrs, utf8string* objp)
{
    if (!xdr_bytes (xdrs, (char**)&objp->utf8string_val, (u_int*) &objp->utf8string_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_utf8str_cis (XDR* xdrs, utf8str_cis* objp)
{
    if (!xdr_utf8string (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_utf8str_cs (XDR* xdrs, utf8str_cs* objp)
{
    if (!xdr_utf8string (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_utf8str_mixed (XDR* xdrs, utf8str_mixed* objp)
{
    if (!xdr_utf8string (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_component4 (XDR* xdrs, component4* objp)
{
    if (!xdr_utf8str_cs (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_linktext4 (XDR* xdrs, linktext4* objp)
{
    if (!xdr_utf8str_cs (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_pathname4 (XDR* xdrs, pathname4* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->pathname4_val, (u_int*) &objp->pathname4_len, ~0,
                    sizeof (component4), (xdrproc_t) xdr_component4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_verifier4 (XDR* xdrs, verifier4 objp)
{
    if (!xdr_opaque (xdrs, objp, NFS4_VERIFIER_SIZE))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfstime4 (XDR* xdrs, nfstime4* objp)
{
    if (!xdr_int64_t (xdrs, &objp->seconds))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->nseconds))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_time_how4 (XDR* xdrs, time_how4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_settime4 (XDR* xdrs, settime4* objp)
{
    if (!xdr_time_how4 (xdrs, &objp->set_it))
    {
        return FALSE;
    }
    switch (objp->set_it)
    {
    case SET_TO_CLIENT_TIME4:
        if (!xdr_nfstime4 (xdrs, &objp->settime4_u.time))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_nfs_lease4 (XDR* xdrs, nfs_lease4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fsid4 (XDR* xdrs, fsid4* objp)
{
    if (!xdr_uint64_t (xdrs, &objp->major))
    {
        return FALSE;
    }
    if (!xdr_uint64_t (xdrs, &objp->minor))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_change_policy4 (XDR* xdrs, change_policy4* objp)
{
    if (!xdr_uint64_t (xdrs, &objp->cp_major))
    {
        return FALSE;
    }
    if (!xdr_uint64_t (xdrs, &objp->cp_minor))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fs_location4 (XDR* xdrs, fs_location4* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->server.server_val, (u_int*) &objp->server.server_len, ~0,
                    sizeof (utf8str_cis), (xdrproc_t) xdr_utf8str_cis))
    {
        return FALSE;
    }
    if (!xdr_pathname4 (xdrs, &objp->rootpath))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fs_locations4 (XDR* xdrs, fs_locations4* objp)
{
    if (!xdr_pathname4 (xdrs, &objp->fs_root))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->locations.locations_val, (u_int*) &objp->locations.locations_len, ~0,
                    sizeof (fs_location4), (xdrproc_t) xdr_fs_location4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_acetype4 (XDR* xdrs, acetype4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_aceflag4 (XDR* xdrs, aceflag4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_acemask4 (XDR* xdrs, acemask4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfsace4 (XDR* xdrs, nfsace4* objp)
{
    if (!xdr_acetype4 (xdrs, &objp->type))
    {
        return FALSE;
    }
    if (!xdr_aceflag4 (xdrs, &objp->flag))
    {
        return FALSE;
    }
    if (!xdr_acemask4 (xdrs, &objp->access_mask))
    {
        return FALSE;
    }
    if (!xdr_utf8str_mixed (xdrs, &objp->who))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_aclflag4 (XDR* xdrs, aclflag4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfsacl41 (XDR* xdrs, nfsacl41* objp)
{
    if (!xdr_aclflag4 (xdrs, &objp->na41_flag))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->na41_aces.na41_aces_val, (u_int*) &objp->na41_aces.na41_aces_len, ~0,
                    sizeof (nfsace4), (xdrproc_t) xdr_nfsace4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_mode_masked4 (XDR* xdrs, mode_masked4* objp)
{
    if (!xdr_mode4 (xdrs, &objp->mm_value_to_set))
    {
        return FALSE;
    }
    if (!xdr_mode4 (xdrs, &objp->mm_mask_bits))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_specdata4 (XDR* xdrs, specdata4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->specdata1))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->specdata2))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_netaddr4 (XDR* xdrs, netaddr4* objp)
{
    if (!xdr_string (xdrs, &objp->na_r_netid, ~0))
    {
        return FALSE;
    }
    if (!xdr_string (xdrs, &objp->na_r_addr, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_impl_id4 (XDR* xdrs, nfs_impl_id4* objp)
{
    if (!xdr_utf8str_cis (xdrs, &objp->nii_domain))
    {
        return FALSE;
    }
    if (!xdr_utf8str_cs (xdrs, &objp->nii_name))
    {
        return FALSE;
    }
    if (!xdr_nfstime4 (xdrs, &objp->nii_date))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_stateid4 (XDR* xdrs, stateid4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->seqid))
    {
        return FALSE;
    }
    if (!xdr_opaque (xdrs, objp->other, 12))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layouttype4 (XDR* xdrs, layouttype4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layout_content4 (XDR* xdrs, layout_content4* objp)
{
    if (!xdr_layouttype4 (xdrs, &objp->loc_type))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->loc_body.loc_body_val, (u_int*) &objp->loc_body.loc_body_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}
/*
 * LAYOUT4_OSD2_OBJECTS loc_body description
 * is in a separate .x file
 */

/*
 * LAYOUT4_BLOCK_VOLUME loc_body description
 * is in a separate .x file
 */

bool_t
xdr_layouthint4 (XDR* xdrs, layouthint4* objp)
{
    if (!xdr_layouttype4 (xdrs, &objp->loh_type))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->loh_body.loh_body_val, (u_int*) &objp->loh_body.loh_body_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layoutiomode4 (XDR* xdrs, layoutiomode4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layout4 (XDR* xdrs, layout4* objp)
{
    if (!xdr_offset4 (xdrs, &objp->lo_offset))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->lo_length))
    {
        return FALSE;
    }
    if (!xdr_layoutiomode4 (xdrs, &objp->lo_iomode))
    {
        return FALSE;
    }
    if (!xdr_layout_content4 (xdrs, &objp->lo_content))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_deviceid4 (XDR* xdrs, deviceid4 objp)
{
    if (!xdr_opaque (xdrs, objp, NFS4_DEVICEID4_SIZE))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_device_addr4 (XDR* xdrs, device_addr4* objp)
{
    if (!xdr_layouttype4 (xdrs, &objp->da_layout_type))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->da_addr_body.da_addr_body_val, (u_int*) &objp->da_addr_body.da_addr_body_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layoutupdate4 (XDR* xdrs, layoutupdate4* objp)
{
    if (!xdr_layouttype4 (xdrs, &objp->lou_type))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->lou_body.lou_body_val, (u_int*) &objp->lou_body.lou_body_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}



bool_t
xdr_layoutreturn_type4 (XDR* xdrs, layoutreturn_type4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}
/* layouttype4 specific data */

bool_t
xdr_layoutreturn_file4 (XDR* xdrs, layoutreturn_file4* objp)
{
    if (!xdr_offset4 (xdrs, &objp->lrf_offset))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->lrf_length))
    {
        return FALSE;
    }
    if (!xdr_stateid4 (xdrs, &objp->lrf_stateid))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->lrf_body.lrf_body_val, (u_int*) &objp->lrf_body.lrf_body_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layoutreturn4 (XDR* xdrs, layoutreturn4* objp)
{
    if (!xdr_layoutreturn_type4 (xdrs, &objp->lr_returntype))
    {
        return FALSE;
    }
    switch (objp->lr_returntype)
    {
    case LAYOUTRETURN4_FILE:
        if (!xdr_layoutreturn_file4 (xdrs, &objp->layoutreturn4_u.lr_layout))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}


bool_t
xdr_fs4_status_type (XDR* xdrs, fs4_status_type* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fs4_status (XDR* xdrs, fs4_status* objp)
{
    if (!xdr_bool (xdrs, &objp->fss_absent))
    {
        return FALSE;
    }
    if (!xdr_fs4_status_type (xdrs, &objp->fss_type))
    {
        return FALSE;
    }
    if (!xdr_utf8str_cs (xdrs, &objp->fss_source))
    {
        return FALSE;
    }
    if (!xdr_utf8str_cs (xdrs, &objp->fss_current))
    {
        return FALSE;
    }
    if (!xdr_int32_t (xdrs, &objp->fss_age))
    {
        return FALSE;
    }
    if (!xdr_nfstime4 (xdrs, &objp->fss_version))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_threshold4_read_size (XDR* xdrs, threshold4_read_size* objp)
{
    if (!xdr_length4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_threshold4_write_size (XDR* xdrs, threshold4_write_size* objp)
{
    if (!xdr_length4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_threshold4_read_iosize (XDR* xdrs, threshold4_read_iosize* objp)
{
    if (!xdr_length4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_threshold4_write_iosize (XDR* xdrs, threshold4_write_iosize* objp)
{
    if (!xdr_length4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_threshold_item4 (XDR* xdrs, threshold_item4* objp)
{
    if (!xdr_layouttype4 (xdrs, &objp->thi_layout_type))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->thi_hintset))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->thi_hintlist.thi_hintlist_val, (u_int*) &objp->thi_hintlist.thi_hintlist_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_mdsthreshold4 (XDR* xdrs, mdsthreshold4* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->mth_hints.mth_hints_val, (u_int*) &objp->mth_hints.mth_hints_len, ~0,
                    sizeof (threshold_item4), (xdrproc_t) xdr_threshold_item4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_retention_get4 (XDR* xdrs, retention_get4* objp)
{
    if (!xdr_uint64_t (xdrs, &objp->rg_duration))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->rg_begin_time.rg_begin_time_val, (u_int*) &objp->rg_begin_time.rg_begin_time_len, 1,
                    sizeof (nfstime4), (xdrproc_t) xdr_nfstime4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_retention_set4 (XDR* xdrs, retention_set4* objp)
{
    if (!xdr_bool (xdrs, &objp->rs_enable))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->rs_duration.rs_duration_val, (u_int*) &objp->rs_duration.rs_duration_len, 1,
                    sizeof (uint64_t), (xdrproc_t) xdr_uint64_t))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fs_charset_cap4 (XDR* xdrs, fs_charset_cap4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_supported_attrs (XDR* xdrs, fattr4_supported_attrs* objp)
{
    if (!xdr_bitmap4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_type (XDR* xdrs, fattr4_type* objp)
{
    if (!xdr_nfs_ftype4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_fh_expire_type (XDR* xdrs, fattr4_fh_expire_type* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_change (XDR* xdrs, fattr4_change* objp)
{
    if (!xdr_changeid4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_size (XDR* xdrs, fattr4_size* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_link_support (XDR* xdrs, fattr4_link_support* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_symlink_support (XDR* xdrs, fattr4_symlink_support* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_named_attr (XDR* xdrs, fattr4_named_attr* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_fsid (XDR* xdrs, fattr4_fsid* objp)
{
    if (!xdr_fsid4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_unique_handles (XDR* xdrs, fattr4_unique_handles* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_lease_time (XDR* xdrs, fattr4_lease_time* objp)
{
    if (!xdr_nfs_lease4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_rdattr_error (XDR* xdrs, fattr4_rdattr_error* objp)
{
    if (!xdr_nfsstat4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_acl (XDR* xdrs, fattr4_acl* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->fattr4_acl_val, (u_int*) &objp->fattr4_acl_len, ~0,
                    sizeof (nfsace4), (xdrproc_t) xdr_nfsace4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_aclsupport (XDR* xdrs, fattr4_aclsupport* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_archive (XDR* xdrs, fattr4_archive* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_cansettime (XDR* xdrs, fattr4_cansettime* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_case_insensitive (XDR* xdrs, fattr4_case_insensitive* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_case_preserving (XDR* xdrs, fattr4_case_preserving* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_chown_restricted (XDR* xdrs, fattr4_chown_restricted* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_fileid (XDR* xdrs, fattr4_fileid* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_files_avail (XDR* xdrs, fattr4_files_avail* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_filehandle (XDR* xdrs, fattr4_filehandle* objp)
{
    if (!xdr_nfs_fh4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_files_free (XDR* xdrs, fattr4_files_free* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_files_total (XDR* xdrs, fattr4_files_total* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_fs_locations (XDR* xdrs, fattr4_fs_locations* objp)
{
    if (!xdr_fs_locations4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_hidden (XDR* xdrs, fattr4_hidden* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_homogeneous (XDR* xdrs, fattr4_homogeneous* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_maxfilesize (XDR* xdrs, fattr4_maxfilesize* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_maxlink (XDR* xdrs, fattr4_maxlink* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_maxname (XDR* xdrs, fattr4_maxname* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_maxread (XDR* xdrs, fattr4_maxread* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_maxwrite (XDR* xdrs, fattr4_maxwrite* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_mimetype (XDR* xdrs, fattr4_mimetype* objp)
{
    if (!xdr_utf8str_cs (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_mode (XDR* xdrs, fattr4_mode* objp)
{
    if (!xdr_mode4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_mode_set_masked (XDR* xdrs, fattr4_mode_set_masked* objp)
{
    if (!xdr_mode_masked4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_mounted_on_fileid (XDR* xdrs, fattr4_mounted_on_fileid* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_no_trunc (XDR* xdrs, fattr4_no_trunc* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_numlinks (XDR* xdrs, fattr4_numlinks* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_owner (XDR* xdrs, fattr4_owner* objp)
{
    if (!xdr_utf8str_mixed (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_owner_group (XDR* xdrs, fattr4_owner_group* objp)
{
    if (!xdr_utf8str_mixed (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_quota_avail_hard (XDR* xdrs, fattr4_quota_avail_hard* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_quota_avail_soft (XDR* xdrs, fattr4_quota_avail_soft* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_quota_used (XDR* xdrs, fattr4_quota_used* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_rawdev (XDR* xdrs, fattr4_rawdev* objp)
{
    if (!xdr_specdata4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_space_avail (XDR* xdrs, fattr4_space_avail* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_space_free (XDR* xdrs, fattr4_space_free* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_space_total (XDR* xdrs, fattr4_space_total* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_space_used (XDR* xdrs, fattr4_space_used* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_system (XDR* xdrs, fattr4_system* objp)
{
    if (!xdr_bool (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_time_access (XDR* xdrs, fattr4_time_access* objp)
{
    if (!xdr_nfstime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_time_access_set (XDR* xdrs, fattr4_time_access_set* objp)
{
    if (!xdr_settime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_time_backup (XDR* xdrs, fattr4_time_backup* objp)
{
    if (!xdr_nfstime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_time_create (XDR* xdrs, fattr4_time_create* objp)
{
    if (!xdr_nfstime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_time_delta (XDR* xdrs, fattr4_time_delta* objp)
{
    if (!xdr_nfstime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_time_metadata (XDR* xdrs, fattr4_time_metadata* objp)
{
    if (!xdr_nfstime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_time_modify (XDR* xdrs, fattr4_time_modify* objp)
{
    if (!xdr_nfstime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_time_modify_set (XDR* xdrs, fattr4_time_modify_set* objp)
{
    if (!xdr_settime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_suppattr_exclcreat (XDR* xdrs, fattr4_suppattr_exclcreat* objp)
{
    if (!xdr_bitmap4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_dir_notif_delay (XDR* xdrs, fattr4_dir_notif_delay* objp)
{
    if (!xdr_nfstime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_dirent_notif_delay (XDR* xdrs, fattr4_dirent_notif_delay* objp)
{
    if (!xdr_nfstime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_fs_layout_types (XDR* xdrs, fattr4_fs_layout_types* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->fattr4_fs_layout_types_val, (u_int*) &objp->fattr4_fs_layout_types_len, ~0,
                    sizeof (layouttype4), (xdrproc_t) xdr_layouttype4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_fs_status (XDR* xdrs, fattr4_fs_status* objp)
{
    if (!xdr_fs4_status (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_fs_charset_cap (XDR* xdrs, fattr4_fs_charset_cap* objp)
{
    if (!xdr_fs_charset_cap4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_layout_alignment (XDR* xdrs, fattr4_layout_alignment* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_layout_blksize (XDR* xdrs, fattr4_layout_blksize* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_layout_hint (XDR* xdrs, fattr4_layout_hint* objp)
{
    if (!xdr_layouthint4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_layout_types (XDR* xdrs, fattr4_layout_types* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->fattr4_layout_types_val, (u_int*) &objp->fattr4_layout_types_len, ~0,
                    sizeof (layouttype4), (xdrproc_t) xdr_layouttype4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_mdsthreshold (XDR* xdrs, fattr4_mdsthreshold* objp)
{
    if (!xdr_mdsthreshold4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_retention_get (XDR* xdrs, fattr4_retention_get* objp)
{
    if (!xdr_retention_get4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_retention_set (XDR* xdrs, fattr4_retention_set* objp)
{
    if (!xdr_retention_set4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_retentevt_get (XDR* xdrs, fattr4_retentevt_get* objp)
{
    if (!xdr_retention_get4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_retentevt_set (XDR* xdrs, fattr4_retentevt_set* objp)
{
    if (!xdr_retention_set4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_retention_hold (XDR* xdrs, fattr4_retention_hold* objp)
{
    if (!xdr_uint64_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_dacl (XDR* xdrs, fattr4_dacl* objp)
{
    if (!xdr_nfsacl41 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_sacl (XDR* xdrs, fattr4_sacl* objp)
{
    if (!xdr_nfsacl41 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_change_policy (XDR* xdrs, fattr4_change_policy* objp)
{
    if (!xdr_change_policy4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}
/*
 * REQUIRED Attributes
 */
/* new to NFSV4.1 */
/*
 * RECOMMENDED Attributes
 */

/* new to NFSV4.1 */


bool_t
xdr_fattr4 (XDR* xdrs, fattr4* objp)
{
    if (!xdr_bitmap4 (xdrs, &objp->attrmask))
    {
        return FALSE;
    }
    if (!xdr_attrlist4 (xdrs, &objp->attr_vals))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_change_info4 (XDR* xdrs, change_info4* objp)
{
    if (!xdr_bool (xdrs, &objp->atomic))
    {
        return FALSE;
    }
    if (!xdr_changeid4 (xdrs, &objp->before))
    {
        return FALSE;
    }
    if (!xdr_changeid4 (xdrs, &objp->after))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_clientaddr4 (XDR* xdrs, clientaddr4* objp)
{
    if (!xdr_netaddr4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_cb_client4 (XDR* xdrs, cb_client4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->cb_program))
    {
        return FALSE;
    }
    if (!xdr_netaddr4 (xdrs, &objp->cb_location))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_client_id4 (XDR* xdrs, nfs_client_id4* objp)
{
    if (!xdr_verifier4 (xdrs, objp->verifier))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->id.id_val, (u_int*) &objp->id.id_len, NFS4_OPAQUE_LIMIT))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_client_owner4 (XDR* xdrs, client_owner4* objp)
{
    if (!xdr_verifier4 (xdrs, objp->co_verifier))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->co_ownerid.co_ownerid_val, (u_int*) &objp->co_ownerid.co_ownerid_len, NFS4_OPAQUE_LIMIT))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_server_owner4 (XDR* xdrs, server_owner4* objp)
{
    if (!xdr_uint64_t (xdrs, &objp->so_minor_id))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->so_major_id.so_major_id_val, (u_int*) &objp->so_major_id.so_major_id_len, NFS4_OPAQUE_LIMIT))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_state_owner4 (XDR* xdrs, state_owner4* objp)
{
    if (!xdr_clientid4 (xdrs, &objp->clientid))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->owner.owner_val, (u_int*) &objp->owner.owner_len, NFS4_OPAQUE_LIMIT))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_open_owner4 (XDR* xdrs, open_owner4* objp)
{
    if (!xdr_state_owner4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_lock_owner4 (XDR* xdrs, lock_owner4* objp)
{
    if (!xdr_state_owner4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_lock_type4 (XDR* xdrs, nfs_lock_type4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

/* Input for computing subkeys */

bool_t
xdr_ssv_subkey4 (XDR* xdrs, ssv_subkey4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}


/* Input for computing smt_hmac */

bool_t
xdr_ssv_mic_plain_tkn4 (XDR* xdrs, ssv_mic_plain_tkn4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->smpt_ssv_seq))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->smpt_orig_plain.smpt_orig_plain_val, (u_int*) &objp->smpt_orig_plain.smpt_orig_plain_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}


/* SSV GSS PerMsgToken token */

bool_t
xdr_ssv_mic_tkn4 (XDR* xdrs, ssv_mic_tkn4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->smt_ssv_seq))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->smt_hmac.smt_hmac_val, (u_int*) &objp->smt_hmac.smt_hmac_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}


/* Input for computing ssct_encr_data and ssct_hmac */

bool_t
xdr_ssv_seal_plain_tkn4 (XDR* xdrs, ssv_seal_plain_tkn4* objp)
{
    if (!xdr_bytes (xdrs, (char**)&objp->sspt_confounder.sspt_confounder_val, (u_int*) &objp->sspt_confounder.sspt_confounder_len, ~0))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->sspt_ssv_seq))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->sspt_orig_plain.sspt_orig_plain_val, (u_int*) &objp->sspt_orig_plain.sspt_orig_plain_len, ~0))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->sspt_pad.sspt_pad_val, (u_int*) &objp->sspt_pad.sspt_pad_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}


/* SSV GSS SealedMessage token */

bool_t
xdr_ssv_seal_cipher_tkn4 (XDR* xdrs, ssv_seal_cipher_tkn4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->ssct_ssv_seq))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->ssct_iv.ssct_iv_val, (u_int*) &objp->ssct_iv.ssct_iv_len, ~0))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->ssct_encr_data.ssct_encr_data_val, (u_int*) &objp->ssct_encr_data.ssct_encr_data_len, ~0))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->ssct_hmac.ssct_hmac_val, (u_int*) &objp->ssct_hmac.ssct_hmac_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}


bool_t
xdr_fs_locations_server4 (XDR* xdrs, fs_locations_server4* objp)
{
    if (!xdr_int32_t (xdrs, &objp->fls_currency))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->fls_info.fls_info_val, (u_int*) &objp->fls_info.fls_info_len, ~0))
    {
        return FALSE;
    }
    if (!xdr_utf8str_cis (xdrs, &objp->fls_server))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fs_locations_item4 (XDR* xdrs, fs_locations_item4* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->fli_entries.fli_entries_val, (u_int*) &objp->fli_entries.fli_entries_len, ~0,
                    sizeof (fs_locations_server4), (xdrproc_t) xdr_fs_locations_server4))
    {
        return FALSE;
    }
    if (!xdr_pathname4 (xdrs, &objp->fli_rootpath))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fs_locations_info4 (XDR* xdrs, fs_locations_info4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->fli_flags))
    {
        return FALSE;
    }
    if (!xdr_int32_t (xdrs, &objp->fli_valid_for))
    {
        return FALSE;
    }
    if (!xdr_pathname4 (xdrs, &objp->fli_fs_root))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->fli_items.fli_items_val, (u_int*) &objp->fli_items.fli_items_len, ~0,
                    sizeof (fs_locations_item4), (xdrproc_t) xdr_fs_locations_item4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_fattr4_fs_locations_info (XDR* xdrs, fattr4_fs_locations_info* objp)
{
    if (!xdr_fs_locations_info4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfl_util4 (XDR* xdrs, nfl_util4* objp)
{
    if (!xdr_uint32_t (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}


bool_t
xdr_filelayout_hint_care4 (XDR* xdrs, filelayout_hint_care4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

/* Encoded in the loh_body field of data type layouthint4: */


bool_t
xdr_nfsv4_1_file_layouthint4 (XDR* xdrs, nfsv4_1_file_layouthint4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->nflh_care))
    {
        return FALSE;
    }
    if (!xdr_nfl_util4 (xdrs, &objp->nflh_util))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->nflh_stripe_count))
    {
        return FALSE;
    }
    return TRUE;
}



bool_t
xdr_multipath_list4 (XDR* xdrs, multipath_list4* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->multipath_list4_val, (u_int*) &objp->multipath_list4_len, ~0,
                    sizeof (netaddr4), (xdrproc_t) xdr_netaddr4))
    {
        return FALSE;
    }
    return TRUE;
}

/*
 * Encoded in the da_addr_body field of
 * data type device_addr4:
 */

bool_t
xdr_nfsv4_1_file_layout_ds_addr4 (XDR* xdrs, nfsv4_1_file_layout_ds_addr4* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->nflda_stripe_indices.nflda_stripe_indices_val, (u_int*) &objp->nflda_stripe_indices.nflda_stripe_indices_len, ~0,
                    sizeof (uint32_t), (xdrproc_t) xdr_uint32_t))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->nflda_multipath_ds_list.nflda_multipath_ds_list_val, (u_int*) &objp->nflda_multipath_ds_list.nflda_multipath_ds_list_len, ~0,
                    sizeof (multipath_list4), (xdrproc_t) xdr_multipath_list4))
    {
        return FALSE;
    }
    return TRUE;
}


/*
 * Encoded in the loc_body field of
 * data type layout_content4:
 */

bool_t
xdr_nfsv4_1_file_layout4 (XDR* xdrs, nfsv4_1_file_layout4* objp)
{
    if (!xdr_deviceid4 (xdrs, objp->nfl_deviceid))
    {
        return FALSE;
    }
    if (!xdr_nfl_util4 (xdrs, &objp->nfl_util))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->nfl_first_stripe_index))
    {
        return FALSE;
    }
    if (!xdr_offset4 (xdrs, &objp->nfl_pattern_offset))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->nfl_fh_list.nfl_fh_list_val, (u_int*) &objp->nfl_fh_list.nfl_fh_list_len, ~0,
                    sizeof (nfs_fh4), (xdrproc_t) xdr_nfs_fh4))
    {
        return FALSE;
    }
    return TRUE;
}

/*
 * Encoded in the lou_body field of data type layoutupdate4:
 *      Nothing. lou_body is a zero length array of bytes.
 */

/*
 * Encoded in the lrf_body field of
 * data type layoutreturn_file4:
 *      Nothing. lrf_body is a zero length array of bytes.
 */

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
xdr_ACCESS4args (XDR* xdrs, ACCESS4args* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->access))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ACCESS4resok (XDR* xdrs, ACCESS4resok* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->supported))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->access))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ACCESS4res (XDR* xdrs, ACCESS4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_ACCESS4resok (xdrs, &objp->ACCESS4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_CLOSE4args (XDR* xdrs, CLOSE4args* objp)
{
    if (!xdr_seqid4 (xdrs, &objp->seqid))
    {
        return FALSE;
    }
    if (!xdr_stateid4 (xdrs, &objp->open_stateid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CLOSE4res (XDR* xdrs, CLOSE4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_stateid4 (xdrs, &objp->CLOSE4res_u.open_stateid))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_COMMIT4args (XDR* xdrs, COMMIT4args* objp)
{
    if (!xdr_offset4 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->count))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_COMMIT4resok (XDR* xdrs, COMMIT4resok* objp)
{
    if (!xdr_verifier4 (xdrs, objp->writeverf))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_COMMIT4res (XDR* xdrs, COMMIT4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_COMMIT4resok (xdrs, &objp->COMMIT4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_createtype4 (XDR* xdrs, createtype4* objp)
{
    if (!xdr_nfs_ftype4 (xdrs, &objp->type))
    {
        return FALSE;
    }
    switch (objp->type)
    {
    case NF4LNK:
        if (!xdr_linktext4 (xdrs, &objp->createtype4_u.linkdata))
        {
            return FALSE;
        }
        break;
    case NF4BLK:
    case NF4CHR:
        if (!xdr_specdata4 (xdrs, &objp->createtype4_u.devdata))
        {
            return FALSE;
        }
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
xdr_CREATE4args (XDR* xdrs, CREATE4args* objp)
{
    if (!xdr_createtype4 (xdrs, &objp->objtype))
    {
        return FALSE;
    }
    if (!xdr_component4 (xdrs, &objp->objname))
    {
        return FALSE;
    }
    if (!xdr_fattr4 (xdrs, &objp->createattrs))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CREATE4resok (XDR* xdrs, CREATE4resok* objp)
{
    if (!xdr_change_info4 (xdrs, &objp->cinfo))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->attrset))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CREATE4res (XDR* xdrs, CREATE4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_CREATE4resok (xdrs, &objp->CREATE4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_DELEGPURGE4args (XDR* xdrs, DELEGPURGE4args* objp)
{
    if (!xdr_clientid4 (xdrs, &objp->clientid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_DELEGPURGE4res (XDR* xdrs, DELEGPURGE4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_DELEGRETURN4args (XDR* xdrs, DELEGRETURN4args* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->deleg_stateid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_DELEGRETURN4res (XDR* xdrs, DELEGRETURN4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETATTR4args (XDR* xdrs, GETATTR4args* objp)
{
    if (!xdr_bitmap4 (xdrs, &objp->attr_request))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETATTR4resok (XDR* xdrs, GETATTR4resok* objp)
{
    if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETATTR4res (XDR* xdrs, GETATTR4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_GETATTR4resok (xdrs, &objp->GETATTR4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_GETFH4resok (XDR* xdrs, GETFH4resok* objp)
{
    if (!xdr_nfs_fh4 (xdrs, &objp->object))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETFH4res (XDR* xdrs, GETFH4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_GETFH4resok (xdrs, &objp->GETFH4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LINK4args (XDR* xdrs, LINK4args* objp)
{
    if (!xdr_component4 (xdrs, &objp->newname))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LINK4resok (XDR* xdrs, LINK4resok* objp)
{
    if (!xdr_change_info4 (xdrs, &objp->cinfo))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LINK4res (XDR* xdrs, LINK4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_LINK4resok (xdrs, &objp->LINK4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_open_to_lock_owner4 (XDR* xdrs, open_to_lock_owner4* objp)
{
    if (!xdr_seqid4 (xdrs, &objp->open_seqid))
    {
        return FALSE;
    }
    if (!xdr_stateid4 (xdrs, &objp->open_stateid))
    {
        return FALSE;
    }
    if (!xdr_seqid4 (xdrs, &objp->lock_seqid))
    {
        return FALSE;
    }
    if (!xdr_lock_owner4 (xdrs, &objp->lock_owner))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_exist_lock_owner4 (XDR* xdrs, exist_lock_owner4* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->lock_stateid))
    {
        return FALSE;
    }
    if (!xdr_seqid4 (xdrs, &objp->lock_seqid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_locker4 (XDR* xdrs, locker4* objp)
{
    if (!xdr_bool (xdrs, &objp->new_lock_owner))
    {
        return FALSE;
    }
    switch (objp->new_lock_owner)
    {
    case TRUE:
        if (!xdr_open_to_lock_owner4 (xdrs, &objp->locker4_u.open_owner))
        {
            return FALSE;
        }
        break;
    case FALSE:
        if (!xdr_exist_lock_owner4 (xdrs, &objp->locker4_u.lock_owner))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOCK4args (XDR* xdrs, LOCK4args* objp)
{
    if (!xdr_nfs_lock_type4 (xdrs, &objp->locktype))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->reclaim))
    {
        return FALSE;
    }
    if (!xdr_offset4 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->length))
    {
        return FALSE;
    }
    if (!xdr_locker4 (xdrs, &objp->locker))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOCK4denied (XDR* xdrs, LOCK4denied* objp)
{
    if (!xdr_offset4 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->length))
    {
        return FALSE;
    }
    if (!xdr_nfs_lock_type4 (xdrs, &objp->locktype))
    {
        return FALSE;
    }
    if (!xdr_lock_owner4 (xdrs, &objp->owner))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOCK4resok (XDR* xdrs, LOCK4resok* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->lock_stateid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOCK4res (XDR* xdrs, LOCK4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_LOCK4resok (xdrs, &objp->LOCK4res_u.resok4))
        {
            return FALSE;
        }
        break;
    case NFS4ERR_DENIED:
        if (!xdr_LOCK4denied (xdrs, &objp->LOCK4res_u.denied))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LOCKT4args (XDR* xdrs, LOCKT4args* objp)
{
    if (!xdr_nfs_lock_type4 (xdrs, &objp->locktype))
    {
        return FALSE;
    }
    if (!xdr_offset4 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->length))
    {
        return FALSE;
    }
    if (!xdr_lock_owner4 (xdrs, &objp->owner))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOCKT4res (XDR* xdrs, LOCKT4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4ERR_DENIED:
        if (!xdr_LOCK4denied (xdrs, &objp->LOCKT4res_u.denied))
        {
            return FALSE;
        }
        break;
    case NFS4_OK:
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LOCKU4args (XDR* xdrs, LOCKU4args* objp)
{
    if (!xdr_nfs_lock_type4 (xdrs, &objp->locktype))
    {
        return FALSE;
    }
    if (!xdr_seqid4 (xdrs, &objp->seqid))
    {
        return FALSE;
    }
    if (!xdr_stateid4 (xdrs, &objp->lock_stateid))
    {
        return FALSE;
    }
    if (!xdr_offset4 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->length))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOCKU4res (XDR* xdrs, LOCKU4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_stateid4 (xdrs, &objp->LOCKU4res_u.lock_stateid))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LOOKUP4args (XDR* xdrs, LOOKUP4args* objp)
{
    if (!xdr_component4 (xdrs, &objp->objname))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOOKUP4res (XDR* xdrs, LOOKUP4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LOOKUPP4res (XDR* xdrs, LOOKUPP4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_NVERIFY4args (XDR* xdrs, NVERIFY4args* objp)
{
    if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_NVERIFY4res (XDR* xdrs, NVERIFY4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_createmode4 (XDR* xdrs, createmode4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_creatverfattr (XDR* xdrs, creatverfattr* objp)
{
    if (!xdr_verifier4 (xdrs, objp->cva_verf))
    {
        return FALSE;
    }
    if (!xdr_fattr4 (xdrs, &objp->cva_attrs))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_createhow4 (XDR* xdrs, createhow4* objp)
{
    if (!xdr_createmode4 (xdrs, &objp->mode))
    {
        return FALSE;
    }
    switch (objp->mode)
    {
    case UNCHECKED4:
    case GUARDED4:
        if (!xdr_fattr4 (xdrs, &objp->createhow4_u.createattrs))
        {
            return FALSE;
        }
        break;
    case EXCLUSIVE4:
        if (!xdr_verifier4 (xdrs, objp->createhow4_u.createverf))
        {
            return FALSE;
        }
        break;
    case EXCLUSIVE4_1:
        if (!xdr_creatverfattr (xdrs, &objp->createhow4_u.ch_createboth))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_opentype4 (XDR* xdrs, opentype4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_openflag4 (XDR* xdrs, openflag4* objp)
{
    if (!xdr_opentype4 (xdrs, &objp->opentype))
    {
        return FALSE;
    }
    switch (objp->opentype)
    {
    case OPEN4_CREATE:
        if (!xdr_createhow4 (xdrs, &objp->openflag4_u.how))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_limit_by4 (XDR* xdrs, limit_by4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_modified_limit4 (XDR* xdrs, nfs_modified_limit4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->num_blocks))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->bytes_per_block))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_space_limit4 (XDR* xdrs, nfs_space_limit4* objp)
{
    if (!xdr_limit_by4 (xdrs, &objp->limitby))
    {
        return FALSE;
    }
    switch (objp->limitby)
    {
    case NFS_LIMIT_SIZE:
        if (!xdr_uint64_t (xdrs, &objp->nfs_space_limit4_u.filesize))
        {
            return FALSE;
        }
        break;
    case NFS_LIMIT_BLOCKS:
        if (!xdr_nfs_modified_limit4 (xdrs, &objp->nfs_space_limit4_u.mod_blocks))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_open_delegation_type4 (XDR* xdrs, open_delegation_type4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_open_claim_type4 (XDR* xdrs, open_claim_type4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_open_claim_delegate_cur4 (XDR* xdrs, open_claim_delegate_cur4* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->delegate_stateid))
    {
        return FALSE;
    }
    if (!xdr_component4 (xdrs, &objp->file))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_open_claim4 (XDR* xdrs, open_claim4* objp)
{
    if (!xdr_open_claim_type4 (xdrs, &objp->claim))
    {
        return FALSE;
    }
    switch (objp->claim)
    {
    case CLAIM_NULL:
        if (!xdr_component4 (xdrs, &objp->open_claim4_u.file))
        {
            return FALSE;
        }
        break;
    case CLAIM_PREVIOUS:
        if (!xdr_open_delegation_type4 (xdrs, &objp->open_claim4_u.delegate_type))
        {
            return FALSE;
        }
        break;
    case CLAIM_DELEGATE_CUR:
        if (!xdr_open_claim_delegate_cur4 (xdrs, &objp->open_claim4_u.delegate_cur_info))
        {
            return FALSE;
        }
        break;
    case CLAIM_DELEGATE_PREV:
        if (!xdr_component4 (xdrs, &objp->open_claim4_u.file_delegate_prev))
        {
            return FALSE;
        }
        break;
    case CLAIM_FH:
        break;
    case CLAIM_DELEG_PREV_FH:
        break;
    case CLAIM_DELEG_CUR_FH:
        if (!xdr_stateid4 (xdrs, &objp->open_claim4_u.oc_delegate_stateid))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN4args (XDR* xdrs, OPEN4args* objp)
{
    if (!xdr_seqid4 (xdrs, &objp->seqid))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->share_access))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->share_deny))
    {
        return FALSE;
    }
    if (!xdr_open_owner4 (xdrs, &objp->owner))
    {
        return FALSE;
    }
    if (!xdr_openflag4 (xdrs, &objp->openhow))
    {
        return FALSE;
    }
    if (!xdr_open_claim4 (xdrs, &objp->claim))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_open_read_delegation4 (XDR* xdrs, open_read_delegation4* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->stateid))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->recall))
    {
        return FALSE;
    }
    if (!xdr_nfsace4 (xdrs, &objp->permissions))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_open_write_delegation4 (XDR* xdrs, open_write_delegation4* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->stateid))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->recall))
    {
        return FALSE;
    }
    if (!xdr_nfs_space_limit4 (xdrs, &objp->space_limit))
    {
        return FALSE;
    }
    if (!xdr_nfsace4 (xdrs, &objp->permissions))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_why_no_delegation4 (XDR* xdrs, why_no_delegation4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_open_none_delegation4 (XDR* xdrs, open_none_delegation4* objp)
{
    if (!xdr_why_no_delegation4 (xdrs, &objp->ond_why))
    {
        return FALSE;
    }
    switch (objp->ond_why)
    {
    case WND4_CONTENTION:
        if (!xdr_bool (xdrs, &objp->open_none_delegation4_u.ond_server_will_push_deleg))
        {
            return FALSE;
        }
        break;
    case WND4_RESOURCE:
        if (!xdr_bool (xdrs, &objp->open_none_delegation4_u.ond_server_will_signal_avail))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_open_delegation4 (XDR* xdrs, open_delegation4* objp)
{
    if (!xdr_open_delegation_type4 (xdrs, &objp->delegation_type))
    {
        return FALSE;
    }
    switch (objp->delegation_type)
    {
    case OPEN_DELEGATE_NONE:
        break;
    case OPEN_DELEGATE_READ:
        if (!xdr_open_read_delegation4 (xdrs, &objp->open_delegation4_u.read))
        {
            return FALSE;
        }
        break;
    case OPEN_DELEGATE_WRITE:
        if (!xdr_open_write_delegation4 (xdrs, &objp->open_delegation4_u.write))
        {
            return FALSE;
        }
        break;
    case OPEN_DELEGATE_NONE_EXT:
        if (!xdr_open_none_delegation4 (xdrs, &objp->open_delegation4_u.od_whynone))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN4resok (XDR* xdrs, OPEN4resok* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->stateid))
    {
        return FALSE;
    }
    if (!xdr_change_info4 (xdrs, &objp->cinfo))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->rflags))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->attrset))
    {
        return FALSE;
    }
    if (!xdr_open_delegation4 (xdrs, &objp->delegation))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN4res (XDR* xdrs, OPEN4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_OPEN4resok (xdrs, &objp->OPEN4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_OPENATTR4args (XDR* xdrs, OPENATTR4args* objp)
{
    if (!xdr_bool (xdrs, &objp->createdir))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPENATTR4res (XDR* xdrs, OPENATTR4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN_CONFIRM4args (XDR* xdrs, OPEN_CONFIRM4args* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->open_stateid))
    {
        return FALSE;
    }
    if (!xdr_seqid4 (xdrs, &objp->seqid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN_CONFIRM4resok (XDR* xdrs, OPEN_CONFIRM4resok* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->open_stateid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN_CONFIRM4res (XDR* xdrs, OPEN_CONFIRM4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_OPEN_CONFIRM4resok (xdrs, &objp->OPEN_CONFIRM4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_OPEN_DOWNGRADE4args (XDR* xdrs, OPEN_DOWNGRADE4args* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->open_stateid))
    {
        return FALSE;
    }
    if (!xdr_seqid4 (xdrs, &objp->seqid))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->share_access))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->share_deny))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN_DOWNGRADE4resok (XDR* xdrs, OPEN_DOWNGRADE4resok* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->open_stateid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_OPEN_DOWNGRADE4res (XDR* xdrs, OPEN_DOWNGRADE4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_OPEN_DOWNGRADE4resok (xdrs, &objp->OPEN_DOWNGRADE4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_PUTFH4args (XDR* xdrs, PUTFH4args* objp)
{
    if (!xdr_nfs_fh4 (xdrs, &objp->object))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_PUTFH4res (XDR* xdrs, PUTFH4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_PUTPUBFH4res (XDR* xdrs, PUTPUBFH4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_PUTROOTFH4res (XDR* xdrs, PUTROOTFH4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READ4args (XDR* xdrs, READ4args* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->stateid))
    {
        return FALSE;
    }
    if (!xdr_offset4 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->count))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READ4resok (XDR* xdrs, READ4resok* objp)
{
    if (!xdr_bool (xdrs, &objp->eof))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->data.data_val, (u_int*) &objp->data.data_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READ4res (XDR* xdrs, READ4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_READ4resok (xdrs, &objp->READ4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_READDIR4args (XDR* xdrs, READDIR4args* objp)
{
    if (!xdr_nfs_cookie4 (xdrs, &objp->cookie))
    {
        return FALSE;
    }
    if (!xdr_verifier4 (xdrs, objp->cookieverf))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->dircount))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->maxcount))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->attr_request))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_entry4 (XDR* xdrs, entry4* objp)
{
    if (!xdr_nfs_cookie4 (xdrs, &objp->cookie))
    {
        return FALSE;
    }
    if (!xdr_component4 (xdrs, &objp->name))
    {
        return FALSE;
    }
    if (!xdr_fattr4 (xdrs, &objp->attrs))
    {
        return FALSE;
    }
    if (!xdr_pointer (xdrs, (char**)&objp->nextentry, sizeof (entry4), (xdrproc_t) xdr_entry4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_dirlist4 (XDR* xdrs, dirlist4* objp)
{
    if (!xdr_pointer (xdrs, (char**)&objp->entries, sizeof (entry4), (xdrproc_t) xdr_entry4))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->eof))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READDIR4resok (XDR* xdrs, READDIR4resok* objp)
{
    if (!xdr_verifier4 (xdrs, objp->cookieverf))
    {
        return FALSE;
    }
    if (!xdr_dirlist4 (xdrs, &objp->reply))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READDIR4res (XDR* xdrs, READDIR4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_READDIR4resok (xdrs, &objp->READDIR4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_READLINK4resok (XDR* xdrs, READLINK4resok* objp)
{
    if (!xdr_linktext4 (xdrs, &objp->link))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_READLINK4res (XDR* xdrs, READLINK4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_READLINK4resok (xdrs, &objp->READLINK4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_REMOVE4args (XDR* xdrs, REMOVE4args* objp)
{
    if (!xdr_component4 (xdrs, &objp->target))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_REMOVE4resok (XDR* xdrs, REMOVE4resok* objp)
{
    if (!xdr_change_info4 (xdrs, &objp->cinfo))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_REMOVE4res (XDR* xdrs, REMOVE4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_REMOVE4resok (xdrs, &objp->REMOVE4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_RENAME4args (XDR* xdrs, RENAME4args* objp)
{
    if (!xdr_component4 (xdrs, &objp->oldname))
    {
        return FALSE;
    }
    if (!xdr_component4 (xdrs, &objp->newname))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RENAME4resok (XDR* xdrs, RENAME4resok* objp)
{
    if (!xdr_change_info4 (xdrs, &objp->source_cinfo))
    {
        return FALSE;
    }
    if (!xdr_change_info4 (xdrs, &objp->target_cinfo))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RENAME4res (XDR* xdrs, RENAME4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_RENAME4resok (xdrs, &objp->RENAME4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_RENEW4args (XDR* xdrs, RENEW4args* objp)
{
    if (!xdr_clientid4 (xdrs, &objp->clientid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RENEW4res (XDR* xdrs, RENEW4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RESTOREFH4res (XDR* xdrs, RESTOREFH4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SAVEFH4res (XDR* xdrs, SAVEFH4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SECINFO4args (XDR* xdrs, SECINFO4args* objp)
{
    if (!xdr_component4 (xdrs, &objp->name))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_rpc_gss_svc_t (XDR* xdrs, rpc_gss_svc_t* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_rpcsec_gss_info (XDR* xdrs, rpcsec_gss_info* objp)
{
    if (!xdr_sec_oid4 (xdrs, &objp->oid))
    {
        return FALSE;
    }
    if (!xdr_qop4 (xdrs, &objp->qop))
    {
        return FALSE;
    }
    if (!xdr_rpc_gss_svc_t (xdrs, &objp->service))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_secinfo4 (XDR* xdrs, secinfo4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->flavor))
    {
        return FALSE;
    }
    switch (objp->flavor)
    {
    case RPCSEC_GSS:
        if (!xdr_rpcsec_gss_info (xdrs, &objp->secinfo4_u.flavor_info))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_SECINFO4resok (XDR* xdrs, SECINFO4resok* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->SECINFO4resok_val, (u_int*) &objp->SECINFO4resok_len, ~0,
                    sizeof (secinfo4), (xdrproc_t) xdr_secinfo4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SECINFO4res (XDR* xdrs, SECINFO4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_SECINFO4resok (xdrs, &objp->SECINFO4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_SETATTR4args (XDR* xdrs, SETATTR4args* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->stateid))
    {
        return FALSE;
    }
    if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SETATTR4res (XDR* xdrs, SETATTR4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->attrsset))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SETCLIENTID4args (XDR* xdrs, SETCLIENTID4args* objp)
{
    if (!xdr_nfs_client_id4 (xdrs, &objp->client))
    {
        return FALSE;
    }
    if (!xdr_cb_client4 (xdrs, &objp->callback))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->callback_ident))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SETCLIENTID4resok (XDR* xdrs, SETCLIENTID4resok* objp)
{
    if (!xdr_clientid4 (xdrs, &objp->clientid))
    {
        return FALSE;
    }
    if (!xdr_verifier4 (xdrs, objp->setclientid_confirm))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SETCLIENTID4res (XDR* xdrs, SETCLIENTID4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_SETCLIENTID4resok (xdrs, &objp->SETCLIENTID4res_u.resok4))
        {
            return FALSE;
        }
        break;
    case NFS4ERR_CLID_INUSE:
        if (!xdr_clientaddr4 (xdrs, &objp->SETCLIENTID4res_u.client_using))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_SETCLIENTID_CONFIRM4args (XDR* xdrs, SETCLIENTID_CONFIRM4args* objp)
{
    if (!xdr_clientid4 (xdrs, &objp->clientid))
    {
        return FALSE;
    }
    if (!xdr_verifier4 (xdrs, objp->setclientid_confirm))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SETCLIENTID_CONFIRM4res (XDR* xdrs, SETCLIENTID_CONFIRM4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_VERIFY4args (XDR* xdrs, VERIFY4args* objp)
{
    if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_VERIFY4res (XDR* xdrs, VERIFY4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_stable_how4 (XDR* xdrs, stable_how4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_WRITE4args (XDR* xdrs, WRITE4args* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->stateid))
    {
        return FALSE;
    }
    if (!xdr_offset4 (xdrs, &objp->offset))
    {
        return FALSE;
    }
    if (!xdr_stable_how4 (xdrs, &objp->stable))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->data.data_val, (u_int*) &objp->data.data_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_WRITE4resok (XDR* xdrs, WRITE4resok* objp)
{
    if (!xdr_count4 (xdrs, &objp->count))
    {
        return FALSE;
    }
    if (!xdr_stable_how4 (xdrs, &objp->committed))
    {
        return FALSE;
    }
    if (!xdr_verifier4 (xdrs, objp->writeverf))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_WRITE4res (XDR* xdrs, WRITE4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_WRITE4resok (xdrs, &objp->WRITE4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_RELEASE_LOCKOWNER4args (XDR* xdrs, RELEASE_LOCKOWNER4args* objp)
{
    if (!xdr_lock_owner4 (xdrs, &objp->lock_owner))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RELEASE_LOCKOWNER4res (XDR* xdrs, RELEASE_LOCKOWNER4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ILLEGAL4res (XDR* xdrs, ILLEGAL4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_gsshandle4_t (XDR* xdrs, gsshandle4_t* objp)
{
    if (!xdr_bytes (xdrs, (char**)&objp->gsshandle4_t_val, (u_int*) &objp->gsshandle4_t_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_gss_cb_handles4 (XDR* xdrs, gss_cb_handles4* objp)
{
    if (!xdr_rpc_gss_svc_t (xdrs, &objp->gcbp_service))
    {
        return FALSE;
    }
    if (!xdr_gsshandle4_t (xdrs, &objp->gcbp_handle_from_server))
    {
        return FALSE;
    }
    if (!xdr_gsshandle4_t (xdrs, &objp->gcbp_handle_from_client))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_callback_sec_parms4 (XDR* xdrs, callback_sec_parms4* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->cb_secflavor))
    {
        return FALSE;
    }
    switch (objp->cb_secflavor)
    {
    case AUTH_NONE:
        break;
    case AUTH_SYS:
        if (!xdr_authunix_parms (xdrs, &objp->callback_sec_parms4_u.cbsp_sys_cred))
        {
            return FALSE;
        }
        break;
    case RPCSEC_GSS:
        if (!xdr_gss_cb_handles4 (xdrs, &objp->callback_sec_parms4_u.cbsp_gss_handles))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_BACKCHANNEL_CTL4args (XDR* xdrs, BACKCHANNEL_CTL4args* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->bca_cb_program))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->bca_sec_parms.bca_sec_parms_val, (u_int*) &objp->bca_sec_parms.bca_sec_parms_len, ~0,
                    sizeof (callback_sec_parms4), (xdrproc_t) xdr_callback_sec_parms4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_BACKCHANNEL_CTL4res (XDR* xdrs, BACKCHANNEL_CTL4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->bcr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_channel_dir_from_client4 (XDR* xdrs, channel_dir_from_client4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_BIND_CONN_TO_SESSION4args (XDR* xdrs, BIND_CONN_TO_SESSION4args* objp)
{
    if (!xdr_sessionid4 (xdrs, objp->bctsa_sessid))
    {
        return FALSE;
    }
    if (!xdr_channel_dir_from_client4 (xdrs, &objp->bctsa_dir))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->bctsa_use_conn_in_rdma_mode))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_channel_dir_from_server4 (XDR* xdrs, channel_dir_from_server4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_BIND_CONN_TO_SESSION4resok (XDR* xdrs, BIND_CONN_TO_SESSION4resok* objp)
{
    if (!xdr_sessionid4 (xdrs, objp->bctsr_sessid))
    {
        return FALSE;
    }
    if (!xdr_channel_dir_from_server4 (xdrs, &objp->bctsr_dir))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->bctsr_use_conn_in_rdma_mode))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_BIND_CONN_TO_SESSION4res (XDR* xdrs, BIND_CONN_TO_SESSION4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->bctsr_status))
    {
        return FALSE;
    }
    switch (objp->bctsr_status)
    {
    case NFS4_OK:
        if (!xdr_BIND_CONN_TO_SESSION4resok (xdrs, &objp->BIND_CONN_TO_SESSION4res_u.bctsr_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_state_protect_ops4 (XDR* xdrs, state_protect_ops4* objp)
{
    if (!xdr_bitmap4 (xdrs, &objp->spo_must_enforce))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->spo_must_allow))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ssv_sp_parms4 (XDR* xdrs, ssv_sp_parms4* objp)
{
    if (!xdr_state_protect_ops4 (xdrs, &objp->ssp_ops))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->ssp_hash_algs.ssp_hash_algs_val, (u_int*) &objp->ssp_hash_algs.ssp_hash_algs_len, ~0,
                    sizeof (sec_oid4), (xdrproc_t) xdr_sec_oid4))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->ssp_encr_algs.ssp_encr_algs_val, (u_int*) &objp->ssp_encr_algs.ssp_encr_algs_len, ~0,
                    sizeof (sec_oid4), (xdrproc_t) xdr_sec_oid4))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->ssp_window))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->ssp_num_gss_handles))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_state_protect_how4 (XDR* xdrs, state_protect_how4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_state_protect4_a (XDR* xdrs, state_protect4_a* objp)
{
    if (!xdr_state_protect_how4 (xdrs, &objp->spa_how))
    {
        return FALSE;
    }
    switch (objp->spa_how)
    {
    case SP4_NONE:
        break;
    case SP4_MACH_CRED:
        if (!xdr_state_protect_ops4 (xdrs, &objp->state_protect4_a_u.spa_mach_ops))
        {
            return FALSE;
        }
        break;
    case SP4_SSV:
        if (!xdr_ssv_sp_parms4 (xdrs, &objp->state_protect4_a_u.spa_ssv_parms))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_EXCHANGE_ID4args (XDR* xdrs, EXCHANGE_ID4args* objp)
{
    if (!xdr_client_owner4 (xdrs, &objp->eia_clientowner))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->eia_flags))
    {
        return FALSE;
    }
    if (!xdr_state_protect4_a (xdrs, &objp->eia_state_protect))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->eia_client_impl_id.eia_client_impl_id_val, (u_int*) &objp->eia_client_impl_id.eia_client_impl_id_len, 1,
                    sizeof (nfs_impl_id4), (xdrproc_t) xdr_nfs_impl_id4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ssv_prot_info4 (XDR* xdrs, ssv_prot_info4* objp)
{
    if (!xdr_state_protect_ops4 (xdrs, &objp->spi_ops))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->spi_hash_alg))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->spi_encr_alg))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->spi_ssv_len))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->spi_window))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->spi_handles.spi_handles_val, (u_int*) &objp->spi_handles.spi_handles_len, ~0,
                    sizeof (gsshandle4_t), (xdrproc_t) xdr_gsshandle4_t))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_state_protect4_r (XDR* xdrs, state_protect4_r* objp)
{
    if (!xdr_state_protect_how4 (xdrs, &objp->spr_how))
    {
        return FALSE;
    }
    switch (objp->spr_how)
    {
    case SP4_NONE:
        break;
    case SP4_MACH_CRED:
        if (!xdr_state_protect_ops4 (xdrs, &objp->state_protect4_r_u.spr_mach_ops))
        {
            return FALSE;
        }
        break;
    case SP4_SSV:
        if (!xdr_ssv_prot_info4 (xdrs, &objp->state_protect4_r_u.spr_ssv_info))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_EXCHANGE_ID4resok (XDR* xdrs, EXCHANGE_ID4resok* objp)
{
    if (!xdr_clientid4 (xdrs, &objp->eir_clientid))
    {
        return FALSE;
    }
    if (!xdr_sequenceid4 (xdrs, &objp->eir_sequenceid))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->eir_flags))
    {
        return FALSE;
    }
    if (!xdr_state_protect4_r (xdrs, &objp->eir_state_protect))
    {
        return FALSE;
    }
    if (!xdr_server_owner4 (xdrs, &objp->eir_server_owner))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->eir_server_scope.eir_server_scope_val, (u_int*) &objp->eir_server_scope.eir_server_scope_len, NFS4_OPAQUE_LIMIT))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->eir_server_impl_id.eir_server_impl_id_val, (u_int*) &objp->eir_server_impl_id.eir_server_impl_id_len, 1,
                    sizeof (nfs_impl_id4), (xdrproc_t) xdr_nfs_impl_id4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_EXCHANGE_ID4res (XDR* xdrs, EXCHANGE_ID4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->eir_status))
    {
        return FALSE;
    }
    switch (objp->eir_status)
    {
    case NFS4_OK:
        if (!xdr_EXCHANGE_ID4resok (xdrs, &objp->EXCHANGE_ID4res_u.eir_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_channel_attrs4 (XDR* xdrs, channel_attrs4* objp)
{
    if (!xdr_count4 (xdrs, &objp->ca_headerpadsize))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->ca_maxrequestsize))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->ca_maxresponsesize))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->ca_maxresponsesize_cached))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->ca_maxoperations))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->ca_maxrequests))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->ca_rdma_ird.ca_rdma_ird_val, (u_int*) &objp->ca_rdma_ird.ca_rdma_ird_len, 1,
                    sizeof (uint32_t), (xdrproc_t) xdr_uint32_t))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CREATE_SESSION4args (XDR* xdrs, CREATE_SESSION4args* objp)
{
    if (!xdr_clientid4 (xdrs, &objp->csa_clientid))
    {
        return FALSE;
    }
    if (!xdr_sequenceid4 (xdrs, &objp->csa_sequence))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->csa_flags))
    {
        return FALSE;
    }
    if (!xdr_channel_attrs4 (xdrs, &objp->csa_fore_chan_attrs))
    {
        return FALSE;
    }
    if (!xdr_channel_attrs4 (xdrs, &objp->csa_back_chan_attrs))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->csa_cb_program))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->csa_sec_parms.csa_sec_parms_val, (u_int*) &objp->csa_sec_parms.csa_sec_parms_len, ~0,
                    sizeof (callback_sec_parms4), (xdrproc_t) xdr_callback_sec_parms4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CREATE_SESSION4resok (XDR* xdrs, CREATE_SESSION4resok* objp)
{
    if (!xdr_sessionid4 (xdrs, objp->csr_sessionid))
    {
        return FALSE;
    }
    if (!xdr_sequenceid4 (xdrs, &objp->csr_sequence))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->csr_flags))
    {
        return FALSE;
    }
    if (!xdr_channel_attrs4 (xdrs, &objp->csr_fore_chan_attrs))
    {
        return FALSE;
    }
    if (!xdr_channel_attrs4 (xdrs, &objp->csr_back_chan_attrs))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CREATE_SESSION4res (XDR* xdrs, CREATE_SESSION4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->csr_status))
    {
        return FALSE;
    }
    switch (objp->csr_status)
    {
    case NFS4_OK:
        if (!xdr_CREATE_SESSION4resok (xdrs, &objp->CREATE_SESSION4res_u.csr_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_DESTROY_SESSION4args (XDR* xdrs, DESTROY_SESSION4args* objp)
{
    if (!xdr_sessionid4 (xdrs, objp->dsa_sessionid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_DESTROY_SESSION4res (XDR* xdrs, DESTROY_SESSION4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->dsr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_FREE_STATEID4args (XDR* xdrs, FREE_STATEID4args* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->fsa_stateid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_FREE_STATEID4res (XDR* xdrs, FREE_STATEID4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->fsr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_attr_notice4 (XDR* xdrs, attr_notice4* objp)
{
    if (!xdr_nfstime4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GET_DIR_DELEGATION4args (XDR* xdrs, GET_DIR_DELEGATION4args* objp)
{
    if (!xdr_bool (xdrs, &objp->gdda_signal_deleg_avail))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->gdda_notification_types))
    {
        return FALSE;
    }
    if (!xdr_attr_notice4 (xdrs, &objp->gdda_child_attr_delay))
    {
        return FALSE;
    }
    if (!xdr_attr_notice4 (xdrs, &objp->gdda_dir_attr_delay))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->gdda_child_attributes))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->gdda_dir_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GET_DIR_DELEGATION4resok (XDR* xdrs, GET_DIR_DELEGATION4resok* objp)
{
    if (!xdr_verifier4 (xdrs, objp->gddr_cookieverf))
    {
        return FALSE;
    }
    if (!xdr_stateid4 (xdrs, &objp->gddr_stateid))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->gddr_notification))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->gddr_child_attributes))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->gddr_dir_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_gddrnf4_status (XDR* xdrs, gddrnf4_status* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GET_DIR_DELEGATION4res_non_fatal (XDR* xdrs, GET_DIR_DELEGATION4res_non_fatal* objp)
{
    if (!xdr_gddrnf4_status (xdrs, &objp->gddrnf_status))
    {
        return FALSE;
    }
    switch (objp->gddrnf_status)
    {
    case GDD4_OK:
        if (!xdr_GET_DIR_DELEGATION4resok (xdrs, &objp->GET_DIR_DELEGATION4res_non_fatal_u.gddrnf_resok4))
        {
            return FALSE;
        }
        break;
    case GDD4_UNAVAIL:
        if (!xdr_bool (xdrs, &objp->GET_DIR_DELEGATION4res_non_fatal_u.gddrnf_will_signal_deleg_avail))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GET_DIR_DELEGATION4res (XDR* xdrs, GET_DIR_DELEGATION4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->gddr_status))
    {
        return FALSE;
    }
    switch (objp->gddr_status)
    {
    case NFS4_OK:
        if (!xdr_GET_DIR_DELEGATION4res_non_fatal (xdrs, &objp->GET_DIR_DELEGATION4res_u.gddr_res_non_fatal4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_GETDEVICEINFO4args (XDR* xdrs, GETDEVICEINFO4args* objp)
{
    if (!xdr_deviceid4 (xdrs, objp->gdia_device_id))
    {
        return FALSE;
    }
    if (!xdr_layouttype4 (xdrs, &objp->gdia_layout_type))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->gdia_maxcount))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->gdia_notify_types))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETDEVICEINFO4resok (XDR* xdrs, GETDEVICEINFO4resok* objp)
{
    if (!xdr_device_addr4 (xdrs, &objp->gdir_device_addr))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->gdir_notification))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETDEVICEINFO4res (XDR* xdrs, GETDEVICEINFO4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->gdir_status))
    {
        return FALSE;
    }
    switch (objp->gdir_status)
    {
    case NFS4_OK:
        if (!xdr_GETDEVICEINFO4resok (xdrs, &objp->GETDEVICEINFO4res_u.gdir_resok4))
        {
            return FALSE;
        }
        break;
    case NFS4ERR_TOOSMALL:
        if (!xdr_count4 (xdrs, &objp->GETDEVICEINFO4res_u.gdir_mincount))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_GETDEVICELIST4args (XDR* xdrs, GETDEVICELIST4args* objp)
{
    if (!xdr_layouttype4 (xdrs, &objp->gdla_layout_type))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->gdla_maxdevices))
    {
        return FALSE;
    }
    if (!xdr_nfs_cookie4 (xdrs, &objp->gdla_cookie))
    {
        return FALSE;
    }
    if (!xdr_verifier4 (xdrs, objp->gdla_cookieverf))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETDEVICELIST4resok (XDR* xdrs, GETDEVICELIST4resok* objp)
{
    if (!xdr_nfs_cookie4 (xdrs, &objp->gdlr_cookie))
    {
        return FALSE;
    }
    if (!xdr_verifier4 (xdrs, objp->gdlr_cookieverf))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->gdlr_deviceid_list.gdlr_deviceid_list_val, (u_int*) &objp->gdlr_deviceid_list.gdlr_deviceid_list_len, ~0,
                    sizeof (deviceid4), (xdrproc_t) xdr_deviceid4))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->gdlr_eof))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_GETDEVICELIST4res (XDR* xdrs, GETDEVICELIST4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->gdlr_status))
    {
        return FALSE;
    }
    switch (objp->gdlr_status)
    {
    case NFS4_OK:
        if (!xdr_GETDEVICELIST4resok (xdrs, &objp->GETDEVICELIST4res_u.gdlr_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_newtime4 (XDR* xdrs, newtime4* objp)
{
    if (!xdr_bool (xdrs, &objp->nt_timechanged))
    {
        return FALSE;
    }
    switch (objp->nt_timechanged)
    {
    case TRUE:
        if (!xdr_nfstime4 (xdrs, &objp->newtime4_u.nt_time))
        {
            return FALSE;
        }
        break;
    case FALSE:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_newoffset4 (XDR* xdrs, newoffset4* objp)
{
    if (!xdr_bool (xdrs, &objp->no_newoffset))
    {
        return FALSE;
    }
    switch (objp->no_newoffset)
    {
    case TRUE:
        if (!xdr_offset4 (xdrs, &objp->newoffset4_u.no_offset))
        {
            return FALSE;
        }
        break;
    case FALSE:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LAYOUTCOMMIT4args (XDR* xdrs, LAYOUTCOMMIT4args* objp)
{
    if (!xdr_offset4 (xdrs, &objp->loca_offset))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->loca_length))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->loca_reclaim))
    {
        return FALSE;
    }
    if (!xdr_stateid4 (xdrs, &objp->loca_stateid))
    {
        return FALSE;
    }
    if (!xdr_newoffset4 (xdrs, &objp->loca_last_write_offset))
    {
        return FALSE;
    }
    if (!xdr_newtime4 (xdrs, &objp->loca_time_modify))
    {
        return FALSE;
    }
    if (!xdr_layoutupdate4 (xdrs, &objp->loca_layoutupdate))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_newsize4 (XDR* xdrs, newsize4* objp)
{
    if (!xdr_bool (xdrs, &objp->ns_sizechanged))
    {
        return FALSE;
    }
    switch (objp->ns_sizechanged)
    {
    case TRUE:
        if (!xdr_length4 (xdrs, &objp->newsize4_u.ns_size))
        {
            return FALSE;
        }
        break;
    case FALSE:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LAYOUTCOMMIT4resok (XDR* xdrs, LAYOUTCOMMIT4resok* objp)
{
    if (!xdr_newsize4 (xdrs, &objp->locr_newsize))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LAYOUTCOMMIT4res (XDR* xdrs, LAYOUTCOMMIT4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->locr_status))
    {
        return FALSE;
    }
    switch (objp->locr_status)
    {
    case NFS4_OK:
        if (!xdr_LAYOUTCOMMIT4resok (xdrs, &objp->LAYOUTCOMMIT4res_u.locr_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LAYOUTGET4args (XDR* xdrs, LAYOUTGET4args* objp)
{
    if (!xdr_bool (xdrs, &objp->loga_signal_layout_avail))
    {
        return FALSE;
    }
    if (!xdr_layouttype4 (xdrs, &objp->loga_layout_type))
    {
        return FALSE;
    }
    if (!xdr_layoutiomode4 (xdrs, &objp->loga_iomode))
    {
        return FALSE;
    }
    if (!xdr_offset4 (xdrs, &objp->loga_offset))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->loga_length))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->loga_minlength))
    {
        return FALSE;
    }
    if (!xdr_stateid4 (xdrs, &objp->loga_stateid))
    {
        return FALSE;
    }
    if (!xdr_count4 (xdrs, &objp->loga_maxcount))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LAYOUTGET4resok (XDR* xdrs, LAYOUTGET4resok* objp)
{
    if (!xdr_bool (xdrs, &objp->logr_return_on_close))
    {
        return FALSE;
    }
    if (!xdr_stateid4 (xdrs, &objp->logr_stateid))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->logr_layout.logr_layout_val, (u_int*) &objp->logr_layout.logr_layout_len, ~0,
                    sizeof (layout4), (xdrproc_t) xdr_layout4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LAYOUTGET4res (XDR* xdrs, LAYOUTGET4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->logr_status))
    {
        return FALSE;
    }
    switch (objp->logr_status)
    {
    case NFS4_OK:
        if (!xdr_LAYOUTGET4resok (xdrs, &objp->LAYOUTGET4res_u.logr_resok4))
        {
            return FALSE;
        }
        break;
    case NFS4ERR_LAYOUTTRYLATER:
        if (!xdr_bool (xdrs, &objp->LAYOUTGET4res_u.logr_will_signal_layout_avail))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_LAYOUTRETURN4args (XDR* xdrs, LAYOUTRETURN4args* objp)
{
    if (!xdr_bool (xdrs, &objp->lora_reclaim))
    {
        return FALSE;
    }
    if (!xdr_layouttype4 (xdrs, &objp->lora_layout_type))
    {
        return FALSE;
    }
    if (!xdr_layoutiomode4 (xdrs, &objp->lora_iomode))
    {
        return FALSE;
    }
    if (!xdr_layoutreturn4 (xdrs, &objp->lora_layoutreturn))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layoutreturn_stateid (XDR* xdrs, layoutreturn_stateid* objp)
{
    if (!xdr_bool (xdrs, &objp->lrs_present))
    {
        return FALSE;
    }
    switch (objp->lrs_present)
    {
    case TRUE:
        if (!xdr_stateid4 (xdrs, &objp->layoutreturn_stateid_u.lrs_stateid))
        {
            return FALSE;
        }
        break;
    case FALSE:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_LAYOUTRETURN4res (XDR* xdrs, LAYOUTRETURN4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->lorr_status))
    {
        return FALSE;
    }
    switch (objp->lorr_status)
    {
    case NFS4_OK:
        if (!xdr_layoutreturn_stateid (xdrs, &objp->LAYOUTRETURN4res_u.lorr_stateid))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_secinfo_style4 (XDR* xdrs, secinfo_style4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SECINFO_NO_NAME4args (XDR* xdrs, SECINFO_NO_NAME4args* objp)
{
    if (!xdr_secinfo_style4 (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SECINFO_NO_NAME4res (XDR* xdrs, SECINFO_NO_NAME4res* objp)
{
    if (!xdr_SECINFO4res (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SEQUENCE4args (XDR* xdrs, SEQUENCE4args* objp)
{
    if (!xdr_sessionid4 (xdrs, objp->sa_sessionid))
    {
        return FALSE;
    }
    if (!xdr_sequenceid4 (xdrs, &objp->sa_sequenceid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->sa_slotid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->sa_highest_slotid))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->sa_cachethis))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SEQUENCE4resok (XDR* xdrs, SEQUENCE4resok* objp)
{
    if (!xdr_sessionid4 (xdrs, objp->sr_sessionid))
    {
        return FALSE;
    }
    if (!xdr_sequenceid4 (xdrs, &objp->sr_sequenceid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->sr_slotid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->sr_highest_slotid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->sr_target_highest_slotid))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->sr_status_flags))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SEQUENCE4res (XDR* xdrs, SEQUENCE4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->sr_status))
    {
        return FALSE;
    }
    switch (objp->sr_status)
    {
    case NFS4_OK:
        if (!xdr_SEQUENCE4resok (xdrs, &objp->SEQUENCE4res_u.sr_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_ssa_digest_input4 (XDR* xdrs, ssa_digest_input4* objp)
{
    if (!xdr_SEQUENCE4args (xdrs, &objp->sdi_seqargs))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SET_SSV4args (XDR* xdrs, SET_SSV4args* objp)
{
    if (!xdr_bytes (xdrs, (char**)&objp->ssa_ssv.ssa_ssv_val, (u_int*) &objp->ssa_ssv.ssa_ssv_len, ~0))
    {
        return FALSE;
    }
    if (!xdr_bytes (xdrs, (char**)&objp->ssa_digest.ssa_digest_val, (u_int*) &objp->ssa_digest.ssa_digest_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_ssr_digest_input4 (XDR* xdrs, ssr_digest_input4* objp)
{
    if (!xdr_SEQUENCE4res (xdrs, &objp->sdi_seqres))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SET_SSV4resok (XDR* xdrs, SET_SSV4resok* objp)
{
    if (!xdr_bytes (xdrs, (char**)&objp->ssr_digest.ssr_digest_val, (u_int*) &objp->ssr_digest.ssr_digest_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_SET_SSV4res (XDR* xdrs, SET_SSV4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->ssr_status))
    {
        return FALSE;
    }
    switch (objp->ssr_status)
    {
    case NFS4_OK:
        if (!xdr_SET_SSV4resok (xdrs, &objp->SET_SSV4res_u.ssr_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_TEST_STATEID4args (XDR* xdrs, TEST_STATEID4args* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->ts_stateids.ts_stateids_val, (u_int*) &objp->ts_stateids.ts_stateids_len, ~0,
                    sizeof (stateid4), (xdrproc_t) xdr_stateid4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_TEST_STATEID4resok (XDR* xdrs, TEST_STATEID4resok* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->tsr_status_codes.tsr_status_codes_val, (u_int*) &objp->tsr_status_codes.tsr_status_codes_len, ~0,
                    sizeof (nfsstat4), (xdrproc_t) xdr_nfsstat4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_TEST_STATEID4res (XDR* xdrs, TEST_STATEID4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->tsr_status))
    {
        return FALSE;
    }
    switch (objp->tsr_status)
    {
    case NFS4_OK:
        if (!xdr_TEST_STATEID4resok (xdrs, &objp->TEST_STATEID4res_u.tsr_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_deleg_claim4 (XDR* xdrs, deleg_claim4* objp)
{
    if (!xdr_open_claim_type4 (xdrs, &objp->dc_claim))
    {
        return FALSE;
    }
    switch (objp->dc_claim)
    {
    case CLAIM_FH:
        break;
    case CLAIM_DELEG_PREV_FH:
        break;
    case CLAIM_PREVIOUS:
        if (!xdr_open_delegation_type4 (xdrs, &objp->deleg_claim4_u.dc_delegate_type))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_WANT_DELEGATION4args (XDR* xdrs, WANT_DELEGATION4args* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->wda_want))
    {
        return FALSE;
    }
    if (!xdr_deleg_claim4 (xdrs, &objp->wda_claim))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_WANT_DELEGATION4res (XDR* xdrs, WANT_DELEGATION4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->wdr_status))
    {
        return FALSE;
    }
    switch (objp->wdr_status)
    {
    case NFS4_OK:
        if (!xdr_open_delegation4 (xdrs, &objp->WANT_DELEGATION4res_u.wdr_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_DESTROY_CLIENTID4args (XDR* xdrs, DESTROY_CLIENTID4args* objp)
{
    if (!xdr_clientid4 (xdrs, &objp->dca_clientid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_DESTROY_CLIENTID4res (XDR* xdrs, DESTROY_CLIENTID4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->dcr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RECLAIM_COMPLETE4args (XDR* xdrs, RECLAIM_COMPLETE4args* objp)
{
    if (!xdr_bool (xdrs, &objp->rca_one_fs))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_RECLAIM_COMPLETE4res (XDR* xdrs, RECLAIM_COMPLETE4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->rcr_status))
    {
        return FALSE;
    }
    return TRUE;
}

/* new operations for NFSv4.1 */


bool_t
xdr_nfs_opnum4 (XDR* xdrs, nfs_opnum4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_argop4 (XDR* xdrs, nfs_argop4* objp)
{
    if (!xdr_nfs_opnum4 (xdrs, &objp->argop))
    {
        return FALSE;
    }
    switch (objp->argop)
    {
    case OP_ACCESS:
        if (!xdr_ACCESS4args (xdrs, &objp->nfs_argop4_u.opaccess))
        {
            return FALSE;
        }
        break;
    case OP_CLOSE:
        if (!xdr_CLOSE4args (xdrs, &objp->nfs_argop4_u.opclose))
        {
            return FALSE;
        }
        break;
    case OP_COMMIT:
        if (!xdr_COMMIT4args (xdrs, &objp->nfs_argop4_u.opcommit))
        {
            return FALSE;
        }
        break;
    case OP_CREATE:
        if (!xdr_CREATE4args (xdrs, &objp->nfs_argop4_u.opcreate))
        {
            return FALSE;
        }
        break;
    case OP_DELEGPURGE:
        if (!xdr_DELEGPURGE4args (xdrs, &objp->nfs_argop4_u.opdelegpurge))
        {
            return FALSE;
        }
        break;
    case OP_DELEGRETURN:
        if (!xdr_DELEGRETURN4args (xdrs, &objp->nfs_argop4_u.opdelegreturn))
        {
            return FALSE;
        }
        break;
    case OP_GETATTR:
        if (!xdr_GETATTR4args (xdrs, &objp->nfs_argop4_u.opgetattr))
        {
            return FALSE;
        }
        break;
    case OP_GETFH:
        break;
    case OP_LINK:
        if (!xdr_LINK4args (xdrs, &objp->nfs_argop4_u.oplink))
        {
            return FALSE;
        }
        break;
    case OP_LOCK:
        if (!xdr_LOCK4args (xdrs, &objp->nfs_argop4_u.oplock))
        {
            return FALSE;
        }
        break;
    case OP_LOCKT:
        if (!xdr_LOCKT4args (xdrs, &objp->nfs_argop4_u.oplockt))
        {
            return FALSE;
        }
        break;
    case OP_LOCKU:
        if (!xdr_LOCKU4args (xdrs, &objp->nfs_argop4_u.oplocku))
        {
            return FALSE;
        }
        break;
    case OP_LOOKUP:
        if (!xdr_LOOKUP4args (xdrs, &objp->nfs_argop4_u.oplookup))
        {
            return FALSE;
        }
        break;
    case OP_LOOKUPP:
        break;
    case OP_NVERIFY:
        if (!xdr_NVERIFY4args (xdrs, &objp->nfs_argop4_u.opnverify))
        {
            return FALSE;
        }
        break;
    case OP_OPEN:
        if (!xdr_OPEN4args (xdrs, &objp->nfs_argop4_u.opopen))
        {
            return FALSE;
        }
        break;
    case OP_OPENATTR:
        if (!xdr_OPENATTR4args (xdrs, &objp->nfs_argop4_u.opopenattr))
        {
            return FALSE;
        }
        break;
    case OP_OPEN_CONFIRM:
        if (!xdr_OPEN_CONFIRM4args (xdrs, &objp->nfs_argop4_u.opopen_confirm))
        {
            return FALSE;
        }
        break;
    case OP_OPEN_DOWNGRADE:
        if (!xdr_OPEN_DOWNGRADE4args (xdrs, &objp->nfs_argop4_u.opopen_downgrade))
        {
            return FALSE;
        }
        break;
    case OP_PUTFH:
        if (!xdr_PUTFH4args (xdrs, &objp->nfs_argop4_u.opputfh))
        {
            return FALSE;
        }
        break;
    case OP_PUTPUBFH:
        break;
    case OP_PUTROOTFH:
        break;
    case OP_READ:
        if (!xdr_READ4args (xdrs, &objp->nfs_argop4_u.opread))
        {
            return FALSE;
        }
        break;
    case OP_READDIR:
        if (!xdr_READDIR4args (xdrs, &objp->nfs_argop4_u.opreaddir))
        {
            return FALSE;
        }
        break;
    case OP_READLINK:
        break;
    case OP_REMOVE:
        if (!xdr_REMOVE4args (xdrs, &objp->nfs_argop4_u.opremove))
        {
            return FALSE;
        }
        break;
    case OP_RENAME:
        if (!xdr_RENAME4args (xdrs, &objp->nfs_argop4_u.oprename))
        {
            return FALSE;
        }
        break;
    case OP_RENEW:
        if (!xdr_RENEW4args (xdrs, &objp->nfs_argop4_u.oprenew))
        {
            return FALSE;
        }
        break;
    case OP_RESTOREFH:
        break;
    case OP_SAVEFH:
        break;
    case OP_SECINFO:
        if (!xdr_SECINFO4args (xdrs, &objp->nfs_argop4_u.opsecinfo))
        {
            return FALSE;
        }
        break;
    case OP_SETATTR:
        if (!xdr_SETATTR4args (xdrs, &objp->nfs_argop4_u.opsetattr))
        {
            return FALSE;
        }
        break;
    case OP_SETCLIENTID:
        if (!xdr_SETCLIENTID4args (xdrs, &objp->nfs_argop4_u.opsetclientid))
        {
            return FALSE;
        }
        break;
    case OP_SETCLIENTID_CONFIRM:
        if (!xdr_SETCLIENTID_CONFIRM4args (xdrs, &objp->nfs_argop4_u.opsetclientid_confirm))
        {
            return FALSE;
        }
        break;
    case OP_VERIFY:
        if (!xdr_VERIFY4args (xdrs, &objp->nfs_argop4_u.opverify))
        {
            return FALSE;
        }
        break;
    case OP_WRITE:
        if (!xdr_WRITE4args (xdrs, &objp->nfs_argop4_u.opwrite))
        {
            return FALSE;
        }
        break;
    case OP_RELEASE_LOCKOWNER:
        if (!xdr_RELEASE_LOCKOWNER4args (xdrs, &objp->nfs_argop4_u.oprelease_lockowner))
        {
            return FALSE;
        }
        break;
    case OP_BACKCHANNEL_CTL:
        if (!xdr_BACKCHANNEL_CTL4args (xdrs, &objp->nfs_argop4_u.opbackchannel_ctl))
        {
            return FALSE;
        }
        break;
    case OP_BIND_CONN_TO_SESSION:
        if (!xdr_BIND_CONN_TO_SESSION4args (xdrs, &objp->nfs_argop4_u.opbind_conn_to_session))
        {
            return FALSE;
        }
        break;
    case OP_EXCHANGE_ID:
        if (!xdr_EXCHANGE_ID4args (xdrs, &objp->nfs_argop4_u.opexchange_id))
        {
            return FALSE;
        }
        break;
    case OP_CREATE_SESSION:
        if (!xdr_CREATE_SESSION4args (xdrs, &objp->nfs_argop4_u.opcreate_session))
        {
            return FALSE;
        }
        break;
    case OP_DESTROY_SESSION:
        if (!xdr_DESTROY_SESSION4args (xdrs, &objp->nfs_argop4_u.opdestroy_session))
        {
            return FALSE;
        }
        break;
    case OP_FREE_STATEID:
        if (!xdr_FREE_STATEID4args (xdrs, &objp->nfs_argop4_u.opfree_stateid))
        {
            return FALSE;
        }
        break;
    case OP_GET_DIR_DELEGATION:
        if (!xdr_GET_DIR_DELEGATION4args (xdrs, &objp->nfs_argop4_u.opget_dir_delegation))
        {
            return FALSE;
        }
        break;
    case OP_GETDEVICEINFO:
        if (!xdr_GETDEVICEINFO4args (xdrs, &objp->nfs_argop4_u.opgetdeviceinfo))
        {
            return FALSE;
        }
        break;
    case OP_GETDEVICELIST:
        if (!xdr_GETDEVICELIST4args (xdrs, &objp->nfs_argop4_u.opgetdevicelist))
        {
            return FALSE;
        }
        break;
    case OP_LAYOUTCOMMIT:
        if (!xdr_LAYOUTCOMMIT4args (xdrs, &objp->nfs_argop4_u.oplayoutcommit))
        {
            return FALSE;
        }
        break;
    case OP_LAYOUTGET:
        if (!xdr_LAYOUTGET4args (xdrs, &objp->nfs_argop4_u.oplayoutget))
        {
            return FALSE;
        }
        break;
    case OP_LAYOUTRETURN:
        if (!xdr_LAYOUTRETURN4args (xdrs, &objp->nfs_argop4_u.oplayoutreturn))
        {
            return FALSE;
        }
        break;
    case OP_SECINFO_NO_NAME:
        if (!xdr_SECINFO_NO_NAME4args (xdrs, &objp->nfs_argop4_u.opsecinfo_no_name))
        {
            return FALSE;
        }
        break;
    case OP_SEQUENCE:
        if (!xdr_SEQUENCE4args (xdrs, &objp->nfs_argop4_u.opsequence))
        {
            return FALSE;
        }
        break;
    case OP_SET_SSV:
        if (!xdr_SET_SSV4args (xdrs, &objp->nfs_argop4_u.opset_ssv))
        {
            return FALSE;
        }
        break;
    case OP_TEST_STATEID:
        if (!xdr_TEST_STATEID4args (xdrs, &objp->nfs_argop4_u.optest_stateid))
        {
            return FALSE;
        }
        break;
    case OP_WANT_DELEGATION:
        if (!xdr_WANT_DELEGATION4args (xdrs, &objp->nfs_argop4_u.opwant_delegation))
        {
            return FALSE;
        }
        break;
    case OP_DESTROY_CLIENTID:
        if (!xdr_DESTROY_CLIENTID4args (xdrs, &objp->nfs_argop4_u.opdestroy_clientid))
        {
            return FALSE;
        }
        break;
    case OP_RECLAIM_COMPLETE:
        if (!xdr_RECLAIM_COMPLETE4args (xdrs, &objp->nfs_argop4_u.opreclaim_complete))
        {
            return FALSE;
        }
        break;
    case OP_ILLEGAL:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_resop4 (XDR* xdrs, nfs_resop4* objp)
{
    if (!xdr_nfs_opnum4 (xdrs, &objp->resop))
    {
        return FALSE;
    }
    switch (objp->resop)
    {
    case OP_ACCESS:
        if (!xdr_ACCESS4res (xdrs, &objp->nfs_resop4_u.opaccess))
        {
            return FALSE;
        }
        break;
    case OP_CLOSE:
        if (!xdr_CLOSE4res (xdrs, &objp->nfs_resop4_u.opclose))
        {
            return FALSE;
        }
        break;
    case OP_COMMIT:
        if (!xdr_COMMIT4res (xdrs, &objp->nfs_resop4_u.opcommit))
        {
            return FALSE;
        }
        break;
    case OP_CREATE:
        if (!xdr_CREATE4res (xdrs, &objp->nfs_resop4_u.opcreate))
        {
            return FALSE;
        }
        break;
    case OP_DELEGPURGE:
        if (!xdr_DELEGPURGE4res (xdrs, &objp->nfs_resop4_u.opdelegpurge))
        {
            return FALSE;
        }
        break;
    case OP_DELEGRETURN:
        if (!xdr_DELEGRETURN4res (xdrs, &objp->nfs_resop4_u.opdelegreturn))
        {
            return FALSE;
        }
        break;
    case OP_GETATTR:
        if (!xdr_GETATTR4res (xdrs, &objp->nfs_resop4_u.opgetattr))
        {
            return FALSE;
        }
        break;
    case OP_GETFH:
        if (!xdr_GETFH4res (xdrs, &objp->nfs_resop4_u.opgetfh))
        {
            return FALSE;
        }
        break;
    case OP_LINK:
        if (!xdr_LINK4res (xdrs, &objp->nfs_resop4_u.oplink))
        {
            return FALSE;
        }
        break;
    case OP_LOCK:
        if (!xdr_LOCK4res (xdrs, &objp->nfs_resop4_u.oplock))
        {
            return FALSE;
        }
        break;
    case OP_LOCKT:
        if (!xdr_LOCKT4res (xdrs, &objp->nfs_resop4_u.oplockt))
        {
            return FALSE;
        }
        break;
    case OP_LOCKU:
        if (!xdr_LOCKU4res (xdrs, &objp->nfs_resop4_u.oplocku))
        {
            return FALSE;
        }
        break;
    case OP_LOOKUP:
        if (!xdr_LOOKUP4res (xdrs, &objp->nfs_resop4_u.oplookup))
        {
            return FALSE;
        }
        break;
    case OP_LOOKUPP:
        if (!xdr_LOOKUPP4res (xdrs, &objp->nfs_resop4_u.oplookupp))
        {
            return FALSE;
        }
        break;
    case OP_NVERIFY:
        if (!xdr_NVERIFY4res (xdrs, &objp->nfs_resop4_u.opnverify))
        {
            return FALSE;
        }
        break;
    case OP_OPEN:
        if (!xdr_OPEN4res (xdrs, &objp->nfs_resop4_u.opopen))
        {
            return FALSE;
        }
        break;
    case OP_OPENATTR:
        if (!xdr_OPENATTR4res (xdrs, &objp->nfs_resop4_u.opopenattr))
        {
            return FALSE;
        }
        break;
    case OP_OPEN_CONFIRM:
        if (!xdr_OPEN_CONFIRM4res (xdrs, &objp->nfs_resop4_u.opopen_confirm))
        {
            return FALSE;
        }
        break;
    case OP_OPEN_DOWNGRADE:
        if (!xdr_OPEN_DOWNGRADE4res (xdrs, &objp->nfs_resop4_u.opopen_downgrade))
        {
            return FALSE;
        }
        break;
    case OP_PUTFH:
        if (!xdr_PUTFH4res (xdrs, &objp->nfs_resop4_u.opputfh))
        {
            return FALSE;
        }
        break;
    case OP_PUTPUBFH:
        if (!xdr_PUTPUBFH4res (xdrs, &objp->nfs_resop4_u.opputpubfh))
        {
            return FALSE;
        }
        break;
    case OP_PUTROOTFH:
        if (!xdr_PUTROOTFH4res (xdrs, &objp->nfs_resop4_u.opputrootfh))
        {
            return FALSE;
        }
        break;
    case OP_READ:
        if (!xdr_READ4res (xdrs, &objp->nfs_resop4_u.opread))
        {
            return FALSE;
        }
        break;
    case OP_READDIR:
        if (!xdr_READDIR4res (xdrs, &objp->nfs_resop4_u.opreaddir))
        {
            return FALSE;
        }
        break;
    case OP_READLINK:
        if (!xdr_READLINK4res (xdrs, &objp->nfs_resop4_u.opreadlink))
        {
            return FALSE;
        }
        break;
    case OP_REMOVE:
        if (!xdr_REMOVE4res (xdrs, &objp->nfs_resop4_u.opremove))
        {
            return FALSE;
        }
        break;
    case OP_RENAME:
        if (!xdr_RENAME4res (xdrs, &objp->nfs_resop4_u.oprename))
        {
            return FALSE;
        }
        break;
    case OP_RENEW:
        if (!xdr_RENEW4res (xdrs, &objp->nfs_resop4_u.oprenew))
        {
            return FALSE;
        }
        break;
    case OP_RESTOREFH:
        if (!xdr_RESTOREFH4res (xdrs, &objp->nfs_resop4_u.oprestorefh))
        {
            return FALSE;
        }
        break;
    case OP_SAVEFH:
        if (!xdr_SAVEFH4res (xdrs, &objp->nfs_resop4_u.opsavefh))
        {
            return FALSE;
        }
        break;
    case OP_SECINFO:
        if (!xdr_SECINFO4res (xdrs, &objp->nfs_resop4_u.opsecinfo))
        {
            return FALSE;
        }
        break;
    case OP_SETATTR:
        if (!xdr_SETATTR4res (xdrs, &objp->nfs_resop4_u.opsetattr))
        {
            return FALSE;
        }
        break;
    case OP_SETCLIENTID:
        if (!xdr_SETCLIENTID4res (xdrs, &objp->nfs_resop4_u.opsetclientid))
        {
            return FALSE;
        }
        break;
    case OP_SETCLIENTID_CONFIRM:
        if (!xdr_SETCLIENTID_CONFIRM4res (xdrs, &objp->nfs_resop4_u.opsetclientid_confirm))
        {
            return FALSE;
        }
        break;
    case OP_VERIFY:
        if (!xdr_VERIFY4res (xdrs, &objp->nfs_resop4_u.opverify))
        {
            return FALSE;
        }
        break;
    case OP_WRITE:
        if (!xdr_WRITE4res (xdrs, &objp->nfs_resop4_u.opwrite))
        {
            return FALSE;
        }
        break;
    case OP_RELEASE_LOCKOWNER:
        if (!xdr_RELEASE_LOCKOWNER4res (xdrs, &objp->nfs_resop4_u.oprelease_lockowner))
        {
            return FALSE;
        }
        break;
    case OP_BACKCHANNEL_CTL:
        if (!xdr_BACKCHANNEL_CTL4res (xdrs, &objp->nfs_resop4_u.opbackchannel_ctl))
        {
            return FALSE;
        }
        break;
    case OP_BIND_CONN_TO_SESSION:
        if (!xdr_BIND_CONN_TO_SESSION4res (xdrs, &objp->nfs_resop4_u.opbind_conn_to_session))
        {
            return FALSE;
        }
        break;
    case OP_EXCHANGE_ID:
        if (!xdr_EXCHANGE_ID4res (xdrs, &objp->nfs_resop4_u.opexchange_id))
        {
            return FALSE;
        }
        break;
    case OP_CREATE_SESSION:
        if (!xdr_CREATE_SESSION4res (xdrs, &objp->nfs_resop4_u.opcreate_session))
        {
            return FALSE;
        }
        break;
    case OP_DESTROY_SESSION:
        if (!xdr_DESTROY_SESSION4res (xdrs, &objp->nfs_resop4_u.opdestroy_session))
        {
            return FALSE;
        }
        break;
    case OP_FREE_STATEID:
        if (!xdr_FREE_STATEID4res (xdrs, &objp->nfs_resop4_u.opfree_stateid))
        {
            return FALSE;
        }
        break;
    case OP_GET_DIR_DELEGATION:
        if (!xdr_GET_DIR_DELEGATION4res (xdrs, &objp->nfs_resop4_u.opget_dir_delegation))
        {
            return FALSE;
        }
        break;
    case OP_GETDEVICEINFO:
        if (!xdr_GETDEVICEINFO4res (xdrs, &objp->nfs_resop4_u.opgetdeviceinfo))
        {
            return FALSE;
        }
        break;
    case OP_GETDEVICELIST:
        if (!xdr_GETDEVICELIST4res (xdrs, &objp->nfs_resop4_u.opgetdevicelist))
        {
            return FALSE;
        }
        break;
    case OP_LAYOUTCOMMIT:
        if (!xdr_LAYOUTCOMMIT4res (xdrs, &objp->nfs_resop4_u.oplayoutcommit))
        {
            return FALSE;
        }
        break;
    case OP_LAYOUTGET:
        if (!xdr_LAYOUTGET4res (xdrs, &objp->nfs_resop4_u.oplayoutget))
        {
            return FALSE;
        }
        break;
    case OP_LAYOUTRETURN:
        if (!xdr_LAYOUTRETURN4res (xdrs, &objp->nfs_resop4_u.oplayoutreturn))
        {
            return FALSE;
        }
        break;
    case OP_SECINFO_NO_NAME:
        if (!xdr_SECINFO_NO_NAME4res (xdrs, &objp->nfs_resop4_u.opsecinfo_no_name))
        {
            return FALSE;
        }
        break;
    case OP_SEQUENCE:
        if (!xdr_SEQUENCE4res (xdrs, &objp->nfs_resop4_u.opsequence))
        {
            return FALSE;
        }
        break;
    case OP_SET_SSV:
        if (!xdr_SET_SSV4res (xdrs, &objp->nfs_resop4_u.opset_ssv))
        {
            return FALSE;
        }
        break;
    case OP_TEST_STATEID:
        if (!xdr_TEST_STATEID4res (xdrs, &objp->nfs_resop4_u.optest_stateid))
        {
            return FALSE;
        }
        break;
    case OP_WANT_DELEGATION:
        if (!xdr_WANT_DELEGATION4res (xdrs, &objp->nfs_resop4_u.opwant_delegation))
        {
            return FALSE;
        }
        break;
    case OP_DESTROY_CLIENTID:
        if (!xdr_DESTROY_CLIENTID4res (xdrs, &objp->nfs_resop4_u.opdestroy_clientid))
        {
            return FALSE;
        }
        break;
    case OP_RECLAIM_COMPLETE:
        if (!xdr_RECLAIM_COMPLETE4res (xdrs, &objp->nfs_resop4_u.opreclaim_complete))
        {
            return FALSE;
        }
        break;
    case OP_ILLEGAL:
        if (!xdr_ILLEGAL4res (xdrs, &objp->nfs_resop4_u.opillegal))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_COMPOUND4args (XDR* xdrs, COMPOUND4args* objp)
{
    if (!xdr_utf8str_cs (xdrs, &objp->tag))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->minorversion))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->argarray.argarray_val, (u_int*) &objp->argarray.argarray_len, ~0,
                    sizeof (nfs_argop4), (xdrproc_t) xdr_nfs_argop4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_COMPOUND4res (XDR* xdrs, COMPOUND4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    if (!xdr_utf8str_cs (xdrs, &objp->tag))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->resarray.resarray_val, (u_int*) &objp->resarray.resarray_len, ~0,
                    sizeof (nfs_resop4), (xdrproc_t) xdr_nfs_resop4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_GETATTR4args (XDR* xdrs, CB_GETATTR4args* objp)
{
    if (!xdr_nfs_fh4 (xdrs, &objp->fh))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->attr_request))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_GETATTR4resok (XDR* xdrs, CB_GETATTR4resok* objp)
{
    if (!xdr_fattr4 (xdrs, &objp->obj_attributes))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_GETATTR4res (XDR* xdrs, CB_GETATTR4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    switch (objp->status)
    {
    case NFS4_OK:
        if (!xdr_CB_GETATTR4resok (xdrs, &objp->CB_GETATTR4res_u.resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_CB_RECALL4args (XDR* xdrs, CB_RECALL4args* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->stateid))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->truncate))
    {
        return FALSE;
    }
    if (!xdr_nfs_fh4 (xdrs, &objp->fh))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_RECALL4res (XDR* xdrs, CB_RECALL4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_ILLEGAL4res (XDR* xdrs, CB_ILLEGAL4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layoutrecall_type4 (XDR* xdrs, layoutrecall_type4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layoutrecall_file4 (XDR* xdrs, layoutrecall_file4* objp)
{
    if (!xdr_nfs_fh4 (xdrs, &objp->lor_fh))
    {
        return FALSE;
    }
    if (!xdr_offset4 (xdrs, &objp->lor_offset))
    {
        return FALSE;
    }
    if (!xdr_length4 (xdrs, &objp->lor_length))
    {
        return FALSE;
    }
    if (!xdr_stateid4 (xdrs, &objp->lor_stateid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_layoutrecall4 (XDR* xdrs, layoutrecall4* objp)
{
    if (!xdr_layoutrecall_type4 (xdrs, &objp->lor_recalltype))
    {
        return FALSE;
    }
    switch (objp->lor_recalltype)
    {
    case LAYOUTRECALL4_FILE:
        if (!xdr_layoutrecall_file4 (xdrs, &objp->layoutrecall4_u.lor_layout))
        {
            return FALSE;
        }
        break;
    case LAYOUTRECALL4_FSID:
        if (!xdr_fsid4 (xdrs, &objp->layoutrecall4_u.lor_fsid))
        {
            return FALSE;
        }
        break;
    case LAYOUTRECALL4_ALL:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_LAYOUTRECALL4args (XDR* xdrs, CB_LAYOUTRECALL4args* objp)
{
    if (!xdr_layouttype4 (xdrs, &objp->clora_type))
    {
        return FALSE;
    }
    if (!xdr_layoutiomode4 (xdrs, &objp->clora_iomode))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->clora_changed))
    {
        return FALSE;
    }
    if (!xdr_layoutrecall4 (xdrs, &objp->clora_recall))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_LAYOUTRECALL4res (XDR* xdrs, CB_LAYOUTRECALL4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->clorr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_type4 (XDR* xdrs, notify_type4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_entry4 (XDR* xdrs, notify_entry4* objp)
{
    if (!xdr_component4 (xdrs, &objp->ne_file))
    {
        return FALSE;
    }
    if (!xdr_fattr4 (xdrs, &objp->ne_attrs))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_prev_entry4 (XDR* xdrs, prev_entry4* objp)
{
    if (!xdr_notify_entry4 (xdrs, &objp->pe_prev_entry))
    {
        return FALSE;
    }
    if (!xdr_nfs_cookie4 (xdrs, &objp->pe_prev_entry_cookie))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_remove4 (XDR* xdrs, notify_remove4* objp)
{
    if (!xdr_notify_entry4 (xdrs, &objp->nrm_old_entry))
    {
        return FALSE;
    }
    if (!xdr_nfs_cookie4 (xdrs, &objp->nrm_old_entry_cookie))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_add4 (XDR* xdrs, notify_add4* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->nad_old_entry.nad_old_entry_val, (u_int*) &objp->nad_old_entry.nad_old_entry_len, 1,
                    sizeof (notify_remove4), (xdrproc_t) xdr_notify_remove4))
    {
        return FALSE;
    }
    if (!xdr_notify_entry4 (xdrs, &objp->nad_new_entry))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->nad_new_entry_cookie.nad_new_entry_cookie_val, (u_int*) &objp->nad_new_entry_cookie.nad_new_entry_cookie_len, 1,
                    sizeof (nfs_cookie4), (xdrproc_t) xdr_nfs_cookie4))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->nad_prev_entry.nad_prev_entry_val, (u_int*) &objp->nad_prev_entry.nad_prev_entry_len, 1,
                    sizeof (prev_entry4), (xdrproc_t) xdr_prev_entry4))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->nad_last_entry))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_attr4 (XDR* xdrs, notify_attr4* objp)
{
    if (!xdr_notify_entry4 (xdrs, &objp->na_changed_entry))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_rename4 (XDR* xdrs, notify_rename4* objp)
{
    if (!xdr_notify_remove4 (xdrs, &objp->nrn_old_entry))
    {
        return FALSE;
    }
    if (!xdr_notify_add4 (xdrs, &objp->nrn_new_entry))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_verifier4 (XDR* xdrs, notify_verifier4* objp)
{
    if (!xdr_verifier4 (xdrs, objp->nv_old_cookieverf))
    {
        return FALSE;
    }
    if (!xdr_verifier4 (xdrs, objp->nv_new_cookieverf))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notifylist4 (XDR* xdrs, notifylist4* objp)
{
    if (!xdr_bytes (xdrs, (char**)&objp->notifylist4_val, (u_int*) &objp->notifylist4_len, ~0))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify4 (XDR* xdrs, notify4* objp)
{
    if (!xdr_bitmap4 (xdrs, &objp->notify_mask))
    {
        return FALSE;
    }
    if (!xdr_notifylist4 (xdrs, &objp->notify_vals))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_NOTIFY4args (XDR* xdrs, CB_NOTIFY4args* objp)
{
    if (!xdr_stateid4 (xdrs, &objp->cna_stateid))
    {
        return FALSE;
    }
    if (!xdr_nfs_fh4 (xdrs, &objp->cna_fh))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->cna_changes.cna_changes_val, (u_int*) &objp->cna_changes.cna_changes_len, ~0,
                    sizeof (notify4), (xdrproc_t) xdr_notify4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_NOTIFY4res (XDR* xdrs, CB_NOTIFY4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->cnr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_PUSH_DELEG4args (XDR* xdrs, CB_PUSH_DELEG4args* objp)
{
    if (!xdr_nfs_fh4 (xdrs, &objp->cpda_fh))
    {
        return FALSE;
    }
    if (!xdr_open_delegation4 (xdrs, &objp->cpda_delegation))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_PUSH_DELEG4res (XDR* xdrs, CB_PUSH_DELEG4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->cpdr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_RECALL_ANY4args (XDR* xdrs, CB_RECALL_ANY4args* objp)
{
    if (!xdr_uint32_t (xdrs, &objp->craa_objects_to_keep))
    {
        return FALSE;
    }
    if (!xdr_bitmap4 (xdrs, &objp->craa_type_mask))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_RECALL_ANY4res (XDR* xdrs, CB_RECALL_ANY4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->crar_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_RECALLABLE_OBJ_AVAIL4args (XDR* xdrs, CB_RECALLABLE_OBJ_AVAIL4args* objp)
{
    if (!xdr_CB_RECALL_ANY4args (xdrs, objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_RECALLABLE_OBJ_AVAIL4res (XDR* xdrs, CB_RECALLABLE_OBJ_AVAIL4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->croa_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_RECALL_SLOT4args (XDR* xdrs, CB_RECALL_SLOT4args* objp)
{
    if (!xdr_slotid4 (xdrs, &objp->rsa_target_highest_slotid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_RECALL_SLOT4res (XDR* xdrs, CB_RECALL_SLOT4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->rsr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_referring_call4 (XDR* xdrs, referring_call4* objp)
{
    if (!xdr_sequenceid4 (xdrs, &objp->rc_sequenceid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->rc_slotid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_referring_call_list4 (XDR* xdrs, referring_call_list4* objp)
{
    if (!xdr_sessionid4 (xdrs, objp->rcl_sessionid))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->rcl_referring_calls.rcl_referring_calls_val, (u_int*) &objp->rcl_referring_calls.rcl_referring_calls_len, ~0,
                    sizeof (referring_call4), (xdrproc_t) xdr_referring_call4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_SEQUENCE4args (XDR* xdrs, CB_SEQUENCE4args* objp)
{
    if (!xdr_sessionid4 (xdrs, objp->csa_sessionid))
    {
        return FALSE;
    }
    if (!xdr_sequenceid4 (xdrs, &objp->csa_sequenceid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->csa_slotid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->csa_highest_slotid))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->csa_cachethis))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->csa_referring_call_lists.csa_referring_call_lists_val, (u_int*) &objp->csa_referring_call_lists.csa_referring_call_lists_len, ~0,
                    sizeof (referring_call_list4), (xdrproc_t) xdr_referring_call_list4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_SEQUENCE4resok (XDR* xdrs, CB_SEQUENCE4resok* objp)
{
    if (!xdr_sessionid4 (xdrs, objp->csr_sessionid))
    {
        return FALSE;
    }
    if (!xdr_sequenceid4 (xdrs, &objp->csr_sequenceid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->csr_slotid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->csr_highest_slotid))
    {
        return FALSE;
    }
    if (!xdr_slotid4 (xdrs, &objp->csr_target_highest_slotid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_SEQUENCE4res (XDR* xdrs, CB_SEQUENCE4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->csr_status))
    {
        return FALSE;
    }
    switch (objp->csr_status)
    {
    case NFS4_OK:
        if (!xdr_CB_SEQUENCE4resok (xdrs, &objp->CB_SEQUENCE4res_u.csr_resok4))
        {
            return FALSE;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_CB_WANTS_CANCELLED4args (XDR* xdrs, CB_WANTS_CANCELLED4args* objp)
{
    if (!xdr_bool (xdrs, &objp->cwca_contended_wants_cancelled))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->cwca_resourced_wants_cancelled))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_WANTS_CANCELLED4res (XDR* xdrs, CB_WANTS_CANCELLED4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->cwcr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_NOTIFY_LOCK4args (XDR* xdrs, CB_NOTIFY_LOCK4args* objp)
{
    if (!xdr_nfs_fh4 (xdrs, &objp->cnla_fh))
    {
        return FALSE;
    }
    if (!xdr_lock_owner4 (xdrs, &objp->cnla_lock_owner))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_NOTIFY_LOCK4res (XDR* xdrs, CB_NOTIFY_LOCK4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->cnlr_status))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_deviceid_type4 (XDR* xdrs, notify_deviceid_type4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_deviceid_delete4 (XDR* xdrs, notify_deviceid_delete4* objp)
{
    if (!xdr_layouttype4 (xdrs, &objp->ndd_layouttype))
    {
        return FALSE;
    }
    if (!xdr_deviceid4 (xdrs, objp->ndd_deviceid))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_notify_deviceid_change4 (XDR* xdrs, notify_deviceid_change4* objp)
{
    if (!xdr_layouttype4 (xdrs, &objp->ndc_layouttype))
    {
        return FALSE;
    }
    if (!xdr_deviceid4 (xdrs, objp->ndc_deviceid))
    {
        return FALSE;
    }
    if (!xdr_bool (xdrs, &objp->ndc_immediate))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_NOTIFY_DEVICEID4args (XDR* xdrs, CB_NOTIFY_DEVICEID4args* objp)
{
    if (!xdr_array (xdrs, (char**)&objp->cnda_changes.cnda_changes_val, (u_int*) &objp->cnda_changes.cnda_changes_len, ~0,
                    sizeof (notify4), (xdrproc_t) xdr_notify4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_NOTIFY_DEVICEID4res (XDR* xdrs, CB_NOTIFY_DEVICEID4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->cndr_status))
    {
        return FALSE;
    }
    return TRUE;
}

/* Callback operations new to NFSv4.1 */

bool_t
xdr_nfs_cb_opnum4 (XDR* xdrs, nfs_cb_opnum4* objp)
{
    if (!xdr_enum (xdrs, (enum_t*) objp))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_cb_argop4 (XDR* xdrs, nfs_cb_argop4* objp)
{
    if (!xdr_u_int (xdrs, &objp->argop))
    {
        return FALSE;
    }
    switch (objp->argop)
    {
    case OP_CB_GETATTR:
        if (!xdr_CB_GETATTR4args (xdrs, &objp->nfs_cb_argop4_u.opcbgetattr))
        {
            return FALSE;
        }
        break;
    case OP_CB_RECALL:
        if (!xdr_CB_RECALL4args (xdrs, &objp->nfs_cb_argop4_u.opcbrecall))
        {
            return FALSE;
        }
        break;
    case OP_CB_LAYOUTRECALL:
        if (!xdr_CB_LAYOUTRECALL4args (xdrs, &objp->nfs_cb_argop4_u.opcblayoutrecall))
        {
            return FALSE;
        }
        break;
    case OP_CB_NOTIFY:
        if (!xdr_CB_NOTIFY4args (xdrs, &objp->nfs_cb_argop4_u.opcbnotify))
        {
            return FALSE;
        }
        break;
    case OP_CB_PUSH_DELEG:
        if (!xdr_CB_PUSH_DELEG4args (xdrs, &objp->nfs_cb_argop4_u.opcbpush_deleg))
        {
            return FALSE;
        }
        break;
    case OP_CB_RECALL_ANY:
        if (!xdr_CB_RECALL_ANY4args (xdrs, &objp->nfs_cb_argop4_u.opcbrecall_any))
        {
            return FALSE;
        }
        break;
    case OP_CB_RECALLABLE_OBJ_AVAIL:
        if (!xdr_CB_RECALLABLE_OBJ_AVAIL4args (xdrs, &objp->nfs_cb_argop4_u.opcbrecallable_obj_avail))
        {
            return FALSE;
        }
        break;
    case OP_CB_RECALL_SLOT:
        if (!xdr_CB_RECALL_SLOT4args (xdrs, &objp->nfs_cb_argop4_u.opcbrecall_slot))
        {
            return FALSE;
        }
        break;
    case OP_CB_SEQUENCE:
        if (!xdr_CB_SEQUENCE4args (xdrs, &objp->nfs_cb_argop4_u.opcbsequence))
        {
            return FALSE;
        }
        break;
    case OP_CB_WANTS_CANCELLED:
        if (!xdr_CB_WANTS_CANCELLED4args (xdrs, &objp->nfs_cb_argop4_u.opcbwants_cancelled))
        {
            return FALSE;
        }
        break;
    case OP_CB_NOTIFY_LOCK:
        if (!xdr_CB_NOTIFY_LOCK4args (xdrs, &objp->nfs_cb_argop4_u.opcbnotify_lock))
        {
            return FALSE;
        }
        break;
    case OP_CB_NOTIFY_DEVICEID:
        if (!xdr_CB_NOTIFY_DEVICEID4args (xdrs, &objp->nfs_cb_argop4_u.opcbnotify_deviceid))
        {
            return FALSE;
        }
        break;
    case OP_CB_ILLEGAL:
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_nfs_cb_resop4 (XDR* xdrs, nfs_cb_resop4* objp)
{
    if (!xdr_u_int (xdrs, &objp->resop))
    {
        return FALSE;
    }
    switch (objp->resop)
    {
    case OP_CB_GETATTR:
        if (!xdr_CB_GETATTR4res (xdrs, &objp->nfs_cb_resop4_u.opcbgetattr))
        {
            return FALSE;
        }
        break;
    case OP_CB_RECALL:
        if (!xdr_CB_RECALL4res (xdrs, &objp->nfs_cb_resop4_u.opcbrecall))
        {
            return FALSE;
        }
        break;
    case OP_CB_LAYOUTRECALL:
        if (!xdr_CB_LAYOUTRECALL4res (xdrs, &objp->nfs_cb_resop4_u.opcblayoutrecall))
        {
            return FALSE;
        }
        break;
    case OP_CB_NOTIFY:
        if (!xdr_CB_NOTIFY4res (xdrs, &objp->nfs_cb_resop4_u.opcbnotify))
        {
            return FALSE;
        }
        break;
    case OP_CB_PUSH_DELEG:
        if (!xdr_CB_PUSH_DELEG4res (xdrs, &objp->nfs_cb_resop4_u.opcbpush_deleg))
        {
            return FALSE;
        }
        break;
    case OP_CB_RECALL_ANY:
        if (!xdr_CB_RECALL_ANY4res (xdrs, &objp->nfs_cb_resop4_u.opcbrecall_any))
        {
            return FALSE;
        }
        break;
    case OP_CB_RECALLABLE_OBJ_AVAIL:
        if (!xdr_CB_RECALLABLE_OBJ_AVAIL4res (xdrs, &objp->nfs_cb_resop4_u.opcbrecallable_obj_avail))
        {
            return FALSE;
        }
        break;
    case OP_CB_RECALL_SLOT:
        if (!xdr_CB_RECALL_SLOT4res (xdrs, &objp->nfs_cb_resop4_u.opcbrecall_slot))
        {
            return FALSE;
        }
        break;
    case OP_CB_SEQUENCE:
        if (!xdr_CB_SEQUENCE4res (xdrs, &objp->nfs_cb_resop4_u.opcbsequence))
        {
            return FALSE;
        }
        break;
    case OP_CB_WANTS_CANCELLED:
        if (!xdr_CB_WANTS_CANCELLED4res (xdrs, &objp->nfs_cb_resop4_u.opcbwants_cancelled))
        {
            return FALSE;
        }
        break;
    case OP_CB_NOTIFY_LOCK:
        if (!xdr_CB_NOTIFY_LOCK4res (xdrs, &objp->nfs_cb_resop4_u.opcbnotify_lock))
        {
            return FALSE;
        }
        break;
    case OP_CB_NOTIFY_DEVICEID:
        if (!xdr_CB_NOTIFY_DEVICEID4res (xdrs, &objp->nfs_cb_resop4_u.opcbnotify_deviceid))
        {
            return FALSE;
        }
        break;
    case OP_CB_ILLEGAL:
        if (!xdr_CB_ILLEGAL4res (xdrs, &objp->nfs_cb_resop4_u.opcbillegal))
        {
            return FALSE;
        }
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_COMPOUND4args (XDR* xdrs, CB_COMPOUND4args* objp)
{
    if (!xdr_utf8str_cs (xdrs, &objp->tag))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->minorversion))
    {
        return FALSE;
    }
    if (!xdr_uint32_t (xdrs, &objp->callback_ident))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->argarray.argarray_val, (u_int*) &objp->argarray.argarray_len, ~0,
                    sizeof (nfs_cb_argop4), (xdrproc_t) xdr_nfs_cb_argop4))
    {
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_CB_COMPOUND4res (XDR* xdrs, CB_COMPOUND4res* objp)
{
    if (!xdr_nfsstat4 (xdrs, &objp->status))
    {
        return FALSE;
    }
    if (!xdr_utf8str_cs (xdrs, &objp->tag))
    {
        return FALSE;
    }
    if (!xdr_array (xdrs, (char**)&objp->resarray.resarray_val, (u_int*) &objp->resarray.resarray_len, ~0,
                    sizeof (nfs_cb_resop4), (xdrproc_t) xdr_nfs_cb_resop4))
    {
        return FALSE;
    }
    return TRUE;
}

} // namespace NFS41
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
