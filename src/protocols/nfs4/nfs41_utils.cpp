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
    out <<  "header pad size: "          << obj.ca_headerpadsize
        << " max request size: "         << obj.ca_maxrequestsize
        << " max response size: "        << obj.ca_maxresponsesize
        << " max response size cached: " << obj.ca_maxresponsesize_cached
        << " max operations: "           << obj.ca_maxoperations
        << " max requests: "             << obj.ca_maxrequests
        << " rdma ird: ";
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

} // namespace NFS41
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
