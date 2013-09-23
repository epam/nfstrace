//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: All RFC1813 declared structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS3_TYPES_H
#define NFS3_TYPES_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

const uint32_t NFS3_FHSIZE = 64;
const uint32_t NFS3_COOKIEVERFSIZE = 8;
const uint32_t NFS3_CREATEVERFSIZE = 8;
const uint32_t NFS3_WRITEVERFSIZE  = 8;
//------------------------------------------------------------------------------
typedef Opaque      filename3;
typedef Opaque      nfspath3;
typedef uint64_t    fileid3;
typedef uint64_t    cookie3;
typedef Opaque      cookieverf3;
typedef Opaque      createverf3;
typedef Opaque      writeverf3;

typedef uint32_t    uid3;
typedef uint32_t    gid3;
typedef uint64_t    size3;
typedef uint64_t    offset3;
typedef uint32_t    count3;

struct ProcEnum
{
    enum NFSProcedure
    {
        NFS_NULL    = 0,
        GETATTR     = 1,
        SETATTR     = 2,
        LOOKUP      = 3,
        ACCESS      = 4,
        READLINK    = 5,
        READ        = 6,
        WRITE       = 7,
        CREATE      = 8,
        MKDIR       = 9,
        SYMLINK     = 10,
        MKNOD       = 11,
        REMOVE      = 12,
        RMDIR       = 13,
        RENAME      = 14,
        LINK        = 15,
        READDIR     = 16,
        READDIRPLUS = 17,
        FSSTAT      = 18,
        FSINFO      = 19,
        PATHCONF    = 20,
        COMMIT      = 21
    };
    static const int32_t count = 22;
};

struct mode3
{
    enum Enum_mode3
    {
        USER_ID_EXEC      = 0x00800,
        GROUP_ID_EXEC     = 0x00400,
        SAVE_SWAPPED_TEXT = 0x00200, // Not defined in POSIX
        OWNER_READ        = 0x00100,
        OWNER_WRITE       = 0x00080,
        OWNER_EXEC        = 0x00040, // Search in directory
        GROUP_READ        = 0x00020,
        GROUP_WRITE       = 0x00010,
        GROUP_EXEC        = 0x00008, // Search in directory
        OTHER_READ        = 0x00004,
        OTHER_WRITE       = 0x00002,
        OTHER_EXEC        = 0x00001  // Search in directory
    };

    operator Enum_mode3() const { return Enum_mode3(mode); }

    uint32_t mode;
};

struct nfsstat3
{
    enum Enum_nfsstat3
    {
        OK              = 0,
        ERR_PERM        = 1,
        ERR_NOENT       = 2,
        ERR_IO          = 5,
        ERR_NXIO        = 6,
        ERR_ACCES       = 13,
        ERR_EXIST       = 17,
        ERR_XDEV        = 18,
        ERR_NODEV       = 19,
        ERR_NOTDIR      = 20,
        ERR_ISDIR       = 21,
        ERR_INVAL       = 22,
        ERR_FBIG        = 27,
        ERR_NOSPC       = 28,
        ERR_ROFS        = 30,
        ERR_MLINK       = 31,
        ERR_NAMETOOLONG = 63,
        ERR_NOTEMPTY    = 66,
        ERR_DQUOT       = 69,
        ERR_STALE       = 70,
        ERR_REMOTE      = 71,
        ERR_BADHANDLE   = 10001,
        ERR_NOT_SYNC    = 10002,
        ERR_BAD_COOKIE  = 10003,
        ERR_NOTSUPP     = 10004,
        ERR_TOOSMALL    = 10005,
        ERR_SERVERFAULT = 10006,
        ERR_BADTYPE     = 10007,
        ERR_JUKEBOX     = 10008
    };

    operator Enum_nfsstat3() const { return Enum_nfsstat3(stat); }

    uint32_t stat;
};

struct ftype3
{
    enum Enum_ftype3
    {
        REG  = 1,
        DIR  = 2,
        BLK  = 3,
        CHR  = 4,
        LNK  = 5,
        SOCK = 6,
        FIFO = 7
    };

    operator Enum_ftype3() const { return Enum_ftype3(ftype); }

    uint32_t ftype;
};

struct specdata3
{
    uint32_t specdata1;
    uint32_t specdata2;
};

struct nfs_fh3
{
    Opaque data;
};

struct nfstime3
{
    uint32_t seconds;
    uint32_t nseconds;
};

struct fattr3
{
    ftype3      type;
    mode3       mode;
    uint32_t    nlink;
    uid3        uid;
    gid3        gid;
    size3       size;
    size3       used;
    specdata3   rdev;
    uint64_t    fsid;
    fileid3     fileid;
    nfstime3    atime;
    nfstime3    mtime;
    nfstime3    ctime;
};

struct post_op_attr
{
    uint32_t attributes_follow;
    fattr3   attributes;
};

struct wcc_attr
{
    size3    size;
    nfstime3 mtime;
    nfstime3 ctime;
};

struct pre_op_attr
{
    uint32_t attributes_follow;
    wcc_attr attributes;
};

struct wcc_data
{
    pre_op_attr  before;
    post_op_attr after;
};

struct post_op_fh3
{
    uint32_t    handle_follows;
    nfs_fh3     handle;
};

struct sattr3
{
    enum time_how
    {
        DONT_CHANGE        = 0,
        SET_TO_SERVER_TIME = 1,
        SET_TO_CLIENT_TIME = 2
    };

    uint32_t set_it_mode;
    mode3    mode;
    uint32_t set_it_uid;
    uid3     uid;
    uint32_t set_it_gid;
    gid3     gid;
    uint32_t set_it_size;
    size3    size;
    uint32_t set_it_atime;
    nfstime3 atime;
    uint32_t set_it_mtime;
    nfstime3 mtime;
};

struct diropargs3
{
    nfs_fh3   dir;
    filename3 name;
};

// Procedure 0: NULL - Do nothing
// void NFSPROC3_NULL(void) = 0;
struct NULLargs
{
};

struct NULLres
{
};

// Procedure 1: GETATTR - Get file attributes
// GETATTR3res NFSPROC3_GETATTR(GETATTR3args) = 1;
struct GETATTR3args
{
    nfs_fh3 object;
};

struct GETATTR3res
{
    struct GETATTR3resok
    {
        fattr3 obj_attributes;
    };

    nfsstat3      status;
    GETATTR3resok resok;
};

// Procedure 2: SETATTR - Set file attributes
// SETATTR3res NFSPROC3_SETATTR(SETATTR3args) = 2;
struct sattrguard3
{
    bool     check;
    nfstime3 obj_ctime;
};

struct SETATTR3args
{
    nfs_fh3     object;
    sattr3      new_attributes;
    sattrguard3 guard;
};

struct SETATTR3res
{
    struct SETATTR3resok
    {
        wcc_data obj_wcc;
    };

    struct SETATTR3resfail
    {
        wcc_data obj_wcc;
    };

    nfsstat3 status;
    union
    {
        SETATTR3resok   resok;
        SETATTR3resfail resfail;
    };
};

// Procedure 3: LOOKUP -  Lookup filename
// LOOKUP3res NFSPROC3_LOOKUP(LOOKUP3args) = 3;
struct LOOKUP3args
{
    diropargs3 what;
};

struct LOOKUP3res
{
    struct LOOKUP3resok
    {
       nfs_fh3      object;
       post_op_attr obj_attributes;
       post_op_attr dir_attributes;
    };

    struct LOOKUP3resfail
    {
       post_op_attr dir_attributes;
    };

    nfsstat3 status;
    union
    {
        LOOKUP3resok   resok;
        LOOKUP3resfail resfail;
    };
};

// Procedure 4: ACCESS - Check Access Permission
// ACCESS3res NFSPROC3_ACCESS(ACCESS3args) = 4;
struct ACCESS3args
{
    enum
    {
        ACCESS3_READ    = 0x001,
        ACCESS3_LOOKUP  = 0x002,
        ACCESS3_MODIFY  = 0x004,
        ACCESS3_EXTEND  = 0x008,
        ACCESS3_DELETE  = 0x010,
        ACCESS3_EXECUTE = 0x020
    };

    nfs_fh3  object;
    uint32_t access;
};

struct ACCESS3res
{
    struct ACCESS3resok
    {
       post_op_attr obj_attributes;
       uint32_t access;
    };

    struct ACCESS3resfail
    {
       post_op_attr obj_attributes;
    };

    nfsstat3 status;
    union U
    {
        ACCESS3resok   resok;
        ACCESS3resfail resfail;
    } u;
};

// Procedure 5: READLINK - Read from symbolic link
// READLINK3res NFSPROC3_READLINK(READLINK3args) = 5;
struct READLINK3args
{
    nfs_fh3 symlink;
};

struct READLINK3res
{
    struct READLINK3resok
    {
       post_op_attr symlink_attributes;
       nfspath3 data;
    };

    struct READLINK3resfail
    {
       post_op_attr symlink_attributes;
    };

    nfsstat3 status;
    union U
    {
        READLINK3resok   resok;
        READLINK3resfail resfail;
    } u;
};

// Procedure 6: READ - Read From file
// READ3res NFSPROC3_READ(READ3args) = 6;
struct READ3args
{
    nfs_fh3 file;
    offset3 offset;
    count3  count;
};

struct READ3res
{
    struct READ3resok
    {
        post_op_attr file_attributes;
        count3 count;
        uint32_t eof; // bool
//        Opaque data; skiped on filtration
    };

    struct READ3resfail
    {
        post_op_attr file_attributes;
    };

    nfsstat3 status;
    union U
    {
        READ3resok   resok;
        READ3resfail resfail;
    } u;
};

// Procedure 7: WRITE - Write to file
// WRITE3res NFSPROC3_WRITE(WRITE3args) = 7;
struct stable_how
{
    enum Enum_stable_how
    {
        UNSTABLE    = 0,
        DATA_SYNC   = 1,
        FILE_SYNC   = 2
    };

    operator Enum_stable_how() const { return Enum_stable_how(stable); }

    uint32_t stable;
};

struct WRITE3args
{
    nfs_fh3     file;
    offset3     offset;
    count3      count;
    stable_how  stable;
//    Opaque   data; skiped on filtration
};

struct WRITE3res
{
    struct WRITE3resok
    {
        wcc_data    file_wcc;
        count3      count;
        stable_how  committed;
        writeverf3  verf;
    };

    struct WRITE3resfail
    {
        wcc_data file_wcc;
    };

    nfsstat3 status;
    union U
    {
        WRITE3resok   resok;
        WRITE3resfail resfail;
    } u;
};

// Procedure 8: CREATE - Create a file
// CREATE3res NFSPROC3_CREATE(CREATE3args) = 8;
struct createhow3
{
    enum createmode3
    {
        UNCHECKED = 0,
        GUARDED   = 1,
        EXCLUSIVE = 2
    };

    uint32_t        mode;
    union U
    {
        sattr3      obj_attributes;
        createverf3 verf;
    } u;
};

struct CREATE3args
{
    diropargs3 where;
    createhow3 how;
};

struct CREATE3res
{
    struct CREATE3resok
    {
        post_op_fh3 obj;
        post_op_attr obj_attributes;
        wcc_data dir_wcc;
    };

    struct CREATE3resfail
    {
        wcc_data dir_wcc;
    };

    nfsstat3 status;
    union U
    {
        CREATE3resok   resok;
        CREATE3resfail resfail;
    } u;
};

// Procedure 9: MKDIR - Create a directory
// MKDIR3res NFSPROC3_MKDIR(MKDIR3args) = 9;
struct MKDIR3args
{
    diropargs3 where;
    sattr3     attributes;
};

struct MKDIR3res
{
    struct MKDIR3resok
    {
        post_op_fh3 obj;
        post_op_attr obj_attributes;
        wcc_data dir_wcc;
    };

    struct MKDIR3resfail
    {
        wcc_data dir_wcc;
    };

    nfsstat3 status;
    union U
    {
        MKDIR3resok   resok;
        MKDIR3resfail resfail;
    } u;
};

// Procedure 10: SYMLINK - Create a symbolic link
// SYMLINK3res NFSPROC3_SYMLINK(SYMLINK3args) = 10;
struct symlinkdata3
{
    sattr3   symlink_attributes;
    nfspath3 symlink_data;
};

struct SYMLINK3args
{
    diropargs3   where;
    symlinkdata3 symlink;
};

struct SYMLINK3res
{
    struct SYMLINK3resok
    {
        post_op_fh3 obj;
        post_op_attr obj_attributes;
        wcc_data dir_wcc;
    };

    struct SYMLINK3resfail
    {
        wcc_data dir_wcc;
    };

    nfsstat3 status;
    union U
    {
        SYMLINK3resok   resok;
        SYMLINK3resfail resfail;
    } u;
};

// Procedure 11: MKNOD - Create a special device
// MKNOD3res NFSPROC3_MKNOD(MKNOD3args) = 11;
struct devicedata3
{
    sattr3    dev_attributes;
    specdata3 spec;
};

struct mknoddata3
{
    ftype3          type;
    union U
    {
        devicedata3 device;
        sattr3      pipe_attributes;
    } u;
};

struct MKNOD3args
{
    diropargs3 where;
    mknoddata3 what;
};

struct MKNOD3res
{
    struct MKNOD3resok
    {
        post_op_fh3 obj;
        post_op_attr obj_attributes;
        wcc_data dir_wcc;
    };

    struct MKNOD3resfail
    {
        wcc_data dir_wcc;
    };

    nfsstat3 status;
    union U
    {
        MKNOD3resok   resok;
        MKNOD3resfail resfail;
    } u;
};

// Procedure 12: REMOVE - Remove a File
// REMOVE3res NFSPROC3_REMOVE(REMOVE3args) = 12;
struct REMOVE3args
{
    diropargs3 object;
};

struct REMOVE3res
{
    struct REMOVE3resok
    {
        wcc_data dir_wcc;
    };

    struct REMOVE3resfail
    {
        wcc_data dir_wcc;
    };

    nfsstat3 status;
    union U
    {
        REMOVE3resok   resok;
        REMOVE3resfail resfail;
    } u;
};

// Procedure 13: RMDIR - Remove a Directory
// RMDIR3res NFSPROC3_RMDIR(RMDIR3args) = 13;
struct RMDIR3args
{
    diropargs3 object;
};

struct RMDIR3res
{
    struct RMDIR3resok
    {
        wcc_data dir_wcc;
    };

    struct RMDIR3resfail
    {
        wcc_data dir_wcc;
    };

    nfsstat3 status;
    union U
    {
        RMDIR3resok   resok;
        RMDIR3resfail resfail;
    } u;
};

// Procedure 14: RENAME - Rename a File or Directory
// RENAME3res NFSPROC3_RENAME(RENAME3args) = 14;
struct RENAME3args
{
    diropargs3 from;
    diropargs3 to;
};

struct RENAME3res
{
    struct RENAME3resok
    {
        wcc_data fromdir_wcc;
        wcc_data todir_wcc;
    };

    struct RENAME3resfail
    {
        wcc_data fromdir_wcc;
        wcc_data todir_wcc;
    };

    nfsstat3 status;
    union U
    {
        RENAME3resok   resok;
        RENAME3resfail resfail;
    } u;
};

// Procedure 15: LINK - Create Link to an object
// LINK3res NFSPROC3_LINK(LINK3args) = 15;
struct LINK3args
{
    nfs_fh3    file;
    diropargs3 link;
};

struct LINK3res
{
    struct LINK3resok
    {
        post_op_attr file_attributes;
        wcc_data linkdir_wcc;
    };

    struct LINK3resfail
    {
        post_op_attr file_attributes;
        wcc_data linkdir_wcc;
    };

    nfsstat3 status;
    union U
    {
        LINK3resok   resok;
        LINK3resfail resfail;
    } u;
};

// Procedure 16: READDIR - Read From Directory
// READDIR3res NFSPROC3_READDIR(READDIR3args) = 16;
struct READDIR3args
{
    nfs_fh3     dir;
    cookie3     cookie;
    cookieverf3 cookieverf;
    count3      count;
};

struct READDIR3res
{
    struct entry3
    {
        fileid3 fileid;
        filename3 name;
        cookie3 cookie;
        entry3* nextentry;  //It is not implemented now.
    };

    //
    // dirlist3 is payload
    //
    struct dirlist3
    {
        entry3* entries;    //It is not implemented now.
        uint32_t eof;
    };

    struct READDIR3resok
    {
        post_op_attr dir_attributes;
        cookieverf3 cookieverf;
        dirlist3 reply;
    };

    struct READDIR3resfail
    {
        post_op_attr dir_attributes;
    };

    nfsstat3 status;
    union U
    {
        READDIR3resok   resok;
        READDIR3resfail resfail;
    } u;
};

// Procedure 17: READDIRPLUS - Extended read from directory
// READDIRPLUS3res NFSPROC3_READDIRPLUS(READDIRPLUS3args) = 17;
struct READDIRPLUS3args
{
    nfs_fh3     dir;
    cookie3     cookie;
    cookieverf3 cookieverf;
    count3      dircount;
    count3      maxcount;
};

struct READDIRPLUS3res
{
    struct entryplus3
    {
        fileid3 fileid;
        filename3 name;
        cookie3 cookie;
        post_op_attr name_attributes;
        post_op_fh3 name_handle;
        entryplus3* nextentry;  //It is not implemented now.
    };

    //
    // dirlistplus3 is payload
    //
    struct dirlistplus3
    {
        entryplus3* entries;    //It is not implemented now.
        uint32_t eof;
    };

    struct READDIRPLUS3resok
    {
        post_op_attr dir_attributes;
        cookieverf3 cookieverf;
        dirlistplus3 reply;
    };

    struct READDIRPLUS3resfail
    {
        post_op_attr dir_attributes;
    };

    nfsstat3 status;
    union U
    {
        READDIRPLUS3resok   resok;
        READDIRPLUS3resfail resfail;
    } u;
};

// Procedure 18: FSSTAT - Get dynamic file system information
// FSSTAT3res NFSPROC3_FSSTAT(FSSTAT3args) = 18;
struct FSSTAT3args
{
    nfs_fh3 fsroot;
};

struct FSSTAT3res
{
    struct FSSTAT3resok
    {
        post_op_attr obj_attributes;
        size3 tbytes;
        size3 fbytes;
        size3 abytes;
        size3 tfiles;
        size3 ffiles;
        size3 afiles;
        uint32_t invarsec;
    };

    struct FSSTAT3resfail
    {
        post_op_attr obj_attributes;
    };

    nfsstat3 status;
    union U
    {
        FSSTAT3resok   resok;
        FSSTAT3resfail resfail;
    } u;
};

// Procedure 19: FSINFO - Get static file system Information
// FSINFO3res NFSPROC3_FSINFO(FSINFO3args) = 19;
struct FSINFO3args
{
    nfs_fh3 fsroot;
};

struct FSINFO3res
{
    struct FSINFO3resok
    {
        enum
        {
            FSF3_LINK        = 0x0001,
            FSF3_SYMLINK     = 0x0002,
            FSF3_HOMOGENEOUS = 0x0008,
            FSF3_CANSETTIME  = 0x0010
        };

        post_op_attr obj_attributes;
        uint32_t rtmax;
        uint32_t rtpref;
        uint32_t rtmult;
        uint32_t wtmax;
        uint32_t wtpref;
        uint32_t wtmult;
        uint32_t dtpref;
        size3 maxfilesize;
        nfstime3 time_delta;
        uint32_t properties;
    };

    struct FSINFO3resfail
    {
        post_op_attr obj_attributes;
    };

    nfsstat3 status;
    union U
    {
        FSINFO3resok   resok;
        FSINFO3resfail resfail;
    } u;
};

// Procedure 20: PATHCONF - Retrieve POSIX information
// PATHCONF3res NFSPROC3_PATHCONF(PATHCONF3args) = 20;
struct PATHCONF3args
{
    nfs_fh3 object;
};

struct PATHCONF3res
{
    struct PATHCONF3resok
    {
        post_op_attr obj_attributes;
        uint32_t linkmax;
        uint32_t name_max;
        uint32_t no_trunc;
        uint32_t shown_restricted;
        uint32_t case_insensitive;
        uint32_t case_preserving;
    };

    struct PATHCONF3resfail
    {
        post_op_attr obj_attributes;
    };

    nfsstat3 status;
    union U
    {
        PATHCONF3resok   resok;
        PATHCONF3resfail resfail;
    } u;
};

// Procedure 21: COMMIT - Commit cached data on a server to stable storage
// COMMIT3res NFSPROC3_COMMIT(COMMIT3args) = 21;
struct COMMIT3args
{
    nfs_fh3 file;
    offset3 offset;
    count3  count;
};

struct COMMIT3res
{
    struct COMMIT3resok
    {
        wcc_data file_wcc;
        writeverf3 verf;
    };

    struct COMMIT3resfail
    {
        wcc_data file_wcc;
    };

    nfsstat3 status;
    union U
    {
        COMMIT3resok   resok;
        COMMIT3resfail resfail;
    } u;
};

}
//------------------------------------------------------------------------------
#endif//NFS3_TYPES_H
//------------------------------------------------------------------------------
