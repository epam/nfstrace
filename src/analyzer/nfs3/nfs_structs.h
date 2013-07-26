//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: All RFC1813 declared structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_STRUCTS_H
#define NFS_STRUCTS_H
//------------------------------------------------------------------------------
#include "../../auxiliary/print/indent.h"
#include "../rpc/rpc_structs.h" // OpaqueAuth, RPCMessage, RPCCall, RPCReply
#include "../xdr/xdr_struct.h" // OpaqueDyn, OpaqueStat
#include "../xdr/xdr_reader.h"
#include "nfs_procedures.h" // Proc (enumeration Ops)
//------------------------------------------------------------------------------
using namespace NST::auxiliary::print;
using namespace NST::analyzer::XDR;
using namespace NST::analyzer::RPC;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace NFS3
{

const uint32_t cg_program = 100003;
const uint32_t cg_version = 3;
const uint32_t cg_port    = 2049;
const uint32_t NFS3_FHSIZE  = 64;

const uint32_t NFS3_COOKIEVERFSIZE = 8;
const uint32_t NFS3_CREATEVERFSIZE = 8;
const uint32_t NFS3_WRITEVERFSIZE  = 8;

typedef Opaque      filename3;
typedef Opaque      nfspath3;
typedef uint64_t    fileid3;
typedef uint64_t    cookie3;
typedef Opaque      cookieverf3;
typedef Opaque      createverf3;
typedef Opaque      writeverf3;

typedef uint32_t    uid3;
typedef uint32_t    gid3;
typedef uint32_t    size3;
typedef uint64_t    offset3;
typedef uint32_t    mode3;
typedef uint32_t    count3;


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

    friend XDRReader& operator>>(XDRReader& in, nfsstat3& obj);

    inline Enum_nfsstat3 get_stat() const { return Enum_nfsstat3(stat); }

private:
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

    friend XDRReader& operator>>(XDRReader& in, ftype3& obj);

    inline Enum_ftype3 get_ftype() const { return Enum_ftype3(ftype); }

private:
    uint32_t ftype;
};

struct specdata3
{
    friend XDRReader& operator>>(XDRReader& in, specdata3& obj);

    inline uint32_t get_specdata1() const { return specdata1; }
    inline uint32_t get_specdata2() const { return specdata2; }

private:
    uint32_t specdata1;
    uint32_t specdata2;
};

struct nfs_fh3
{
    friend XDRReader& operator>>(XDRReader& in, nfs_fh3& obj);

    inline const Opaque& get_data() const{ return data; }

private:
    XDR::Opaque data;
};

struct nfstime3
{
    friend XDRReader& operator>>(XDRReader& in, nfstime3& obj);

    inline uint32_t  get_seconds() const { return seconds;  }
    inline uint32_t get_nseconds() const { return nseconds; }

private:
    uint32_t seconds;
    uint32_t nseconds;
};

struct fattr3
{
    friend XDRReader& operator>>(XDRReader& in, fattr3& obj);

    inline const ftype3       get_type() const { return type;   }
    inline const mode3        get_mode() const { return mode;   }
    inline const uint32_t    get_nlink() const { return nlink;  }
    inline const uid3          get_uid() const { return uid;    }
    inline const gid3          get_gid() const { return gid;    }
    inline const size3        get_size() const { return size;   }
    inline const size3        get_used() const { return used;   }
    inline const specdata3&   get_rdev() const { return rdev;   }
    inline const uint64_t     get_fsid() const { return fsid;   }
    inline const fileid3    get_fileid() const { return fileid; }
    inline const nfstime3&   get_atime() const { return atime;  }
    inline const nfstime3&   get_mtime() const { return mtime;  }
    inline const nfstime3&   get_ctime() const { return ctime;  }

private:
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
    friend XDRReader& operator>>(XDRReader& in, post_op_attr& obj);

    inline const uint32_t is_attributes() const { return attributes_follow; }
    inline const fattr3& get_attributes() const { return attributes;        }

private:
    uint32_t attributes_follow;
    fattr3   attributes;
};

struct wcc_attr
{
    friend XDRReader& operator>>(XDRReader& in, wcc_attr& obj);

    inline const size3      get_size() const { return size;  }
    inline const nfstime3& get_mtime() const { return mtime; }
    inline const nfstime3& get_ctime() const { return ctime; }

private:
    size3    size;
    nfstime3 mtime;
    nfstime3 ctime;
};

struct pre_op_attr
{
    friend XDRReader& operator>>(XDRReader& in, pre_op_attr& obj);

    inline const uint32_t   is_attributes() const { return attributes_follow; }
    inline const wcc_attr& get_attributes() const { return attributes;        }

private:
    uint32_t attributes_follow;
    wcc_attr attributes;
};

struct wcc_data
{
    friend XDRReader& operator>>(XDRReader& in, wcc_data& obj);

    inline const pre_op_attr& get_before() const { return before; }
    inline const post_op_attr& get_after() const { return after;  }

private:
    pre_op_attr  before;
    post_op_attr after;
};

struct post_op_fh3
{
    friend XDRReader& operator>>(XDRReader& in, post_op_fh3& obj);

    inline const uint32_t  is_handle() const { return handle_follows; }
    inline const nfs_fh3& get_handle() const { return handle;         }

private:
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

    friend XDRReader& operator>>(XDRReader& in, sattr3& obj);

    inline const bool        is_mode() const { return b_mode; }
    inline const mode3      get_mode() const { return mode;   }

    inline const bool         is_uid() const { return b_uid; }
    inline const uid3        get_uid() const { return uid;   }

    inline const bool         is_gid() const { return b_gid; }
    inline const gid3        get_gid() const { return gid;   }

    inline const bool        is_size() const { return b_size; }
    inline const size3      get_size() const { return size;   }

    inline const time_how   is_atime() const { return time_how(set_it_atime); }
    inline const nfstime3& get_atime() const { return atime;                  }

    inline const time_how   is_mtime() const { return time_how(set_it_mtime); }
    inline const nfstime3& get_mtime() const { return mtime;                  }

private:
    bool b_mode;
    bool b_uid;
    bool b_gid;
    bool b_size;
    uint32_t set_it_atime;
    uint32_t set_it_mtime;
    mode3 mode;
    uid3  uid;
    gid3  gid;
    size3 size;
    nfstime3 atime;
    nfstime3 mtime;
};

struct diropargs3
{
    friend XDRReader& operator>>(XDRReader& in, diropargs3& obj);

    inline const nfs_fh3&   get_dir () const { return dir;  }
    inline const filename3& get_name() const { return name; }

private:
    nfs_fh3   dir;
    filename3 name;
};

// Procedure 0: NULL - Do nothing
// void NFSPROC3_NULL(void) = 0;
class NullArgs : public RPCCall
{
public:
    NullArgs(XDRReader& in) : RPCCall(in)
    {
    }
};

// Procedure 1: GETATTR - Get file attributes
// GETATTR3res NFSPROC3_GETATTR(GETATTR3args) = 1;
class GetAttrArgs : public RPCCall
{
public:
    GetAttrArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file;
    }

    inline const nfs_fh3& get_file() const { return file; }

private:
    nfs_fh3 file;
};

// Procedure 2: SETATTR - Set file attributes
// SETATTR3res NFSPROC3_SETATTR(SETATTR3args) = 2;
struct sattrguard3
{
    friend XDRReader& operator>>(XDRReader& in, sattrguard3& obj);

    inline const bool       is_obj_ctime() const { return check;     }
    inline const nfstime3& get_obj_ctime() const { return obj_ctime; }

private:
    bool     check;
    nfstime3 obj_ctime;
};

class SetAttrArgs : public RPCCall
{
public:
    SetAttrArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object >> new_attributes >> guard;
    }

    inline const nfs_fh3&         get_object() const { return object;         }
    inline const sattr3&  get_new_attributes() const { return new_attributes; }
    inline const sattrguard3&      get_guard() const { return guard;          }

private:
    SetAttrArgs(const SetAttrArgs& obj);
    void operator=(const SetAttrArgs& obj);

    nfs_fh3     object;
    sattr3      new_attributes;
    sattrguard3 guard;
};

// Procedure 3: LOOKUP -  Lookup filename
// LOOKUP3res NFSPROC3_LOOKUP(LOOKUP3args) = 3;
class LookUpArgs : public RPCCall
{
public:
    LookUpArgs(XDRReader& in) : RPCCall(in)
    {
        in >> what;
    }

    inline const diropargs3& get_what() const { return what; }

private:
    diropargs3 what;
};

// Procedure 4: ACCESS - Check Access Permission
// ACCESS3res NFSPROC3_ACCESS(ACCESS3args) = 4;
class AccessArgs : public RPCCall
{
public:
    AccessArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object >> access;
    }

    inline const nfs_fh3& get_object() const { return object; }
    inline const uint32_t get_access() const { return access; }
private:
    nfs_fh3  object;
    uint32_t access;
};

// Procedure 5: READLINK - Read from symbolic link
// READLINK3res NFSPROC3_READLINK(READLINK3args) = 5;
class ReadLinkArgs : public RPCCall
{
public:
    ReadLinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> symlink;
    }

    inline const nfs_fh3& get_symlink() const { return symlink; }

private:
    nfs_fh3 symlink;
};

// Procedure 6: READ - Read From file
// READ3res NFSPROC3_READ(READ3args) = 6;
class ReadArgs : public RPCCall
{
public:
    ReadArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count;
    }

    inline const nfs_fh3&   get_file() const { return file;   }
    inline const offset3  get_offset() const { return offset; }
    inline const count3    get_count() const { return count;  }

private:
    nfs_fh3 file;
    offset3 offset;
    count3  count;
};


// Procedure 7: WRITE - Write to file
// WRITE3res NFSPROC3_WRITE(WRITE3args) = 7;
class WriteArgs : public RPCCall
{
public:
    enum stable_how
    {
        UNSTABLE    = 0,
        DATA_SYNC   = 1,
        FYLE_SYNC   = 2
    };

    WriteArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count >> stable;
    }

    inline const nfs_fh3&     get_file() const { return file; }
    inline const offset3    get_offset() const { return offset; }
    inline const count3      get_count() const { return count; }
    inline const stable_how get_stable() const { return stable_how(stable); }

private:
    nfs_fh3  file;
    offset3  offset;
    count3   count;
    uint32_t stable;
    //Opaque   data; the payload data of this operation. REMOVED
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
    friend XDRReader& operator>>(XDRReader& in, createhow3& obj);

    inline const createverf3&      get_verf() const { return u.verf;           }
    inline const sattr3& get_obj_attributes() const { return u.obj_attributes; }
    inline const createmode3       get_mode() const { return createmode3(mode);}

private:
    uint32_t        mode;
    union U
    {
        sattr3      obj_attributes;
        createverf3 verf;
    } u;
};

class CreateArgs : public RPCCall
{
public:
    CreateArgs(XDRReader& in) : RPCCall(in)
    {
        in >> where >> how;
    }

    inline const diropargs3&  get_where() const { return where; }
    inline const createhow3&    get_how() const { return how;   }

private:
    diropargs3 where;
    createhow3 how;
};

// Procedure 9: MKDIR - Create a directory
// MKDIR3res NFSPROC3_MKDIR(MKDIR3args) = 9;
class MkDirArgs : public RPCCall
{
public:
    MkDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> where >> attributes;
    }

    inline const diropargs3&   get_where() const { return where;      }
    inline const sattr3&  get_attributes() const { return attributes; }

private:
    diropargs3 where;
    sattr3     attributes;
};

// Procedure 10: SYMLINK - Create a symbolic link
// SYMLINK3res NFSPROC3_SYMLINK(SYMLINK3args) = 10;
struct symlinkdata3
{
    friend XDRReader& operator>>(XDRReader& in, symlinkdata3& obj);

    inline const sattr3& get_symlink_attributes() const { return symlink_attributes; }
    inline const nfspath3&     get_symlink_data() const { return symlink_data;       }

private:
    sattr3   symlink_attributes;
    nfspath3 symlink_data;
};

class SymLinkArgs : public RPCCall
{
public:
    SymLinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> where >> symlink;
    }

    inline const diropargs3&     get_where() const { return where;   }
    inline const symlinkdata3& get_symlink() const { return symlink; }

private:
    diropargs3   where;
    symlinkdata3 symlink;
};

// Procedure 11: MKNOD - Create a special device
// MKNOD3res NFSPROC3_MKNOD(MKNOD3args) = 11;
struct devicedata3
{
    friend XDRReader& operator>>(XDRReader& in, devicedata3& obj);

    inline const sattr3&   get_dev_attributes() const { return dev_attributes; }
    inline const specdata3&          get_spec() const { return spec;           }

private:
    sattr3    dev_attributes;
    specdata3 spec;
};

struct mknoddata3
{
    friend XDRReader& operator>>(XDRReader& in, mknoddata3& pipe);

    inline const ftype3::Enum_ftype3 get_type() const { return type.get_ftype();  }
    inline const sattr3&  get_pipe_attributes() const { return u.pipe_attributes; }
    inline const devicedata3&      get_device() const { return u.device;          }

private:
    ftype3          type;
    union U
    {
        devicedata3 device;
        sattr3      pipe_attributes;
    } u;
};

class MkNodArgs : public RPCCall
{
public:
    MkNodArgs(XDRReader& in) : RPCCall(in)
    {
        in >> where >> what;
    }

    inline const diropargs3& get_where() const { return where; }
    inline const mknoddata3&  get_what() const { return what; }

private:
    diropargs3 where;
    mknoddata3 what;
};

// Procedure 12: REMOVE - Remove a File
// REMOVE3res NFSPROC3_REMOVE(REMOVE3args) = 12;
class RemoveArgs : public RPCCall
{
public:
    RemoveArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object;
    }

    inline const diropargs3& get_object() const { return object; }

private:
    diropargs3 object;
};

// Procedure 13: RMDIR - Remove a Directory
// RMDIR3res NFSPROC3_RMDIR(RMDIR3args) = 13;
class RmDirArgs : public RPCCall
{
public:
    RmDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object;
    }

    inline const diropargs3& get_object() const { return object; }

private:
    diropargs3 object;
};

// Procedure 14: RENAME - Rename a File or Directory
// RENAME3res NFSPROC3_RENAME(RENAME3args) = 14;
class RenameArgs : public RPCCall
{
public:
    RenameArgs(XDRReader& in) : RPCCall(in)
    {
        in >> from >> to;
    }

    inline const diropargs3& get_from() const { return from; }
    inline const diropargs3&   get_to() const { return to;   }

private:
    diropargs3 from;
    diropargs3 to;
};

// Procedure 15: LINK - Create Link to an object
// LINK3res NFSPROC3_LINK(LINK3args) = 15;
class LinkArgs : public RPCCall
{
public:
    LinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> link;
    }

    inline const nfs_fh3&    get_file() const { return file; }
    inline const diropargs3& get_link() const { return link; }

private:
    nfs_fh3    file;
    diropargs3 link;
};

// Procedure 16: READDIR - Read From Directory
// READDIR3res NFSPROC3_READDIR(READDIR3args) = 16;
class ReadDirArgs : public RPCCall
{
public:
    ReadDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> cookie;
        in.read_fixed_len(cookieverf, NFS3_COOKIEVERFSIZE);
        in >> count;
    }

    inline const nfs_fh3&            get_dir() const { return dir;        }
    inline const cookie3          get_cookie() const { return cookie;     }
    inline const cookieverf3& get_cookieverf() const { return cookieverf; }
    inline const count3            get_count() const { return count;      }

private:
    nfs_fh3     dir;
    cookie3     cookie;
    cookieverf3 cookieverf;
    count3      count;
};

// Procedure 17: READDIRPLUS - Extended read from directory
// READDIRPLUS3res NFSPROC3_READDIRPLUS(READDIRPLUS3args) = 17;
class ReadDirPlusArgs : public RPCCall
{
public:
    ReadDirPlusArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> cookie;
        in.read_fixed_len(cookieverf, NFS3_COOKIEVERFSIZE);
        in >> dircount >> maxcount;
    }

    inline const nfs_fh3&            get_dir() const { return dir;        }
    inline const cookie3          get_cookie() const { return cookie;     }
    inline const cookieverf3& get_cookieverf() const { return cookieverf; }
    inline const count3         get_dircount() const { return dircount;   }
    inline const count3         get_maxcount() const { return maxcount;   }

private:
    nfs_fh3     dir;
    cookie3     cookie;
    cookieverf3 cookieverf;
    count3      dircount;
    count3      maxcount;
};

// Procedure 18: FSSTAT - Get dynamic file system information
// FSSTAT3res NFSPROC3_FSSTAT(FSSTAT3args) = 18;
class FSStatArgs : public RPCCall
{
public:
    FSStatArgs(XDRReader& in) : RPCCall(in)
    {
        in >> fsroot;
    }

    inline const nfs_fh3& get_fsroot() const { return fsroot; }

private:
    nfs_fh3 fsroot;
};

// Procedure 19: FSINFO - Get static file system Information
// FSINFO3res NFSPROC3_FSINFO(FSINFO3args) = 19;
class FSInfoArgs : public RPCCall
{
public:
    FSInfoArgs(XDRReader& in) : RPCCall(in)
    {
        in >> fsroot;
    }

    inline const nfs_fh3& get_fsroot() const { return fsroot; }

private:
    nfs_fh3 fsroot;
};

// Procedure 20: PATHCONF - Retrieve POSIX information
// PATHCONF3res NFSPROC3_PATHCONF(PATHCONF3args) = 20;
class PathConfArgs : public RPCCall
{
public:
    PathConfArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object;
    }

    inline const nfs_fh3& get_object() const { return object; }

private:
    nfs_fh3 object;
};

// Procedure 21: COMMIT - Commit cached data on a server to stable storage
// COMMIT3res NFSPROC3_COMMIT(COMMIT3args) = 21;
class CommitArgs : public RPCCall
{
public:
    CommitArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count;
    }

    inline const nfs_fh3&   get_file() const { return file;   }
    inline const uint64_t get_offset() const { return offset; }
    inline const uint32_t  get_count() const { return count;  }

private:
    nfs_fh3 file;
    offset3 offset;
    count3  count;
};

std::ostream& operator<<(std::ostream& out, const Enum_mode3 obj);
std::ostream& operator<<(std::ostream& out, const nfsstat3& obj);
std::ostream& operator<<(std::ostream& out, const ftype3& obj);
std::ostream& operator<<(std::ostream& out, const specdata3& obj);
std::ostream& operator<<(std::ostream& out, const nfs_fh3& obj);
std::ostream& operator<<(std::ostream& out, const nfstime3& obj);
std::ostream& operator<<(std::ostream& out, const fattr3& obj);
std::ostream& operator<<(std::ostream& out, const post_op_attr& obj);
std::ostream& operator<<(std::ostream& out, const wcc_attr& obj);
std::ostream& operator<<(std::ostream& out, const pre_op_attr& obj);
std::ostream& operator<<(std::ostream& out, const wcc_data& obj);
std::ostream& operator<<(std::ostream& out, const post_op_fh3& obj);
std::ostream& operator<<(std::ostream& out, const sattr3& obj);
std::ostream& operator<<(std::ostream& out, const diropargs3& obj);

std::ostream& operator<<(std::ostream& out, const sattrguard3& obj);
std::ostream& operator<<(std::ostream& out, const SetAttrArgs& obj);

std::ostream& operator<<(std::ostream& out, const WriteArgs& obj);

std::ostream& operator<<(std::ostream& out, const createhow3& obj);
std::ostream& operator<<(std::ostream& out, const CreateArgs& obj);

std::ostream& operator<<(std::ostream& out, const MkDirArgs& obj);

std::ostream& operator<<(std::ostream& out, const symlinkdata3& obj);
std::ostream& operator<<(std::ostream& out, const SymLinkArgs& obj);

std::ostream& operator<<(std::ostream& out, const devicedata3& obj);
std::ostream& operator<<(std::ostream& out, const mknoddata3& obj);
std::ostream& operator<<(std::ostream& out, const MkNodArgs& obj);


} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_STRUCTS_H
//------------------------------------------------------------------------------
