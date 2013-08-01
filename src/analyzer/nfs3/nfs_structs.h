//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: All RFC1813 declared structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_STRUCTS_H
#define NFS_STRUCTS_H
//------------------------------------------------------------------------------
#include "../xdr/xdr_reader.h"
#include "../../auxiliary/logger.h"
//------------------------------------------------------------------------------
using namespace NST::analyzer::XDR;
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
typedef uint64_t    size3;
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

    inline const bool operator==(const Enum_nfsstat3 e) const { return get_stat() == e; }
    inline Enum_nfsstat3 get_stat() const { return Enum_nfsstat3(stat); }

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

    uint32_t ftype;
};

struct specdata3
{
    friend XDRReader& operator>>(XDRReader& in, specdata3& obj);

    inline uint32_t get_specdata1() const { return specdata1; }
    inline uint32_t get_specdata2() const { return specdata2; }

    uint32_t specdata1;
    uint32_t specdata2;
};

struct nfs_fh3
{
    friend XDRReader& operator>>(XDRReader& in, nfs_fh3& obj);

    inline const Opaque& get_data() const{ return data; }

    XDR::Opaque data;
};

struct nfstime3
{
    friend XDRReader& operator>>(XDRReader& in, nfstime3& obj);

    inline uint32_t  get_seconds() const { return seconds;  }
    inline uint32_t get_nseconds() const { return nseconds; }

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

    uint32_t attributes_follow;
    fattr3   attributes;
};

struct wcc_attr
{
    friend XDRReader& operator>>(XDRReader& in, wcc_attr& obj);

    inline const size3      get_size() const { return size;  }
    inline const nfstime3& get_mtime() const { return mtime; }
    inline const nfstime3& get_ctime() const { return ctime; }

    size3    size;
    nfstime3 mtime;
    nfstime3 ctime;
};

struct pre_op_attr
{
    friend XDRReader& operator>>(XDRReader& in, pre_op_attr& obj);

    inline const uint32_t   is_attributes() const { return attributes_follow; }
    inline const wcc_attr& get_attributes() const { return attributes;        }

    uint32_t attributes_follow;
    wcc_attr attributes;
};

struct wcc_data
{
    friend XDRReader& operator>>(XDRReader& in, wcc_data& obj);

    inline const pre_op_attr& get_before() const { return before; }
    inline const post_op_attr& get_after() const { return after;  }

    pre_op_attr  before;
    post_op_attr after;
};

struct post_op_fh3
{
    friend XDRReader& operator>>(XDRReader& in, post_op_fh3& obj);

    inline const uint32_t  is_handle() const { return handle_follows; }
    inline const nfs_fh3& get_handle() const { return handle;         }

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

    nfs_fh3   dir;
    filename3 name;
};

// Procedure 0: NULL - Do nothing
// void NFSPROC3_NULL(void) = 0;
struct NULLargs
{
    inline friend XDRReader& operator>>(XDRReader& in, NULLargs& o)
    {
        return in;
    }
};

struct NULLres
{
    inline friend XDRReader& operator>>(XDRReader& in, NULLres& o)
    {
        return in;
    }
};

// Procedure 1: GETATTR - Get file attributes
// GETATTR3res NFSPROC3_GETATTR(GETATTR3args) = 1;
struct GETATTR3args
{
    inline friend XDRReader& operator>>(XDRReader& in, GETATTR3args& o)
    {
        return in >> o.file;
    }

    inline const nfs_fh3& get_file() const { return file; }

    nfs_fh3 file;
};

struct GETATTR3res
{
    friend XDRReader& operator>>(XDRReader& in, GETATTR3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj_attributes;
        }
        return in;
    }

    struct GETATTR3resok
    {
        fattr3 obj_attributes;
    };

    nfsstat3 status;
    GETATTR3resok resok;
};

// Procedure 2: SETATTR - Set file attributes
// SETATTR3res NFSPROC3_SETATTR(SETATTR3args) = 2;
struct sattrguard3
{
    friend XDRReader& operator>>(XDRReader& in, sattrguard3& obj);

    inline const bool       is_obj_ctime() const { return check;     }
    inline const nfstime3& get_obj_ctime() const { return obj_ctime; }

    bool     check;
    nfstime3 obj_ctime;
};

struct SETATTR3args
{
    friend XDRReader& operator>>(XDRReader& in, SETATTR3args& o)
    {
        return in >> o.object >> o.new_attributes >> o.guard;
    }

    inline const nfs_fh3&         get_object() const { return object;         }
    inline const sattr3&  get_new_attributes() const { return new_attributes; }
    inline const sattrguard3&      get_guard() const { return guard;          }

    nfs_fh3     object;
    sattr3      new_attributes;
    sattrguard3 guard;
};

struct SETATTR3res
{
    friend XDRReader& operator>>(XDRReader& in, SETATTR3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj_wcc;
        }
        else
        {
            in >> o.resfail.obj_wcc;
        }
        return in;
    }

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
    friend XDRReader& operator>>(XDRReader& in, LOOKUP3args& o)
    {
        return in >> o.what;
    }

    inline const diropargs3& get_what() const { return what; }

    diropargs3 what;
};

struct LOOKUP3res
{
    friend XDRReader& operator>>(XDRReader& in, LOOKUP3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.object;
            in >> o.resok.obj_attributes;
            in >> o.resok.dir_attributes;
        }
        else
        {
            in >> o.resfail.dir_attributes;
        }
        return in;
    }

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

const uint32_t ACCESS3_READ    = 0x001;
const uint32_t ACCESS3_LOOKUP  = 0x002;
const uint32_t ACCESS3_MODIFY  = 0x004;
const uint32_t ACCESS3_EXTEND  = 0x008;
const uint32_t ACCESS3_DELETE  = 0x010;
const uint32_t ACCESS3_EXECUTE = 0x020;

struct ACCESS3args
{

    friend XDRReader& operator>>(XDRReader& in, ACCESS3args& o)
    {
        return in >> o.object >> o.access;
    }

    inline const nfs_fh3& get_object() const { return object; }
    inline const uint32_t get_access() const { return access; }

    nfs_fh3  object;
    uint32_t access;
};
struct ACCESS3res
{
    friend XDRReader& operator>>(XDRReader& in, ACCESS3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj_attributes;
            in >> o.resok.access;
        }
        else
        {
            in >> o.resfail.obj_attributes;
        }
        return in;
    }

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
    union
    {
        ACCESS3resok   resok;
        ACCESS3resfail resfail;
    };
};

// Procedure 5: READLINK - Read from symbolic link
// READLINK3res NFSPROC3_READLINK(READLINK3args) = 5;
struct READLINK3args
{
    friend XDRReader& operator>>(XDRReader& in, READLINK3args& o)
    {
        return in >> o.symlink;
    }

    inline const nfs_fh3& get_symlink() const { return symlink; }

    nfs_fh3 symlink;
};

struct READLINK3res
{
    friend XDRReader& operator>>(XDRReader& in, READLINK3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.symlink_attributes;
            in.read_variable_len(o.resok.data);
        }
        else
        {
            in >> o.resfail.symlink_attributes;
        }
        return in;
    }

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
    union
    {
        READLINK3resok   resok;
        READLINK3resfail resfail;
    };
};

// Procedure 6: READ - Read From file
// READ3res NFSPROC3_READ(READ3args) = 6;
struct READ3args
{
    friend XDRReader& operator>>(XDRReader& in, READ3args& o)
    {
        return in >> o.file >> o.offset >> o.count;
    }

    inline const nfs_fh3&   get_file() const { return file;   }
    inline const offset3  get_offset() const { return offset; }
    inline const count3    get_count() const { return count;  }

    nfs_fh3 file;
    offset3 offset;
    count3  count;
};

struct READ3res
{
    friend XDRReader& operator>>(XDRReader& in, READ3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.file_attributes;
            in >> o.resok.count;
            in >> o.resok.eof;
            //in.read_variable_len(o.resok.data);
        }
        else
        {
            in >> o.resfail.file_attributes;
        }
        return in;
    }

    struct READ3resok
    {
        post_op_attr file_attributes;
        count3 count;
        uint32_t eof; // bool
        Opaque data;
    };

    struct READ3resfail
    {
        post_op_attr file_attributes;
    };

    nfsstat3 status;
    union
    {
        READ3resok   resok;
        READ3resfail resfail;
    };
};

// Procedure 7: WRITE - Write to file
// WRITE3res NFSPROC3_WRITE(WRITE3args) = 7;
struct WRITE3args
{
    enum stable_how
    {
        UNSTABLE    = 0,
        DATA_SYNC   = 1,
        FYLE_SYNC   = 2
    };

    friend XDRReader& operator>>(XDRReader& in, WRITE3args& o)
    {
        return in >> o.file >> o.offset >> o.count >> o.stable;
    }

    inline const nfs_fh3&     get_file() const { return file; }
    inline const offset3    get_offset() const { return offset; }
    inline const count3      get_count() const { return count; }
    inline const stable_how get_stable() const { return stable_how(stable); }

    nfs_fh3  file;
    offset3  offset;
    count3   count;
    uint32_t stable;
    Opaque   data;
};

struct WRITE3res
{
    enum stable_how
    {
        UNSTABLE    = 0,
        DATA_SYNC   = 1,
        FYLE_SYNC   = 2
    };

    friend XDRReader& operator>>(XDRReader& in, WRITE3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.file_wcc;
            in >> o.resok.count;
            in >> o.resok.committed;
            in.read_fixed_len(o.resok.verf, NFS3_WRITEVERFSIZE);
        }
        else
        {
            in >> o.resfail.file_wcc;
        }
        return in;
    }

    struct WRITE3resok
    {
        wcc_data file_wcc;
        count3 count;
        uint32_t committed; // stable_how
        writeverf3 verf;
    };

    struct WRITE3resfail
    {
        wcc_data file_wcc;
    };

    nfsstat3 status;
    union
    {
        WRITE3resok   resok;
        WRITE3resfail resfail;
    };
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

    uint32_t        mode;
    union U
    {
        sattr3      obj_attributes;
        createverf3 verf;
    } u;
};

struct CREATE3args
{
    friend XDRReader& operator>>(XDRReader& in, CREATE3args& o)
    {
        return in >> o.where >> o.how;
    }

    inline const diropargs3&  get_where() const { return where; }
    inline const createhow3&    get_how() const { return how;   }

    diropargs3 where;
    createhow3 how;
};

struct CREATE3res
{
    friend XDRReader& operator>>(XDRReader& in, CREATE3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj;
            in >> o.resok.obj_attributes;
            in >> o.resok.dir_wcc;
        }
        else
        {
            in >> o.resfail.dir_wcc;
        }
        return in;
    }

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
    union
    {
        CREATE3resok   resok;
        CREATE3resfail resfail;
    };
};

// Procedure 9: MKDIR - Create a directory
// MKDIR3res NFSPROC3_MKDIR(MKDIR3args) = 9;
struct MKDIR3args
{
    friend XDRReader& operator>>(XDRReader& in, MKDIR3args& o)
    {
        return in >> o.where >> o.attributes;
    }

    inline const diropargs3&   get_where() const { return where;      }
    inline const sattr3&  get_attributes() const { return attributes; }

    diropargs3 where;
    sattr3     attributes;
};

struct MKDIR3res
{
    friend XDRReader& operator>>(XDRReader& in, MKDIR3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj;
            in >> o.resok.obj_attributes;
            in >> o.resok.dir_wcc;
        }
        else
        {
            in >> o.resfail.dir_wcc;
        }
        return in;
    }

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
    union
    {
        MKDIR3resok   resok;
        MKDIR3resfail resfail;
    };
};

// Procedure 10: SYMLINK - Create a symbolic link
// SYMLINK3res NFSPROC3_SYMLINK(SYMLINK3args) = 10;
struct symlinkdata3
{
    friend XDRReader& operator>>(XDRReader& in, symlinkdata3& obj);

    inline const sattr3& get_symlink_attributes() const { return symlink_attributes; }
    inline const nfspath3&     get_symlink_data() const { return symlink_data;       }

    sattr3   symlink_attributes;
    nfspath3 symlink_data;
};

struct SYMLINK3args
{
    friend XDRReader& operator>>(XDRReader& in, SYMLINK3args& o)
    {
        return in >> o.where >> o.symlink;
    }

    inline const diropargs3&     get_where() const { return where;   }
    inline const symlinkdata3& get_symlink() const { return symlink; }

    diropargs3   where;
    symlinkdata3 symlink;
};

struct SYMLINK3res
{
    friend XDRReader& operator>>(XDRReader& in, SYMLINK3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj;
            in >> o.resok.obj_attributes;
            in >> o.resok.dir_wcc;
        }
        else
        {
            in >> o.resfail.dir_wcc;
        }
        return in;
    }

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
    union
    {
        SYMLINK3resok   resok;
        SYMLINK3resfail resfail;
    };
};

// Procedure 11: MKNOD - Create a special device
// MKNOD3res NFSPROC3_MKNOD(MKNOD3args) = 11;
struct devicedata3
{
    friend XDRReader& operator>>(XDRReader& in, devicedata3& obj);

    inline const sattr3&   get_dev_attributes() const { return dev_attributes; }
    inline const specdata3&          get_spec() const { return spec;           }

    sattr3    dev_attributes;
    specdata3 spec;
};

struct mknoddata3
{
    friend XDRReader& operator>>(XDRReader& in, mknoddata3& pipe);

    inline const ftype3::Enum_ftype3 get_type() const { return type.get_ftype();  }
    inline const sattr3&  get_pipe_attributes() const { return u.pipe_attributes; }
    inline const devicedata3&      get_device() const { return u.device;          }

    ftype3          type;
    union U
    {
        devicedata3 device;
        sattr3      pipe_attributes;
    } u;
};

struct MKNOD3args
{
    friend XDRReader& operator>>(XDRReader& in, MKNOD3args& o)
    {
        return in >> o.where >> o.what;
    }

    inline const diropargs3& get_where() const { return where; }
    inline const mknoddata3&  get_what() const { return what;  }

    diropargs3 where;
    mknoddata3 what;
};

struct MKNOD3res
{
    friend XDRReader& operator>>(XDRReader& in, MKNOD3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj;
            in >> o.resok.obj_attributes;
            in >> o.resok.dir_wcc;
        }
        else
        {
            in >> o.resfail.dir_wcc;
        }
        return in;
    }

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
    union
    {
        MKNOD3resok   resok;
        MKNOD3resfail resfail;
    };
};

// Procedure 12: REMOVE - Remove a File
// REMOVE3res NFSPROC3_REMOVE(REMOVE3args) = 12;
struct REMOVE3args
{
    friend XDRReader& operator>>(XDRReader& in, REMOVE3args& o)
    {
        return in >> o.object;
    }

    inline const diropargs3& get_object() const { return object; }

    diropargs3 object;
};

struct REMOVE3res
{
    friend XDRReader& operator>>(XDRReader& in, REMOVE3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.dir_wcc;
        }
        else
        {
            in >> o.resfail.dir_wcc;
        }
        return in;
    }

    struct REMOVE3resok
    {
        wcc_data dir_wcc;
    };

    struct REMOVE3resfail
    {
        wcc_data dir_wcc;
    };

    nfsstat3 status;
    union
    {
        REMOVE3resok   resok;
        REMOVE3resfail resfail;
    };
};

// Procedure 13: RMDIR - Remove a Directory
// RMDIR3res NFSPROC3_RMDIR(RMDIR3args) = 13;
struct RMDIR3args
{
    friend XDRReader& operator>>(XDRReader& in, RMDIR3args& o)
    {
        return in >> o.object;
    }

    inline const diropargs3& get_object() const { return object; }

    diropargs3 object;
};

struct RMDIR3res
{
    friend XDRReader& operator>>(XDRReader& in, RMDIR3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.dir_wcc;
        }
        else
        {
            in >> o.resfail.dir_wcc;
        }
        return in;
    }

    struct RMDIR3resok
    {
        wcc_data dir_wcc;
    };

    struct RMDIR3resfail
    {
        wcc_data dir_wcc;
    };

    nfsstat3 status;
    union
    {
        RMDIR3resok   resok;
        RMDIR3resfail resfail;
    };
};

// Procedure 14: RENAME - Rename a File or Directory
// RENAME3res NFSPROC3_RENAME(RENAME3args) = 14;
struct RENAME3args
{
    friend XDRReader& operator>>(XDRReader& in, RENAME3args& o)
    {
        return in >> o.from >> o.to;
    }

    inline const diropargs3& get_from() const { return from; }
    inline const diropargs3&   get_to() const { return to;   }

    diropargs3 from;
    diropargs3 to;
};

struct RENAME3res
{
    friend XDRReader& operator>>(XDRReader& in, RENAME3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.fromdir_wcc;
            in >> o.resok.todir_wcc;
        }
        else
        {
            in >> o.resfail.fromdir_wcc;
            in >> o.resfail.todir_wcc;
        }
        return in;
    }

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
    union
    {
        RENAME3resok   resok;
        RENAME3resfail resfail;
    };
};

// Procedure 15: LINK - Create Link to an object
// LINK3res NFSPROC3_LINK(LINK3args) = 15;
struct LINK3args
{
    friend XDRReader& operator>>(XDRReader& in, LINK3args& o)
    {
        return in >> o.file >> o.link;
    }

    inline const nfs_fh3&    get_file() const { return file; }
    inline const diropargs3& get_link() const { return link; }

    nfs_fh3    file;
    diropargs3 link;
};

struct LINK3res
{
    friend XDRReader& operator>>(XDRReader& in, LINK3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.file_attributes;
            in >> o.resok.linkdir_wcc;
        }
        else
        {
            in >> o.resfail.file_attributes;
            in >> o.resfail.linkdir_wcc;
        }
        return in;
    }

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
    union
    {
        LINK3resok   resok;
        LINK3resfail resfail;
    };
};

// Procedure 16: READDIR - Read From Directory
// READDIR3res NFSPROC3_READDIR(READDIR3args) = 16;
struct READDIR3args
{
    friend XDRReader& operator>>(XDRReader& in, READDIR3args& o)
    {
        in >> o.dir >> o.cookie;
        in.read_fixed_len(o.cookieverf, NFS3_COOKIEVERFSIZE);
        return in >> o.count;
    }

    inline const nfs_fh3&            get_dir() const { return dir;        }
    inline const cookie3          get_cookie() const { return cookie;     }
    inline const cookieverf3& get_cookieverf() const { return cookieverf; }
    inline const count3            get_count() const { return count;      }

    nfs_fh3     dir;
    cookie3     cookie;
    cookieverf3 cookieverf;
    count3      count;
};

struct READDIR3res
{
    friend XDRReader& operator>>(XDRReader& in, READDIR3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.dir_attributes;
            in.read_fixed_len(o.resok.cookieverf, NFS3_COOKIEVERFSIZE);
            o.resok.reply.entries = NULL;
            o.resok.reply.eof = true;
        }
        else
        {
            in >> o.resfail.dir_attributes;
        }
        return in;
    }

    struct entry3
    {
        fileid3 fileid;
        filename3 name;
        cookie3 cookie;
        entry3* nextentry;  //It is not implemented now.
    };

    /*
     * dirlist3 is payload
     */
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
    union
    {
        READDIR3resok   resok;
        READDIR3resfail resfail;
    };
};

// Procedure 17: READDIRPLUS - Extended read from directory
// READDIRPLUS3res NFSPROC3_READDIRPLUS(READDIRPLUS3args) = 17;
struct READDIRPLUS3args
{
    friend XDRReader& operator>>(XDRReader& in, READDIRPLUS3args& o)
    {
        in >> o.dir >> o.cookie;
        in.read_fixed_len(o.cookieverf, NFS3_COOKIEVERFSIZE);
        return in >> o.dircount >> o.maxcount;
    }

    inline const nfs_fh3&            get_dir() const { return dir;        }
    inline const cookie3          get_cookie() const { return cookie;     }
    inline const cookieverf3& get_cookieverf() const { return cookieverf; }
    inline const count3         get_dircount() const { return dircount;   }
    inline const count3         get_maxcount() const { return maxcount;   }

    nfs_fh3     dir;
    cookie3     cookie;
    cookieverf3 cookieverf;
    count3      dircount;
    count3      maxcount;
};

struct READDIRPLUS3res
{
    friend XDRReader& operator>>(XDRReader& in, READDIRPLUS3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.dir_attributes;
            in.read_fixed_len(o.resok.cookieverf, NFS3_COOKIEVERFSIZE);
            o.resok.reply.entries = NULL;
            o.resok.reply.eof = true;
        }
        else
        {
            in >> o.resfail.dir_attributes;
        }
        return in;
    }

    struct entryplus3
    {
        fileid3 fileid;
        filename3 name;
        cookie3 cookie;
        post_op_attr name_attributes;
        post_op_fh3 name_handle;
        entryplus3* nextentry;  //It is not implemented now.
    };

    /*
     * dirlistplus3 is payload
     */
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
    union
    {
        READDIRPLUS3resok   resok;
        READDIRPLUS3resfail resfail;
    };
};

// Procedure 18: FSSTAT - Get dynamic file system information
// FSSTAT3res NFSPROC3_FSSTAT(FSSTAT3args) = 18;
struct FSSTAT3args
{
    friend XDRReader& operator>>(XDRReader& in, FSSTAT3args& o)
    {
        return in >> o.fsroot;
    }

    inline const nfs_fh3& get_fsroot() const { return fsroot; }

    nfs_fh3 fsroot;
};

struct FSSTAT3res
{
    friend XDRReader& operator>>(XDRReader& in, FSSTAT3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj_attributes;
            in >> o.resok.tbytes;
            in >> o.resok.fbytes;
            in >> o.resok.abytes;
            in >> o.resok.tfiles;
            in >> o.resok.ffiles;
            in >> o.resok.afiles;
            in >> o.resok.invarsec;
        }
        else
        {
            in >> o.resfail.obj_attributes;
        }
        return in;
    }

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
    union
    {
        FSSTAT3resok   resok;
        FSSTAT3resfail resfail;
    };
};

// Procedure 19: FSINFO - Get static file system Information
// FSINFO3res NFSPROC3_FSINFO(FSINFO3args) = 19;
const uint32_t FSF3_LINK        = 0x0001;
const uint32_t FSF3_SYMLINK     = 0x0002;
const uint32_t FSF3_HOMOGENEOUS = 0x0008;
const uint32_t FSF3_CANSETTIME  = 0x0010;

struct FSINFO3args
{
    friend XDRReader& operator>>(XDRReader& in, FSINFO3args& o)
    {
        return in >> o.fsroot;
    }

    inline const nfs_fh3& get_fsroot() const { return fsroot; }

    nfs_fh3 fsroot;
};

struct FSINFO3res
{
    friend XDRReader& operator>>(XDRReader& in, FSINFO3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj_attributes;
            in >> o.resok.rtmax;
            in >> o.resok.rtpref;
            in >> o.resok.rtmult;
            in >> o.resok.wtmax;
            in >> o.resok.wtpref;
            in >> o.resok.wtmult;
            in >> o.resok.dtpref;
            in >> o.resok.maxfilesize;
            in >> o.resok.time_delta;
            in >> o.resok.properties;
        }
        else
        {
            in >> o.resfail.obj_attributes;
        }
        return in;
    }

    struct FSINFO3resok
    {
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
    union
    {
        FSINFO3resok   resok;
        FSINFO3resfail resfail;
    };
};

// Procedure 20: PATHCONF - Retrieve POSIX information
// PATHCONF3res NFSPROC3_PATHCONF(PATHCONF3args) = 20;
struct PATHCONF3args
{
    friend XDRReader& operator>>(XDRReader& in, PATHCONF3args& o)
    {
        return in >> o.object;
    }

    inline const nfs_fh3& get_object() const { return object; }

    nfs_fh3 object;
};

struct PATHCONF3res
{
    friend XDRReader& operator>>(XDRReader& in, PATHCONF3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.obj_attributes;
            in >> o.resok.linkmax;
            in >> o.resok.name_max;
            in >> o.resok.no_trunc;
            in >> o.resok.shown_restricted;
            in >> o.resok.case_insensitive;
            in >> o.resok.case_preserving;
        }
        else
        {
            in >> o.resfail.obj_attributes;
        }
        return in;
    }

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
    union
    {
        PATHCONF3resok   resok;
        PATHCONF3resfail resfail;
    };
};

// Procedure 21: COMMIT - Commit cached data on a server to stable storage
// COMMIT3res NFSPROC3_COMMIT(COMMIT3args) = 21;
struct COMMIT3args
{
    friend XDRReader& operator>>(XDRReader& in, COMMIT3args& o)
    {
        return in >> o.file >> o.offset >> o.count;
    }

    inline const nfs_fh3&   get_file() const { return file;   }
    inline const uint64_t get_offset() const { return offset; }
    inline const uint32_t  get_count() const { return count;  }

    nfs_fh3 file;
    offset3 offset;
    count3  count;
};

struct COMMIT3res
{
    friend XDRReader& operator>>(XDRReader& in, COMMIT3res& o)
    {
        in >> o.status;
        if(o.status == nfsstat3::OK)
        {
            in >> o.resok.file_wcc;
            in.read_fixed_len(o.resok.verf, NFS3_WRITEVERFSIZE);
        }
        else
        {
            in >> o.resfail.file_wcc;
        }
        return in;
    }

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
    union
    {
        COMMIT3resok   resok;
        COMMIT3resfail resfail;
    };
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
std::ostream& operator<<(std::ostream& out, const SETATTR3args& obj);

std::ostream& operator<<(std::ostream& out, const WRITE3args& obj);

std::ostream& operator<<(std::ostream& out, const createhow3& obj);
std::ostream& operator<<(std::ostream& out, const CREATE3args& obj);

std::ostream& operator<<(std::ostream& out, const MKDIR3args& obj);

std::ostream& operator<<(std::ostream& out, const symlinkdata3& obj);
std::ostream& operator<<(std::ostream& out, const SYMLINK3args& obj);

std::ostream& operator<<(std::ostream& out, const devicedata3& obj);
std::ostream& operator<<(std::ostream& out, const mknoddata3& obj);
std::ostream& operator<<(std::ostream& out, const MKNOD3args& obj);


} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_STRUCTS_H
//------------------------------------------------------------------------------
