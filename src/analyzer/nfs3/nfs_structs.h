//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: All RFC1813 declared structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_STRUCTS_H
#define NFS_STRUCTS_H
//------------------------------------------------------------------------------
#include "../../auxiliary/print/indent.h"
#include "../rpc/rpc_struct.h" // OpaqueAuth, RPCMessage, RPCCall, RPCReply
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
const uint32_t cg_fhsize  = 64;

const uint32_t cg_cookieverfsize = 8;
const uint32_t cg_createverfsize = 8;
const uint32_t cg_writeverfszie  = 8;

class FileName
{
public:
    FileName()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, FileName& obj);
    friend std::ostream& operator<<(std::ostream& out, const FileName& obj); 

    inline std::string get_filename() const
    {
        return filename.to_string();
    }
private:
    FileName(const FileName& obj);
    void operator=(const FileName& obj); 

    OpaqueDyn filename;
};

class NFSPath
{
public:
    NFSPath()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, NFSPath& obj);
    friend std::ostream& operator<<(std::ostream& out, const NFSPath& obj); 

    inline std::string get_nfspath() const
    {
        return nfspath.to_string();
    }
private:
    NFSPath(const NFSPath& obj);
    void operator=(const NFSPath& obj); 

    OpaqueDyn nfspath;
};

class FileID
{
public:
    FileID()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, FileID& obj);
    friend std::ostream& operator<<(std::ostream& out, const FileID& obj); 

    inline uint64_t get_fileid() const
    {
        return fileid;
    }
private:
    FileID(const FileID& obj);
    void operator=(const FileID& obj); 

    uint64_t fileid;
};

class Cookie
{
public:
    Cookie()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, Cookie& obj);
    friend std::ostream& operator<<(std::ostream& out, const Cookie& obj); 

    inline uint64_t get_cookie() const
    {
        return cookie;
    }
private:
    Cookie(const Cookie& obj);
    void operator=(const Cookie& obj); 

    uint64_t cookie;
};

class CookieVerf
{
public:
    CookieVerf()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, CookieVerf& obj);
    friend std::ostream& operator<<(std::ostream& out, const CookieVerf& obj); 

    inline const std::vector<uint8_t>& get_cookieverf() const
    {
        return cookieverf.data;
    }
private:
    CookieVerf(const CookieVerf& obj);
    void operator=(const CookieVerf& obj); 

    OpaqueStat<cg_cookieverfsize> cookieverf;
};

class CreateVerf
{
public:
    CreateVerf()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, CreateVerf& obj);
    friend std::ostream& operator<<(std::ostream& out, const CreateVerf& obj); 

    inline const std::vector<uint8_t>& get_createverf() const
    {
        return createverf.data;
    }
private:
    CreateVerf(const CreateVerf& obj);
    void operator=(const CreateVerf& obj); 

    OpaqueStat<cg_createverfsize> createverf;
};

class WriteVerf
{
public:
    WriteVerf()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, WriteVerf& obj);
    friend std::ostream& operator<<(std::ostream& in, const WriteVerf& obj);

    inline const std::vector<uint8_t>& get_writeverf() const
    {
        return writeverf.data;
    }
private:
    WriteVerf(const WriteVerf& obj);
    void operator=(const WriteVerf& obj); 

    OpaqueStat<cg_writeverfszie> writeverf;
};

class UID
{
public:
    UID()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, UID& obj);
    friend std::ostream& operator<<(std::ostream& in, const UID& obj);

    inline uint32_t get_uid() const
    {
        return uid;
    }
private:
    UID(const UID& obj);
    void operator=(const UID& obj); 

    uint32_t uid;
};

class GID
{
public:
    GID()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, GID& obj);
    friend std::ostream& operator<<(std::ostream& in, const GID& obj);

    inline uint32_t get_gid() const
    {
        return gid;
    }
private:
    GID(const GID& obj);
    void operator=(const GID& obj); 

    uint32_t gid;
};

class Size
{
public:
    Size()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, Size& obj);
    friend std::ostream& operator<<(std::ostream& in, const Size& obj);

    inline uint32_t get_size() const
    {
        return size;
    }
private:
    Size(const Size& obj);
    void operator=(const Size& obj); 

    uint64_t size;
};

class Offset
{
public:
    Offset()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, Offset& obj);
    friend std::ostream& operator<<(std::ostream& in, const Offset& obj);

    inline uint32_t get_offset() const
    {
        return offset;
    }
private:
    Offset(const Offset& obj);
    void operator=(const Offset& obj); 

    uint64_t offset;
};

class Mode
{
public:
    Mode()
    {
    }
    enum EMode
    {
        USER_ID_EXEC      = 0x800,
        GROUP_ID_EXEC     = 0x400,
        SAVE_SWAPPED_TEXT = 0x200, // Not defined in POSIX
        OWNER_READ        = 0x100,
        OWNER_WRITE       = 0x080,
        OWNER_EXEC        = 0x040, // Search in directory
        GROUP_READ        = 0x020,
        GROUP_WRITE       = 0x010,
        GROUP_EXEC        = 0x008, // Search in directory
        OTHER_READ        = 0x004,
        OTHER_WRITE       = 0x002,
        OTHER_EXEC        = 0x001  // Search in directory
    };
    friend XDRReader& operator>>(XDRReader& in, Mode& obj);
    friend std::ostream& operator<<(std::ostream& in, const Mode& obj);

    inline EMode get_mode() const
    {
        return EMode(mode);
    }
private:
    Mode(const Mode& obj);
    void operator=(const Mode& obj); 

    uint32_t mode;
};

class Count
{
public:
    Count()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, Count& obj);
    friend std::ostream& operator<<(std::ostream& in, const Count& obj);

    inline uint32_t get_count() const
    {
        return count;
    }
private:
    Count(const Count& obj);
    void operator=(const Count& obj); 

    uint32_t count;
};

class NFSStat
{
public:
    NFSStat()
    {
    }
    enum ENFSStat
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
    friend XDRReader& operator>>(XDRReader& in, NFSStat& obj);
    friend std::ostream& operator<<(std::ostream& in, const NFSStat& obj);

    inline ENFSStat get_nfsstat() const
    {
        return ENFSStat(nfsstat);
    }
private:
    NFSStat(const NFSStat& obj);
    void operator=(const NFSStat& obj); 

    uint32_t nfsstat;
};

class FType
{
public:
    FType()
    {
    }
    enum EFType
    {
        REG  = 1,
        DIR  = 2,
        BLK  = 3,
        CHR  = 4,
        LNK  = 5,
        SOCK = 6,
        FIFO = 7
    };
    friend XDRReader& operator>>(XDRReader& in, FType& obj);
    friend std::ostream& operator<<(std::ostream& in, const FType& obj);

    inline EFType get_ftype() const
    {
        return EFType(ftype);
    }
private:
    FType(const FType& obj);
    void operator=(const FType& obj); 

    uint32_t ftype;
};

class SpecData
{
public:
    SpecData()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, SpecData& obj);
    friend std::ostream& operator<<(std::ostream& in, const SpecData& obj);

    inline uint32_t get_specdata1() const
    {
        return specdata1;
    }
    inline uint32_t get_specdata2() const
    {
        return specdata2;
    }
private:
    SpecData(const SpecData& obj);
    void operator=(const SpecData& obj); 

    uint32_t specdata1;
    uint32_t specdata2;
};

class NFS_FH
{
public:
    NFS_FH()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, NFS_FH& obj);
    friend std::ostream& operator<<(std::ostream& in, const NFS_FH& obj);

    inline const OpaqueDyn& get_data() const
    {
        return data;
    }
private:
    NFS_FH(const NFS_FH& obj);
    void operator=(const NFS_FH& obj); 

    OpaqueDyn data; //TODO: Check data (should be less than "cg_fhsize") 
};

class NFSTime
{
public:
    NFSTime()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, NFSTime& obj);
    friend std::ostream& operator<<(std::ostream& in, const NFSTime& obj);

    inline uint32_t get_seconds() const
    {
        return seconds;
    }
    inline uint32_t get_nseconds() const
    {
        return nseconds;
    }
private:
    NFSTime(const NFSTime& obj);
    void operator=(const NFSTime& obj); 

    uint32_t seconds;
    uint32_t nseconds;
};

class FAttr
{
public:
    FAttr()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, FAttr& obj);
    friend std::ostream& operator<<(std::ostream& in, const FAttr& obj);

    inline const FType& get_type() const
    {
        return type;
    }
    inline const Mode& get_mode() const
    {
        return mode;
    }
    inline uint32_t get_nlink() const
    {
        return nlink;
    }
    inline const UID& get_uid() const
    {
        return uid;
    }
    inline const GID& get_gid() const
    {
        return gid;
    }
    inline const Size& get_size() const
    {
        return size;
    }
    inline const Size& get_used() const
    {
        return used;
    }
    inline const SpecData& get_rdev() const
    {
        return rdev;
    }
    inline uint64_t get_fsid() const
    {
        return fsid;
    }
    inline const FileID& get_fileid() const
    {
        return fileid;
    }
    inline const NFSTime& get_atime() const
    {
        return atime;
    }
    inline const NFSTime& get_mtime() const
    {
        return mtime;
    }
    inline const NFSTime& get_ctime() const
    {
        return ctime;
    }
private:
    FAttr(const FAttr& obj);
    void operator=(const FAttr& obj); 

    FType    type;
    Mode     mode;
    uint32_t nlink;
    UID      uid;
    GID      gid;
    Size     size;
    Size     used;
    SpecData rdev;
    uint64_t fsid;
    FileID   fileid;
    NFSTime  atime;
    NFSTime  mtime;
    NFSTime  ctime;
};

class Post_Op_Attr
{
public:
    Post_Op_Attr() : attributes(NULL)
    {
    }
    ~Post_Op_Attr()
    {
        delete attributes;
    }
    friend XDRReader& operator>>(XDRReader& in, Post_Op_Attr& obj);
    friend std::ostream& operator<<(std::ostream& in, const Post_Op_Attr& obj);

    inline bool is_attributes() const
    {
        return attributes != NULL;
    }
    inline const FAttr& get_attributes() const
    {
        return *attributes;
    }
private:
    Post_Op_Attr(const Post_Op_Attr& obj);
    void operator=(const Post_Op_Attr& obj); 

    FAttr*  attributes;
};

class WCC_Attr
{
public:
    WCC_Attr()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, WCC_Attr& obj);
    friend std::ostream& operator<<(std::ostream& in, const WCC_Attr& obj);

    inline const Size& get_size() const
    {
        return size;
    }
    inline const NFSTime& get_mtime() const
    {
        return mtime;
    }
    inline const NFSTime& get_ctime() const
    {
        return ctime;
    }
private:
    WCC_Attr(const WCC_Attr& obj);
    void operator=(const WCC_Attr& obj); 

    Size    size;
    NFSTime mtime;
    NFSTime ctime;
};

class Pre_Op_Attr
{
public:
    Pre_Op_Attr() : attributes(NULL)
    {
    }
    ~Pre_Op_Attr()
    {
        delete attributes;
    }
    friend XDRReader& operator>>(XDRReader& in, Pre_Op_Attr& obj);
    friend std::ostream& operator<<(std::ostream& in, const Pre_Op_Attr& obj);

    inline bool is_attributes() const
    {
        return attributes != NULL;
    }
    inline const WCC_Attr& get_attributes() const
    {
        return *attributes;
    }
private:
    Pre_Op_Attr(const Pre_Op_Attr& obj);
    void operator=(const Pre_Op_Attr& obj); 

    WCC_Attr* attributes;
};

class WCC_Data
{
public:
    WCC_Data()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, WCC_Data& obj);
    friend std::ostream& operator<<(std::ostream& in, const WCC_Data& obj);

    inline const Pre_Op_Attr& get_before() const
    {
        return before;
    }
    inline const Post_Op_Attr& get_after() const
    {
        return after;
    }
private:
    WCC_Data(const WCC_Data& obj);
    void operator=(const WCC_Data& obj); 

    Pre_Op_Attr  before;
    Post_Op_Attr after;
};

class Post_Op_FH
{
public:
    Post_Op_FH() : b_handle(false)
    {
    }
    friend XDRReader& operator>>(XDRReader& in, Post_Op_FH& obj);
    friend std::ostream& operator<<(std::ostream& in, const Post_Op_FH& obj);

    inline bool is_handle() const
    {
        return b_handle;
    }
    inline const NFS_FH& get_handle() const
    {
        return handle;
    }
private:
    Post_Op_FH(const Post_Op_FH& obj);
    void operator=(const Post_Op_FH& obj); 

    bool    b_handle;
    NFS_FH  handle;
};

class SAttr
{
public:
    SAttr() : b_mode(false), b_uid(false), b_gid(false), b_size(false), b_atime(false), b_mtime(false)
    {
    }
    enum Time_How
    {
        DONT_CHANGE = 0,
        SET_TO_SERVER_TIME = 1,
        SET_TO_CLIENT_TIME = 2
    };

    friend XDRReader& operator>>(XDRReader& in, SAttr& obj);
    friend std::ostream& operator<<(std::ostream& in, const SAttr& obj);

    inline bool is_mode() const
    {
        return b_mode;
    }
    inline const Mode& get_mode() const
    {
        return mode;
    }
    inline bool is_uid() const
    {
        return b_uid;
    }
    inline const UID& get_uid() const
    {
        return uid;
    }
    inline bool is_gid() const
    {
        return b_gid;
    }
    inline const GID& get_gid() const
    {
        return gid;
    }
    inline bool is_size() const
    {
        return b_size;
    }
    inline const Size& get_size() const
    {
        return size;
    }
    inline bool is_atime() const
    {
        return b_atime;
    }
    inline const NFSTime& get_atime() const
    {
        return atime;
    }
    inline bool is_mtime() const
    {
        return b_mtime;
    }
    inline const NFSTime& get_mtime() const
    {
        return mtime;
    }

private:
    SAttr(const SAttr& obj);
    void operator=(const SAttr& obj); 

    bool b_mode;
    bool b_uid;
    bool b_gid;
    bool b_size;
    bool b_atime;
    bool b_mtime;
    Mode mode;
    UID  uid;
    GID  gid;
    Size size;
    NFSTime atime;
    NFSTime mtime;
};

class DirOpArgs
{
public:
    DirOpArgs()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, DirOpArgs& obj);
    friend std::ostream& operator<<(std::ostream& in, const DirOpArgs& obj);

    inline const NFS_FH& get_dir() const
    {
        return dir;
    }
    inline const FileName& get_name() const
    {
        return name;
    }
private:
    DirOpArgs(const DirOpArgs& obj);
    void operator=(const DirOpArgs& obj); 

    NFS_FH   dir;
    FileName name;
};

class NullArgs : public RPCCall
{
public:
    NullArgs(XDRReader& in) : RPCCall(in)
    {
    }
    virtual ~NullArgs()
    {
    }
};

class GetAttrArgs : public RPCCall
{
public:
    GetAttrArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file;
    }
    virtual ~GetAttrArgs()
    {
    }

    const OpaqueDyn& get_file() const
    {
        return file;
    }

private:
    OpaqueDyn file;     // File handle
};

class SAttrGuard
{
public:
    SAttrGuard()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, SAttrGuard& obj);
    friend std::ostream& operator<<(std::ostream& in, const SAttrGuard& obj);

    inline bool is_obj_ctime() const
    {
        return b_obj_ctime;
    }
    inline const NFSTime& get_obj_ctime() const
    {
        return obj_ctime;
    }
private:
    SAttrGuard(const SAttrGuard& obj);
    void operator=(const SAttrGuard& obj); 

    bool    b_obj_ctime;
    NFSTime obj_ctime;
};

class SetAttrArgs : public RPCCall
{
public:
    SetAttrArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object >> new_attributes >> guard;
    }
    friend std::ostream& operator<<(std::ostream& in, const SetAttrArgs& obj);

    inline const NFS_FH& get_object() const
    {
        return object;
    }
    inline const SAttr& get_new_attributes() const
    {
        return new_attributes;
    }
    inline const SAttrGuard& get_guard() const
    {
        return guard;
    }

private:
    SetAttrArgs(const SetAttrArgs& obj);
    void operator=(const SetAttrArgs& obj); 

    NFS_FH     object;
    SAttr      new_attributes;
    SAttrGuard guard;
};

class LookUpArgs : public RPCCall
{
public:
    LookUpArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> name;
    }
    virtual ~LookUpArgs()
    {
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const std::string& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn dir;      // File handle
    std::string name;   // File name
};

class AccessArgs : public RPCCall
{
public:
    AccessArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object >> access;
    }
    virtual ~AccessArgs()
    {
    }

    const OpaqueDyn& get_object() const
    {
        return object;
    }
    uint32_t get_access() const
    {
        return access;
    }

private:
    OpaqueDyn object;   // File handle
    uint32_t access;
};

class ReadLinkArgs : public RPCCall
{
public:
    ReadLinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> symlink;
    }
    virtual ~ReadLinkArgs()
    {
    }

    const OpaqueDyn& get_symlink() const
    {
        return symlink;
    }

private:
    OpaqueDyn symlink;  // File handle
};

class ReadArgs : public RPCCall
{
public:
    ReadArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count;
    }
    virtual ~ReadArgs()
    {
    }
    
    const OpaqueDyn& get_file() const
    {
        return file;
    }
    uint64_t get_offset() const
    {
        return offset;
    }
    uint32_t get_count() const
    {
        return count;
    }

private:
    OpaqueDyn file;     // File handle
    uint64_t  offset;
    uint32_t  count;
};

class WriteArgs : public RPCCall
{
public:
    WriteArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count >> stable;
    }
    virtual ~WriteArgs()
    {
    }
    enum Stable_How
    {
        UNSTABLE    = 0,
        DATA_SYNC   = 1,
        FYLE_SYNC   = 2
    };
    friend std::ostream& operator<<(std::ostream& in, const WriteArgs& obj);

    const NFS_FH& get_file() const
    {
        return file;
    }
    const Offset& get_offset() const
    {
        return offset;
    }
    const Count& get_count() const
    {
        return count;
    }
    Stable_How get_stable() const
    {
        return Stable_How(stable);
    }
    
private:
    NFS_FH      file;
    Offset      offset;
    Count       count;
    uint32_t    stable;
    //OpaqueDyn   data;
};

class CreateHow
{
public:
    CreateHow() : obj_attributes(NULL), verf(NULL)
    {
    }
    ~CreateHow()
    {
        delete obj_attributes;
        delete verf;
    }
    enum CreateMode
    {
        UNCHECKED = 0,
        GUARDED   = 1,
        EXCLUSIVE = 2
    };
    friend XDRReader& operator>>(XDRReader& in, CreateHow& obj);
    friend std::ostream& operator<<(std::ostream& in, const CreateHow& obj);

    inline const CreateVerf& get_verf() const
    {
        return *verf;
    }
    inline const SAttr& get_obj_attributes() const
    {
        return *obj_attributes;
    }
    inline CreateMode get_mode() const
    {
        return CreateMode(mode);
    }

private:
    CreateHow(const CreateHow& obj);
    void operator=(const CreateHow& obj); 

    SAttr*      obj_attributes;
    CreateVerf* verf;
    uint32_t    mode;
};

class CreateArgs : public RPCCall
{
public:
    CreateArgs(XDRReader& in) : RPCCall(in)
    {
        in >> where >> how;
    }
    friend std::ostream& operator<<(std::ostream& in, const CreateArgs& obj);

    inline const DirOpArgs& get_where() const
    {
        return where;
    }
    inline const CreateHow& get_how() const
    {
        return how;
    }

private:
    CreateArgs(const CreateArgs& obj);
    void operator=(const CreateArgs& obj); 

    DirOpArgs where;
    CreateHow how;
};

class MkDirArgs : public RPCCall
{
public:
    MkDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> where >> attributes;
    }
    friend std::ostream& operator<<(std::ostream& in, const MkDirArgs& obj);

    inline const DirOpArgs& get_where() const
    {
        return where;
    }
    inline const SAttr& get_attributes() const
    {
        return attributes;
    }

private:
    MkDirArgs(const MkDirArgs& obj);
    void operator=(const MkDirArgs& obj); 

    DirOpArgs where;
    SAttr attributes;
};

class SymLinkData
{
public:
    SymLinkData()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, SymLinkData& obj);
    friend std::ostream& operator<<(std::ostream& in, const SymLinkData& obj);

    inline const SAttr& get_symlink_attributes() const
    {
        return symlink_attributes;
    }
    inline const NFSPath& get_symlink_data() const
    {
        return symlink_data;
    }

private:
    SymLinkData(const SymLinkData& obj);
    void operator=(const SymLinkData& obj); 

    SAttr   symlink_attributes;
    NFSPath symlink_data;
};

class SymLinkArgs : public RPCCall
{
public:
    SymLinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> where >> symlink;
    }
    friend std::ostream& operator<<(std::ostream& in, const SymLinkArgs& obj);

    inline const DirOpArgs& get_where() const
    {
        return where;
    }
    inline const SymLinkData& get_symlink() const
    {
        return symlink;
    }

private:
    SymLinkArgs(const SymLinkArgs& obj);
    void operator=(const SymLinkArgs& obj); 

    DirOpArgs where;
    SymLinkData symlink;
};

class DeviceData
{
public:
    DeviceData()
    {
    }
    friend XDRReader& operator>>(XDRReader& in, DeviceData& obj);
    friend std::ostream& operator<<(std::ostream& in, const DeviceData& obj);

    inline const SAttr& get_dev_attributes() const
    {
        return dev_attributes;
    }
    inline const SpecData& get_spec() const
    {
        return spec;
    }

private:
    DeviceData(const DeviceData& obj);
    void operator=(const DeviceData& obj); 

    SAttr    dev_attributes;
    SpecData spec;
};

class MkNodData
{
public:
    MkNodData() : device(NULL), pipe_attributes(NULL)
    {
    }
    friend XDRReader& operator>>(XDRReader& in, MkNodData& pipe);
    friend std::ostream& operator<<(std::ostream& in, const MkNodData& obj);

    inline FType::EFType get_type() const
    {
        return type.get_ftype();
    }
    inline const SAttr& get_pipe_attributes() const
    {
        return *pipe_attributes;
    }
    inline const DeviceData& get_device() const
    {
        return *device;
    }

private:
    MkNodData(const MkNodData& pipe);
    void operator=(const MkNodData& pipe); 

    FType       type;
    DeviceData* device;
    SAttr*      pipe_attributes;
};

class MkNodArgs : public RPCCall
{
public:
    MkNodArgs(XDRReader& in) : RPCCall(in)
    {
        in >> where >> what;
    }
    friend std::ostream& operator<<(std::ostream& in, const MkNodArgs& obj);

    inline const DirOpArgs& get_where() const
    {
        return where;
    }
    inline const MkNodData& get_what() const
    {
        return what;
    }

private:
    MkNodArgs(const MkNodArgs& obj);
    void operator=(const MkNodArgs& obj); 

    DirOpArgs where;
    MkNodData what;
};

class RemoveArgs : public RPCCall
{
public:
    RemoveArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> name;
    }
    virtual ~RemoveArgs()
    {
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const std::string& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn dir;      // File handle
    std::string name;   // File name
}; 

class RmDirArgs : public RPCCall
{
public:
    RmDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> name;
    }
    virtual ~RmDirArgs()
    {
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const std::string& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn dir;      // File handle
    std::string name;   // File name
};

class RenameArgs : public RPCCall
{
public:
    RenameArgs(XDRReader& in) : RPCCall(in)
    {
        in >> from_dir >> from_name;
        in >> to_dir >> to_name;
    }
    virtual ~RenameArgs()
    {
    }
    
    const OpaqueDyn& get_from_dir() const
    {
        return from_dir;
    }
    const std::string& get_from_name() const
    {
        return from_name;
    }
    const OpaqueDyn& get_to_dir() const
    {
        return to_dir;
    }
    const std::string& get_to_name() const
    {
        return to_name;
    }

private:
    OpaqueDyn from_dir; // File handle
    std::string from_name;
    OpaqueDyn to_dir;   // File handle
    std::string to_name;
}; 

class LinkArgs : public RPCCall
{
public:
    LinkArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> dir >> name;
    }
    virtual ~LinkArgs()
    {
    }
    
    const OpaqueDyn& get_file() const
    {
        return file;
    }
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    const std::string& get_name() const
    {
        return name;
    }

private:
    OpaqueDyn file;     // File handle
    OpaqueDyn dir;      // File handle
    std::string name;
};

class ReadDirArgs : public RPCCall
{
public:
    ReadDirArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> cookie >> cookieverf >> count;
    }
    virtual ~ReadDirArgs()
    {
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    uint64_t get_cookie() const
    {
        return cookie;
    }
    const OpaqueStat<8>& get_cookieverf() const
    {
        return cookieverf;
    }
    uint32_t get_count() const
    {
        return count;
    }

private:
    OpaqueDyn dir;      // File handle
    uint64_t cookie;
    OpaqueStat<8> cookieverf;
    uint32_t count;
};

class ReadDirPlusArgs : public RPCCall
{
public:
    ReadDirPlusArgs(XDRReader& in) : RPCCall(in)
    {
        in >> dir >> cookie >> cookieverf >> dir_count >> max_count;
    }
    virtual ~ReadDirPlusArgs()
    {
    }
    
    const OpaqueDyn& get_dir() const
    {
        return dir;
    }
    uint64_t get_cookie() const
    {
        return cookie;
    }
    const OpaqueStat<8>& get_cookieverf() const
    {
        return cookieverf;
    }
    uint32_t get_dir_count() const
    {
        return dir_count;
    }
    uint32_t get_max_count() const
    {
        return max_count;
    }

private:
    OpaqueDyn dir;      // File handle
    uint64_t cookie;
    OpaqueStat<8> cookieverf;
    uint32_t dir_count;
    uint32_t max_count;
};

class FSStatArgs : public RPCCall
{
public:
    FSStatArgs(XDRReader& in) : RPCCall(in)
    {
        in >> fs_root;
    }
    virtual ~FSStatArgs()
    {
    }
    
    const OpaqueDyn& get_fs_root() const
    {
        return fs_root;
    }

private:
    OpaqueDyn fs_root;  // File handle
};

class FSInfoArgs : public RPCCall
{
public:
    FSInfoArgs(XDRReader& in) : RPCCall(in)
    {
        in >> fs_root;
    }
    virtual ~FSInfoArgs()
    {
    }
    
    const OpaqueDyn& get_fs_root() const
    {
        return fs_root;
    }

private:
    OpaqueDyn fs_root;  // File handle
};

class PathConfArgs : public RPCCall
{
public:
    PathConfArgs(XDRReader& in) : RPCCall(in)
    {
        in >> object;
    }
    virtual ~PathConfArgs()
    {
    }

    const OpaqueDyn& get_object() const
    {
        return object;
    }

private:
    OpaqueDyn object;   // File handle
};

class CommitArgs : public RPCCall
{
public:
    CommitArgs(XDRReader& in) : RPCCall(in)
    {
        in >> file >> offset >> count;
    }
    virtual ~CommitArgs()
    {
    }

    const OpaqueDyn& get_file() const
    {
        return file;
    }
    uint64_t get_offset() const
    {
        return offset;
    }
    uint32_t get_count() const
    {
        return count;
    }

private:
    OpaqueDyn file;     // File handle
    uint64_t offset;
    uint32_t count;
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_STRUCTS_H
//------------------------------------------------------------------------------
