//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include "print_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

// Special helper for print-out short representation of NFS FH
std::ostream& operator += (std::ostream& out, const nfs_fh3& fh)
{
    static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    const Opaque& opaque = fh.data;
    const uint8_t* data = opaque.data();
    const uint32_t size = opaque.size();

    if(size <= 8)
    {
        for(uint32_t j = 0; j < size; j++)
        {
            uint8_t value = data[j];
            out << hex[value & 0xF];
            value >>= 4;
            out << hex[value & 0xF];
        }
    }
    else // truncate binary data to: 00112233...CCDDEEFF
    {
        for(uint32_t j = 0; j < 4; j++)
        {
            uint8_t value = data[j];
            out << hex[value & 0xF];
            value >>= 4;
            out << hex[value & 0xF];
        }
        out << "...";
        for(uint32_t j = size-4; j < size; j++)
        {
            uint8_t value = data[j];
            out << hex[value & 0xF];
            value >>= 4;
            out << hex[value & 0xF];
        }
    }
    return out;
}

inline std::ostream& operator << (std::ostream& out, const struct RPCProcedure* proc)
{
    return out << *(proc->session) << ' ' << Proc::Titles[proc->call.proc] << " XID: " << proc->call.xid;
}

void PrintAnalyzer::null(const struct RPCProcedure* proc,
                         const struct NULLargs*,
                         const struct NULLres*)
{
    out << proc;
    out << " CALL [] REPLY []";
    out << std::endl;
}

void PrintAnalyzer::getattr3(const RPCProcedure* proc,
                             const struct GETATTR3args* args,
                             const struct GETATTR3res* res)
{
    out << proc;
    out << " CALL [";
    out << " object: " += args->object;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::setattr3(const RPCProcedure* proc,
                             const struct SETATTR3args* args,
                             const struct SETATTR3res* res)
{
    out << proc;
    out << " CALL [";
    out << " object: "         += args->object;
    out << " new_attributes: " << args->new_attributes;
    out << " guard: "          << args->guard;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::lookup3(const RPCProcedure* proc,
                            const struct LOOKUP3args* args,
                            const struct LOOKUP3res* res)
{
    out << proc;
    out << " CALL [";
    out << " what: " << args->what;
    out << "] REPLY [";
    out << " status: " << res->status;
    if(res->status == nfsstat3::OK)
    {
        out << " object: "          += res->resok.object;
        out << " obj_attributes: "  << res->resok.obj_attributes;
        out << " dir_attributes: "  << res->resok.dir_attributes;
    }
    else
    {
        out << " dir_attributes: "  << res->resfail.dir_attributes;
    }
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::access3(const struct RPCProcedure* proc,
                            const struct ACCESS3args* args,
                            const struct ACCESS3res* res)
{
    out << proc;
    out << " CALL [";
    out << " object: " += args->object;
    out << " access: ";
    if(args->access & ACCESS3args::ACCESS3_READ)   out << "READ ";
    if(args->access & ACCESS3args::ACCESS3_LOOKUP) out << "LOOKUP ";
    if(args->access & ACCESS3args::ACCESS3_MODIFY) out << "MODIFY ";
    if(args->access & ACCESS3args::ACCESS3_EXTEND) out << "EXTEND ";
    if(args->access & ACCESS3args::ACCESS3_DELETE) out << "DELETE ";
    if(args->access & ACCESS3args::ACCESS3_EXECUTE)out << "EXECUTE ";

    out << "] REPLY [";
    out << " status: " << res->status;
    if(res->status == nfsstat3::OK)
    {
        out << " obj_attributes: " << res->u.resok.obj_attributes;
        out << " access: ";
        uint32_t access = res->u.resok.access;
        if(access & ACCESS3args::ACCESS3_READ)   out << "READ ";
        if(access & ACCESS3args::ACCESS3_LOOKUP) out << "LOOKUP ";
        if(access & ACCESS3args::ACCESS3_MODIFY) out << "MODIFY ";
        if(access & ACCESS3args::ACCESS3_EXTEND) out << "EXTEND ";
        if(access & ACCESS3args::ACCESS3_DELETE) out << "DELETE ";
        if(access & ACCESS3args::ACCESS3_EXECUTE)out << "EXECUTE ";
    }
    else
    {
        out << " obj_attributes: " << res->u.resfail.obj_attributes;
    }
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::readlink3(const struct RPCProcedure* proc,
                              const struct READLINK3args* args,
                              const struct READLINK3res* res)
{
    out << proc;
    out << " CALL [";
    out << " symlink: " += args->symlink;
    out << "] REPLY [";
    out << " status: "  << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::read3(const struct RPCProcedure* proc,
                          const struct READ3args* args,
                          const struct READ3res* res)
{
    out << proc;
    out << " CALL [";
    out << " file: "   += args->file;
    out << " offset: " << args->offset;
    out << " count: "  << args->count;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::write3(const struct RPCProcedure* proc,
                           const struct WRITE3args* args,
                           const struct WRITE3res* res)
{
    out << proc;
    out << " CALL [";
    out << " file: "   += args->file;
    out << " offset: " << args->offset;
    out << " count: "  << args->count;
    out << " stable: " << args->stable;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::create3(const struct RPCProcedure* proc,
                            const struct CREATE3args* args,
                            const struct CREATE3res* res)
{
    out << proc;
    out << " CALL [";
    out << " where: " << args->where;
    out << " how: "   << args->how;
    out << "] REPLY [";
    out << " status: " << res->status;
    if(res->status == nfsstat3::OK)
    {
        out << " obj: "            << res->u.resok.obj;
        out << " obj_attributes: " << res->u.resok.obj_attributes;
        out << " dir_wcc: "        << res->u.resok.dir_wcc;
    }
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::mkdir3(const struct RPCProcedure* proc,
                           const struct MKDIR3args* args,
                           const struct MKDIR3res* res)
{
    out << proc;
    out << " CALL [";
    out << " where: "      << args->where;
    out << " attributes: " << args->attributes;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::symlink3(const struct RPCProcedure* proc,
                             const struct SYMLINK3args* args,
                             const struct SYMLINK3res* res)
{
    out << proc;
    out << " CALL [";
    out << " where: "       << args->where;
    out << " symlinkdata: " << args->symlink;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::mknod3(const struct RPCProcedure* proc,
                           const struct MKNOD3args* args,
                           const struct MKNOD3res* res)
{
    out << proc;
    out << " CALL [";
    out << " where: " << args->where;
    out << " what: "  << args->what;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::remove3(const struct RPCProcedure* proc,
                            const struct REMOVE3args* args,
                            const struct REMOVE3res* res)
{
    out << proc;
    out << " CALL [";
    out << " object: " << args->object;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::rmdir3(const struct RPCProcedure* proc,
                           const struct RMDIR3args* args,
                           const struct RMDIR3res* res)
{
    out << proc;
    out << " CALL [";
    out << " object: " << args->object;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::rename3(const struct RPCProcedure* proc,
                            const struct RENAME3args* args,
                            const struct RENAME3res* res)
{
    out << proc;
    out << " CALL [";
    out << " from: " << args->from;
    out << " to: "   << args->to;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::link3(const struct RPCProcedure* proc,
                          const struct LINK3args* args,
                          const struct LINK3res* res)
{
    out << proc;
    out << " CALL [";
    out << " file: " += args->file;
    out << " link: " << args->link;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::readdir3(const struct RPCProcedure* proc,
                             const struct READDIR3args* args,
                             const struct READDIR3res* res)
{
    out << proc;
    out << " CALL [";
    out << " dir: "         += args->dir;
    out << " cookie: "      << args->cookie;
    out << " cookieverf: "  << args->cookieverf;
    out << " count: "       << args->count;
    out << "] REPLY [";
    out << " status: "      << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::readdirplus3(const struct RPCProcedure* proc,
                                 const struct READDIRPLUS3args* args,
                                 const struct READDIRPLUS3res* res)
{
    out << proc;
    out << " CALL [";
    out << " dir: "         += args->dir;
    out << " cookie: "      << args->cookie;
    out << " cookieverf: "  << args->cookieverf;
    out << " dircount: "    << args->dircount;
    out << " maxcount: "    << args->maxcount;
    out << "] REPLY [";
    out << " status: " << res->status;
    if(res->status == nfsstat3::OK)
    {
        out << " dir_attributes: " << res->u.resok.dir_attributes;
        out << " cookieverf: "     << res->u.resok.cookieverf;
    }
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::fsstat3(const struct RPCProcedure* proc,
                            const struct FSSTAT3args* args,
                            const struct FSSTAT3res* res)
{
    out << proc;
    out << " CALL [";
    out << " fsroot: " += args->fsroot;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::fsinfo3(const struct RPCProcedure* proc,
                            const struct FSINFO3args* args,
                            const struct FSINFO3res* res)
{
    out << proc;
    out << " CALL [";
    out << " fsroot: " += args->fsroot;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::pathconf3(const struct RPCProcedure* proc,
                              const struct PATHCONF3args* args,
                              const struct PATHCONF3res* res)
{
    out << proc;
    out << " CALL [";
    out << " object: " += args->object;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::commit3(const struct RPCProcedure* proc,
                            const struct COMMIT3args* args,
                            const struct COMMIT3res* res)
{
    out << proc;
    out << " CALL [";
    out << " file: "    += args->file;
    out << " offset: "  << args->offset;
    out << " count: "   << args->count;
    out << "] REPLY [";
    out << " status: "  << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::flush_statistics()
{
    // flush is in each handler
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
