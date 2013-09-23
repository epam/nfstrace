//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Working Set (OFWS) analyzer. Enumerate the overall set of files accessed by clients.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <algorithm>
#include <vector>

#include "ofws_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
OFWSAnalyzer::~OFWSAnalyzer()
{
    Iterator i = ofws_stat.begin();
    Iterator end = ofws_stat.end();
    for(; i != end;)
    {
        delete i->second;
        i = ofws_stat.erase(i);
    }
}

void OFWSAnalyzer::null(const struct RPCProcedure*,
                        const struct NULLargs*,
                        const struct NULLres*)
{
}

void OFWSAnalyzer::getattr3(const RPCProcedure*,
                            const struct GETATTR3args* args,
                            const struct GETATTR3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->object);
        (*i->second).inc(ProcEnum::GETATTR);
    }
}

void OFWSAnalyzer::setattr3(const RPCProcedure*,
                            const struct SETATTR3args* args,
                            const struct SETATTR3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->object);
        (*i->second).inc(ProcEnum::SETATTR);
    }
}

void OFWSAnalyzer::lookup3(const RPCProcedure*,
                           const struct LOOKUP3args*,
                           const struct LOOKUP3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(res->resok.object);
        (*i->second).inc(ProcEnum::LOOKUP);
    }
}

void OFWSAnalyzer::access3(const struct RPCProcedure*,
                           const struct ACCESS3args* args,
                           const struct ACCESS3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->object);
        (*i->second).inc(ProcEnum::ACCESS);
    }
}

void OFWSAnalyzer::readlink3(const struct RPCProcedure*,
                             const struct READLINK3args* args,
                             const struct READLINK3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->symlink);
        (*i->second).inc(ProcEnum::READLINK);
    }
}

void OFWSAnalyzer::read3(const struct RPCProcedure*,
                         const struct READ3args* args,
                         const struct READ3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->file);
        (*i->second).inc(ProcEnum::READ);
    }
}

void OFWSAnalyzer::write3(const struct RPCProcedure*,
                          const struct WRITE3args* args,
                          const struct WRITE3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->file);
        (*i->second).inc(ProcEnum::WRITE);
    }
}

void OFWSAnalyzer::create3(const struct RPCProcedure*,
                           const struct CREATE3args*,
                           const struct CREATE3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        if(res->u.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res->u.resok.obj.handle);
            (*i->second).inc(ProcEnum::CREATE);
        }
    }
}

void OFWSAnalyzer::mkdir3(const struct RPCProcedure*,
                          const struct MKDIR3args*,
                          const struct MKDIR3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        if(res->u.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res->u.resok.obj.handle);
            (*i->second).inc(ProcEnum::MKDIR);
        }
    }
}

void OFWSAnalyzer::symlink3(const struct RPCProcedure*,
                            const struct SYMLINK3args*,
                            const struct SYMLINK3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        if(res->u.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res->u.resok.obj.handle);
            (*i->second).inc(ProcEnum::SYMLINK);
        }
    }
}

void OFWSAnalyzer::mknod3(const struct RPCProcedure*,
                          const struct MKNOD3args*,
                          const struct MKNOD3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        if(res->u.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res->u.resok.obj.handle);
            (*i->second).inc(ProcEnum::MKNOD);
        }
    }
}

void OFWSAnalyzer::remove3(const struct RPCProcedure*,
                           const struct REMOVE3args* args,
                           const struct REMOVE3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->object.dir);
        (*i->second).inc(ProcEnum::REMOVE);
    }
}

void OFWSAnalyzer::rmdir3(const struct RPCProcedure*,
                          const struct RMDIR3args* args,
                          const struct RMDIR3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->object.dir);
        (*i->second).inc(ProcEnum::RMDIR);
    }
}

void OFWSAnalyzer::rename3(const struct RPCProcedure*,
                           const struct RENAME3args* args,
                           const struct RENAME3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->from.dir);
        (*i->second).inc(ProcEnum::RENAME);
    }
}

void OFWSAnalyzer::link3(const struct RPCProcedure*,
                         const struct LINK3args* args,
                         const struct LINK3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->file);
        (*i->second).inc(ProcEnum::LINK);
    }
}

void OFWSAnalyzer::readdir3(const struct RPCProcedure*,
                            const struct READDIR3args* args,
                            const struct READDIR3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->dir);
        (*i->second).inc(ProcEnum::READDIR);
    }
}

void OFWSAnalyzer::readdirplus3(const struct RPCProcedure*,
                                const struct READDIRPLUS3args* args,
                                const struct READDIRPLUS3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->dir);
        (*i->second).inc(ProcEnum::READDIRPLUS);
    }
}

void OFWSAnalyzer::fsstat3(const struct RPCProcedure*,
                           const struct FSSTAT3args* args,
                           const struct FSSTAT3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->fsroot);
        (*i->second).inc(ProcEnum::FSSTAT);
    }
}

void OFWSAnalyzer::fsinfo3(const struct RPCProcedure*,
                           const struct FSINFO3args* args,
                           const struct FSINFO3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->fsroot);
        (*i->second).inc(ProcEnum::FSINFO);
    }
}

void OFWSAnalyzer::pathconf3(const struct RPCProcedure*,
                             const struct PATHCONF3args* args,
                             const struct PATHCONF3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->object);
        (*i->second).inc(ProcEnum::PATHCONF);
    }
}

void OFWSAnalyzer::commit3(const struct RPCProcedure*,
                           const struct COMMIT3args* args,
                           const struct COMMIT3res* res)
{
    if(res->status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(args->file);
        (*i->second).inc(ProcEnum::COMMIT);
    }
}

void OFWSAnalyzer::flush_statistics()
{
    uint32_t size = ofws_stat.size();
    std::vector< Iterator > v(size);
    Iterator i = ofws_stat.begin();
    Iterator end = ofws_stat.end();
    for(uint32_t j = 0; i != end; ++i, ++j)
    {
        v[j] = i;
    }
    std::sort(v.begin(), v.end(), iterator_comp); 

    out << "###  Overall File Working Set (OFWS) analyzer  ###" << std::endl;
    out << "Total number of files accessed: " << size << std::endl;
    out << "FileHandle" << ",NFS Ops";
    for(int32_t j = 0; j < ProcEnum::count; ++j)
    {
        out << ',' << static_cast<ProcEnum::NFSProcedure>(j);
    }
    out << '\n';

    for(uint32_t i = 0; i != size; ++i)
    {
        Iterator& iterator = v[i];
        const OpCounter* opcounter = iterator->second;

        out << iterator->first << ',' << opcounter->get_total();
        for(int32_t j = 0; j < ProcEnum::count; ++j)
        {
            out << ',' << (*opcounter)[j];
        }
        out << '\n';
    }
}

OFWSAnalyzer::Iterator OFWSAnalyzer::find_or_create_op_counter(const nfs_fh3& key)
{
    Iterator i = ofws_stat.find(key);
    if(i == ofws_stat.end())
    {
        Inserted ins = ofws_stat.insert(Pair(key, new OpCounter()));
        if(ins.second == false)
            throw int();
        i = ins.first;
    }
    return i;
}

extern "C"
{

BaseAnalyzer* create(const char* opts)
{
    return new OFWSAnalyzer(opts);
}

void destroy(BaseAnalyzer* context)
{
    delete context;
}

const char* usage()
{
    return "Do what you want!";
}

}
//------------------------------------------------------------------------------
