//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Working Set (OFWS) analyzer. Enumerate the overall set of files accessed by clients.
// Copyright (c) 2013 EPAM Systems
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
#include <algorithm>
#include <vector>

#include "ofws_analyzer.h"
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

void OFWSAnalyzer::getattr3(const RPCProcedure*,
                            const struct NFS3::GETATTR3args* args,
                            const struct NFS3::GETATTR3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->object);
        (*i->second).inc(ProcEnumNFS3::GETATTR);
    }
}

void OFWSAnalyzer::setattr3(const RPCProcedure*,
                            const struct NFS3::SETATTR3args* args,
                            const struct NFS3::SETATTR3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->object);
        (*i->second).inc(ProcEnumNFS3::SETATTR);
    }
}

void OFWSAnalyzer::lookup3(const RPCProcedure*,
                           const struct NFS3::LOOKUP3args*,
                           const struct NFS3::LOOKUP3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(res->LOOKUP3res_u.resok.object);
        (*i->second).inc(ProcEnumNFS3::LOOKUP);
    }
}

void OFWSAnalyzer::access3(const struct RPCProcedure*,
                           const struct NFS3::ACCESS3args* args,
                           const struct NFS3::ACCESS3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->object);
        (*i->second).inc(ProcEnumNFS3::ACCESS);
    }
}

void OFWSAnalyzer::readlink3(const struct RPCProcedure*,
                             const struct NFS3::READLINK3args* args,
                             const struct NFS3::READLINK3res* res)
{
    if(res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->symlink);
        (*i->second).inc(ProcEnumNFS3::READLINK);
    }
}

void OFWSAnalyzer::read3(const struct RPCProcedure*,
                         const struct NFS3::READ3args* args,
                         const struct NFS3::READ3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->file);
        (*i->second).inc(ProcEnumNFS3::READ);
    }
}

void OFWSAnalyzer::write3(const struct RPCProcedure*,
                          const struct NFS3::WRITE3args* args,
                          const struct NFS3::WRITE3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->file);
        (*i->second).inc(ProcEnumNFS3::WRITE);
    }
}

void OFWSAnalyzer::create3(const struct RPCProcedure*,
                           const struct NFS3::CREATE3args*,
                           const struct NFS3::CREATE3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        if(res->CREATE3res_u.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res->CREATE3res_u.resok.obj.post_op_fh3_u.handle);
            (*i->second).inc(ProcEnumNFS3::CREATE);
        }
    }
}

void OFWSAnalyzer::mkdir3(const struct RPCProcedure*,
                          const struct NFS3::MKDIR3args*,
                          const struct NFS3::MKDIR3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        if(res->MKDIR3res_u.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res->MKDIR3res_u.resok.obj.post_op_fh3_u.handle);
            (*i->second).inc(ProcEnumNFS3::MKDIR);
        }
    }
}

void OFWSAnalyzer::symlink3(const struct RPCProcedure*,
                            const struct NFS3::SYMLINK3args*,
                            const struct NFS3::SYMLINK3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        if(res->SYMLINK3res_u.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res->SYMLINK3res_u.resok.obj.post_op_fh3_u.handle);
            (*i->second).inc(ProcEnumNFS3::SYMLINK);
        }
    }
}

void OFWSAnalyzer::mknod3(const struct RPCProcedure*,
                          const struct NFS3::MKNOD3args*,
                          const struct NFS3::MKNOD3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        if(res->MKNOD3res_u.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res->MKNOD3res_u.resok.obj.post_op_fh3_u.handle);
            (*i->second).inc(ProcEnumNFS3::MKNOD);
        }
    }
}

void OFWSAnalyzer::remove3(const struct RPCProcedure*,
                           const struct NFS3::REMOVE3args* args,
                           const struct NFS3::REMOVE3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->object.dir);
        (*i->second).inc(ProcEnumNFS3::REMOVE);
    }
}

void OFWSAnalyzer::rmdir3(const struct RPCProcedure*,
                          const struct NFS3::RMDIR3args* args,
                          const struct NFS3::RMDIR3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->object.dir);
        (*i->second).inc(ProcEnumNFS3::RMDIR);
    }
}

void OFWSAnalyzer::rename3(const struct RPCProcedure*,
                           const struct NFS3::RENAME3args* args,
                           const struct NFS3::RENAME3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->from.dir);
        (*i->second).inc(ProcEnumNFS3::RENAME);
    }
}

void OFWSAnalyzer::link3(const struct RPCProcedure*,
                         const struct NFS3::LINK3args* args,
                         const struct NFS3::LINK3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->file);
        (*i->second).inc(ProcEnumNFS3::LINK);
    }
}

void OFWSAnalyzer::readdir3(const struct RPCProcedure*,
                            const struct NFS3::READDIR3args* args,
                            const struct NFS3::READDIR3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->dir);
        (*i->second).inc(ProcEnumNFS3::READDIR);
    }
}

void OFWSAnalyzer::readdirplus3(const struct RPCProcedure*,
                                const struct NFS3::READDIRPLUS3args* args,
                                const struct NFS3::READDIRPLUS3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->dir);
        (*i->second).inc(ProcEnumNFS3::READDIRPLUS);
    }
}

void OFWSAnalyzer::fsstat3(const struct RPCProcedure*,
                           const struct NFS3::FSSTAT3args* args,
                           const struct NFS3::FSSTAT3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->fsroot);
        (*i->second).inc(ProcEnumNFS3::FSSTAT);
    }
}

void OFWSAnalyzer::fsinfo3(const struct RPCProcedure*,
                           const struct NFS3::FSINFO3args* args,
                           const struct NFS3::FSINFO3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->fsroot);
        (*i->second).inc(ProcEnumNFS3::FSINFO);
    }
}

void OFWSAnalyzer::pathconf3(const struct RPCProcedure*,
                             const struct NFS3::PATHCONF3args* args,
                             const struct NFS3::PATHCONF3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->object);
        (*i->second).inc(ProcEnumNFS3::PATHCONF);
    }
}

void OFWSAnalyzer::commit3(const struct RPCProcedure*,
                           const struct NFS3::COMMIT3args* args,
                           const struct NFS3::COMMIT3res* res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        Iterator i = find_or_create_op_counter(args->file);
        (*i->second).inc(ProcEnumNFS3::COMMIT);
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
    for(unsigned int j = 0; j < ProcEnumNFS3::count; ++j)
    {
        out << ',' << print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(j));
    }
    out << '\n';

    for(uint32_t i = 0; i != size; ++i)
    {
        Iterator& iterator = v[i];
        const OpCounter* opcounter = iterator->second;

        out << iterator->first << ',' << opcounter->get_total();
        for(unsigned int j = 0; j < ProcEnumNFS3::count; ++j)
        {
            out << ',' << (*opcounter)[j];
        }
        out << '\n';
    }
}

OFWSAnalyzer::Iterator OFWSAnalyzer::find_or_create_op_counter(const NFS3::nfs_fh3& key)
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

const char* usage()
{
    return "Arguments aren't supported. TODO: add description of OFWS Analyser";
}

IAnalyzer* create(const char* /*opts*/)
{
    return new OFWSAnalyzer();
}

void destroy(IAnalyzer* instance)
{
    delete instance;
}

NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

}
//------------------------------------------------------------------------------
