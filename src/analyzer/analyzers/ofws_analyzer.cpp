//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Working Set (OFWS) analyzer. Enumerate the overall set of files accessed by clients.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <algorithm>
#include <iomanip>
#include <vector>

#include "ofws_analyzer.h"
#include "../../auxiliary/logger.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

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

bool OFWSAnalyzer::call_null(const RPCOperation& operation)
{
    //TRACE("NULL");
    return true;
}

bool OFWSAnalyzer::call_getattr(const RPCOperation& operation)
{
    //TRACE("GETATTR");
    const NFSPROC3_GETATTR& op = static_cast<const NFSPROC3_GETATTR&>(operation);
    const NFSPROC3_GETATTR::Arg& arg = op.get_arg();
    const NFSPROC3_GETATTR::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.object);
        (*i->second).inc(Proc::GETATTR);
    }
    return true;
}

bool OFWSAnalyzer::call_setattr(const RPCOperation& operation)
{
    //TRACE("SETATTR");
    const NFSPROC3_SETATTR& op = static_cast<const NFSPROC3_SETATTR&>(operation);
    const NFSPROC3_SETATTR::Arg& arg = op.get_arg();
    const NFSPROC3_SETATTR::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.object);
        (*i->second).inc(Proc::SETATTR);
    }
    return true;
}

bool OFWSAnalyzer::call_lookup(const RPCOperation& operation)
{
    //TRACE("LOOKUP");
    const NFSPROC3_LOOKUP& op = static_cast<const NFSPROC3_LOOKUP&>(operation);
//    const NFSPROC3_LOOKUP::Arg& arg = op.get_arg();
    const NFSPROC3_LOOKUP::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(res.resok.object);
        (*i->second).inc(Proc::LOOKUP);
    }
    return true;
}

bool OFWSAnalyzer::call_access(const RPCOperation& operation)
{
    //TRACE("ACCESS");
    const NFSPROC3_ACCESS& op = static_cast<const NFSPROC3_ACCESS&>(operation);
    const NFSPROC3_ACCESS::Arg& arg = op.get_arg();
    const NFSPROC3_ACCESS::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.object);
        (*i->second).inc(Proc::ACCESS);
    }
    return true;
}

bool OFWSAnalyzer::call_readlink(const RPCOperation& operation)
{
    //TRACE("READLINK");
    const NFSPROC3_READLINK& op = static_cast<const NFSPROC3_READLINK&>(operation);
    const NFSPROC3_READLINK::Arg& arg = op.get_arg();
    const NFSPROC3_READLINK::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.symlink);
        (*i->second).inc(Proc::READLINK);
    }
    return true;
}

bool OFWSAnalyzer::call_read(const RPCOperation& operation)
{
    //TRACE("READ");
    const NFSPROC3_READ& op = static_cast<const NFSPROC3_READ&>(operation);
    const NFSPROC3_READ::Arg& arg = op.get_arg();
    const NFSPROC3_READ::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.file);
        (*i->second).inc(Proc::READ);
    }
    return true;
}

bool OFWSAnalyzer::call_write(const RPCOperation& operation)
{
    //TRACE("WRITE");
    const NFSPROC3_WRITE& op = static_cast<const NFSPROC3_WRITE&>(operation);
    const NFSPROC3_WRITE::Arg& arg = op.get_arg();
    const NFSPROC3_WRITE::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.file);
        (*i->second).inc(Proc::WRITE);
    }
    return true;
}

bool OFWSAnalyzer::call_create(const RPCOperation& operation)
{
    //TRACE("CREATE");
    const NFSPROC3_CREATE& op = static_cast<const NFSPROC3_CREATE&>(operation);
//    const NFSPROC3_CREATE::Arg& arg = op.get_arg();
    const NFSPROC3_CREATE::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        if(res.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res.resok.obj.handle);
            (*i->second).inc(Proc::CREATE);
        }
    }
    return true;
}

bool OFWSAnalyzer::call_mkdir(const RPCOperation& operation)
{
    //TRACE("MKDIR");
    const NFSPROC3_MKDIR& op = static_cast<const NFSPROC3_MKDIR&>(operation);
//    const NFSPROC3_MKDIR::Arg& arg = op.get_arg();
    const NFSPROC3_MKDIR::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        if(res.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res.resok.obj.handle);
            (*i->second).inc(Proc::MKDIR);
        }
    }
    return true;
}

bool OFWSAnalyzer::call_symlink(const RPCOperation& operation)
{
    //TRACE("SYMLINK");
    const NFSPROC3_SYMLINK& op = static_cast<const NFSPROC3_SYMLINK&>(operation);
//    const NFSPROC3_SYMLINK::Arg& arg = op.get_arg();
    const NFSPROC3_SYMLINK::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        if(res.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res.resok.obj.handle);
            (*i->second).inc(Proc::SYMLINK);
        }
    }
    return true;
}

bool OFWSAnalyzer::call_mknod(const RPCOperation& operation)
{
    //TRACE("MKNOD");
    const NFSPROC3_MKNOD& op = static_cast<const NFSPROC3_MKNOD&>(operation);
//    const NFSPROC3_MKNOD::Arg& arg = op.get_arg();
    const NFSPROC3_MKNOD::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        if(res.resok.obj.handle_follows)
        {
            Iterator i = find_or_create_op_counter(res.resok.obj.handle);
            (*i->second).inc(Proc::MKNOD);
        }
    }
    return true;
}

bool OFWSAnalyzer::call_remove(const RPCOperation& operation)
{
    //TRACE("REMOVE");
    const NFSPROC3_REMOVE& op = static_cast<const NFSPROC3_REMOVE&>(operation);
    const NFSPROC3_REMOVE::Arg& arg = op.get_arg();
    const NFSPROC3_REMOVE::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.object.dir);
        (*i->second).inc(Proc::REMOVE);
    }
    return true;
}

bool OFWSAnalyzer::call_rmdir(const RPCOperation& operation)
{
    //TRACE("RMDIR");
    const NFSPROC3_RMDIR& op = static_cast<const NFSPROC3_RMDIR&>(operation);
    const NFSPROC3_RMDIR::Arg& arg = op.get_arg();
    const NFSPROC3_RMDIR::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.object.dir);
        (*i->second).inc(Proc::RMDIR);
    }
    return true;
}

bool OFWSAnalyzer::call_rename(const RPCOperation& operation)
{
    //TRACE("RENAME");
    const NFSPROC3_RENAME& op = static_cast<const NFSPROC3_RENAME&>(operation);
    const NFSPROC3_RENAME::Arg& arg = op.get_arg();
    const NFSPROC3_RENAME::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.from.dir);
        (*i->second).inc(Proc::RENAME);
    }
    return true;
}

bool OFWSAnalyzer::call_link(const RPCOperation& operation)
{
    //TRACE("LINK");
    const NFSPROC3_LINK& op = static_cast<const NFSPROC3_LINK&>(operation);
    const NFSPROC3_LINK::Arg& arg = op.get_arg();
    const NFSPROC3_LINK::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.file);
        (*i->second).inc(Proc::LINK);
    }
    return true;
}

bool OFWSAnalyzer::call_readdir(const RPCOperation& operation)
{
    //TRACE("READDIR");
    const NFSPROC3_READDIR& op = static_cast<const NFSPROC3_READDIR&>(operation);
    const NFSPROC3_READDIR::Arg& arg = op.get_arg();
    const NFSPROC3_READDIR::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.dir);
        (*i->second).inc(Proc::READDIR);
    }
    return true;
}

bool OFWSAnalyzer::call_readdirplus(const RPCOperation& operation)
{
    //TRACE("READDIRPLUS");
    const NFSPROC3_READDIRPLUS& op = static_cast<const NFSPROC3_READDIRPLUS&>(operation);
    const NFSPROC3_READDIRPLUS::Arg& arg = op.get_arg();
    const NFSPROC3_READDIRPLUS::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.dir);
        (*i->second).inc(Proc::READDIRPLUS);
    }
    return true;
}

bool OFWSAnalyzer::call_fsstat(const RPCOperation& operation)
{
    //TRACE("FSSTAT");
    const NFSPROC3_FSSTAT& op = static_cast<const NFSPROC3_FSSTAT&>(operation);
    const NFSPROC3_FSSTAT::Arg& arg = op.get_arg();
    const NFSPROC3_FSSTAT::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.fsroot);
        (*i->second).inc(Proc::FSSTAT);
    }
    return true;
}

bool OFWSAnalyzer::call_fsinfo(const RPCOperation& operation)
{
    //TRACE("FSINFO");
    const NFSPROC3_FSINFO& op = static_cast<const NFSPROC3_FSINFO&>(operation);
    const NFSPROC3_FSINFO::Arg& arg = op.get_arg();
    const NFSPROC3_FSINFO::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.fsroot);
        (*i->second).inc(Proc::FSINFO);
    }
    return true;
}

bool OFWSAnalyzer::call_pathconf(const RPCOperation& operation)
{
    //TRACE("PATHCONF");
    const NFSPROC3_PATHCONF& op = static_cast<const NFSPROC3_PATHCONF&>(operation);
    const NFSPROC3_PATHCONF::Arg& arg = op.get_arg();
    const NFSPROC3_PATHCONF::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.object);
        (*i->second).inc(Proc::PATHCONF);
    }
    return true;
}

bool OFWSAnalyzer::call_commit(const RPCOperation& operation)
{
    //TRACE("COMMIT");
    const NFSPROC3_COMMIT& op = static_cast<const NFSPROC3_COMMIT&>(operation);
    const NFSPROC3_COMMIT::Arg& arg = op.get_arg();
    const NFSPROC3_COMMIT::Res& res = op.get_res();

    if(res.status == nfsstat3::OK)
    {
        Iterator i = find_or_create_op_counter(arg.file);
        (*i->second).inc(Proc::COMMIT);
    }
    return true;
}

void OFWSAnalyzer::print(std::ostream& out)
{
    //TRACE("PRINT");
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
    out << "FileHandle," << "NFS Ops,";
    for(uint32_t j = 0; j < Proc::num; ++j)
    {
        out << Proc::Titles[j] << ',';
    }
    out << '\n';

    for(uint32_t i = 0; i != size; ++i)
    {
        Iterator& iterator = v[i];
        const OpCounter* opcounter = iterator->second;

        out << iterator->first << ',' << opcounter->get_total();
        for(uint32_t j = 0; j < Proc::num; ++j)
        {
            out << (*opcounter)[j] << ',';
        }
        out << '\n';
    }
}

OFWSAnalyzer::Iterator OFWSAnalyzer::find_or_create_op_counter(const nfs_fh3& key)
{
    std::stringstream s;
    s << key;
    //TRACE("FIND_OR_CREATE KEY = %s", s.str().c_str());
    Iterator i = ofws_stat.find(key);
    if(i == ofws_stat.end())
    {
        //TRACE("CREATE op_counter nfs_fh3: %s", s.str().c_str()); 
        Inserted ins = ofws_stat.insert(Pair(key, new OpCounter()));
        if(ins.second == false)
            throw int();
        i = ins.first;
    }
    return i;
}

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
