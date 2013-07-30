//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Analyzers storage. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <list>
#include <vector>

#include "nfs3/nfs_operation.h"
#include "analyzers/base_analyzer.h"
//------------------------------------------------------------------------------
using NST::analyzer::analyzers::BaseAnalyzer;
using NST::analyzer::NFS3::Proc;
using NST::analyzer::RPC::RPCOperation;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class Analyzers
{
    typedef std::list<BaseAnalyzer*> Storage;

    typedef bool (BaseAnalyzer::*Method)(const RPCOperation& operation);
public:
    Analyzers()
    {
        methods.resize(Proc::num);

        methods[Proc::NFS_NULL]     = &BaseAnalyzer::call_null;
        methods[Proc::GETATTR]      = &BaseAnalyzer::call_getattr;
        methods[Proc::SETATTR]      = &BaseAnalyzer::call_setattr;
        methods[Proc::LOOKUP]       = &BaseAnalyzer::call_lookup;
        methods[Proc::ACCESS]       = &BaseAnalyzer::call_access;
        methods[Proc::READLINK]     = &BaseAnalyzer::call_readlink;
        methods[Proc::READ]         = &BaseAnalyzer::call_read;
        methods[Proc::WRITE]        = &BaseAnalyzer::call_write;
        methods[Proc::CREATE]       = &BaseAnalyzer::call_create;
        methods[Proc::MKDIR]        = &BaseAnalyzer::call_mkdir;
        methods[Proc::SYMLINK]      = &BaseAnalyzer::call_symlink;
        methods[Proc::MKNOD]        = &BaseAnalyzer::call_mknod;
        methods[Proc::REMOVE]       = &BaseAnalyzer::call_remove;
        methods[Proc::RMDIR]        = &BaseAnalyzer::call_rmdir;
        methods[Proc::RENAME]       = &BaseAnalyzer::call_rename;
        methods[Proc::LINK]         = &BaseAnalyzer::call_link;
        methods[Proc::READDIR]      = &BaseAnalyzer::call_readdir;
        methods[Proc::READDIRPLUS]  = &BaseAnalyzer::call_readdirplus;
        methods[Proc::FSSTAT]       = &BaseAnalyzer::call_fsstat;
        methods[Proc::FSINFO]       = &BaseAnalyzer::call_fsinfo;
        methods[Proc::PATHCONF]     = &BaseAnalyzer::call_pathconf;
        methods[Proc::COMMIT]       = &BaseAnalyzer::call_commit;
    }
    ~Analyzers()
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            delete *i;
        }
    }

    void add(BaseAnalyzer* analyzer)
    {
        analyzers.push_back(analyzer);
    }

    bool call(const RPCOperation& operation)
    {
        const uint32_t procedure = operation.procedure();
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            ((*i)->*methods[procedure])(operation);
        }
        return true;
    }
    void print(std::ostream& out)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->print(out);
        }
    }

private:
    Storage analyzers;
    std::vector<Method> methods;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
