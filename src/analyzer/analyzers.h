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

#include "../controller/running_status.h"
#include "../filter/nfs/nfs_operation.h"
#include "../filter/nfs/nfs_struct.h"
#include "base_analyzer.h"
#include "nfs_data.h"
//------------------------------------------------------------------------------
using namespace NST::filter::NFS3;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class Analyzers
{
    typedef std::list<BaseAnalyzer*> Storage;
    typedef NFSData::Session Session;
    typedef bool (BaseAnalyzer::*Method)(const Session& session, const NFSOperation& operation);
public:
    Analyzers()
    {
        methods.resize(22);

        methods[0] = &BaseAnalyzer::call_null;
        methods[1] = &BaseAnalyzer::call_getattr;
        //methods[2] = &BaseAnalyzer::call_setattr;
        methods[3] = &BaseAnalyzer::call_lookup;
        methods[4] = &BaseAnalyzer::call_access;
        methods[5] = &BaseAnalyzer::call_readlink;
        methods[6] = &BaseAnalyzer::call_read;
        methods[7] = &BaseAnalyzer::call_write;
        //methods[8] = &BaseAnalyzer::call_create;
        //methods[9] = &BaseAnalyzer::call_mkdir;
        //methods[10] = &BaseAnalyzer::call_symlink;
        //methods[11] = &BaseAnalyzer::call_mknod;
        methods[12] = &BaseAnalyzer::call_remove;
        methods[13] = &BaseAnalyzer::call_rmdir;
        methods[14] = &BaseAnalyzer::call_rename;
        methods[15] = &BaseAnalyzer::call_link;
        methods[16] = &BaseAnalyzer::call_readdir;
        methods[17] = &BaseAnalyzer::call_readdirplus;
        methods[18] = &BaseAnalyzer::call_fsstat;
        methods[19] = &BaseAnalyzer::call_fsinfo;
        methods[20] = &BaseAnalyzer::call_pathconf;
        methods[21] = &BaseAnalyzer::call_commit;
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

    bool call_setattr(const Session& session/*, const NFSOperation& operation*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_setattr(session);
        }
        return true;
    }
    virtual bool call_create(const Session& session/*, const NFSOperation& operation*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_create(session);
        }
        return true;
    }
    virtual bool call_mkdir(const Session& session/*, const NFSOperation& operation*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_mkdir(session);
        }
        return true;
    }
    virtual bool call_symlink(const Session& session/*, const NFSOperation& operation*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_symlink(session);
        }
        return true;
    }
    virtual bool call_mknod(const Session& session/*, const NFSOperation& operation*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_mknod(session);
        }
        return true;
    }
    virtual bool call(const Session& session, const NFSOperation& operation)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            ((*i)->*methods[operation])(session, operation);
        }
        return true;
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
