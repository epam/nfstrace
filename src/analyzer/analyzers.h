//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Analyzers storage. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <list>

#include "../controller/running_status.h"
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
public:
    Analyzers()
    {
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

    bool call_null(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_null(session);
        }
        return true;
    }
    bool call_getattr(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_getattr(session);
        }
        return true;
    }
    bool call_setattr(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_setattr(session);
        }
        return true;
    }
    bool call_lookup(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_lookup(session);
        }
        return true;
    }
    bool call_access(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_access(session);
        }
        return true;
    }
    bool call_readlink(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_readlink(session);
        }
        return true;
    }
    bool call_read(const Session& session, const ReadArgs& ra)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_read(session, ra);
        }
        return true;
    }
    bool call_write(const Session& session, const WriteArgs& wa)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_write(session, wa);
        }
        return true;
    }
    virtual bool call_create(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_create(session);
        }
        return true;
    }
    virtual bool call_mkdir(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_mkdir(session);
        }
        return true;
    }
    virtual bool call_symlink(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_symlink(session);
        }
        return true;
    }
    virtual bool call_mknod(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_mknod(session);
        }
        return true;
    }
    virtual bool call_remove(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_remove(session);
        }
        return true;
    }
    virtual bool call_rmdir(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_rmdir(session);
        }
        return true;
    }
    virtual bool call_rename(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_rename(session);
        }
        return true;
    }
    virtual bool call_link(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_link(session);
        }
        return true;
    }
    virtual bool call_readdir(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_readdir(session);
        }
        return true;
    }
    virtual bool call_readdirplus(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_readdirplus(session);
        }
        return true;
    }
    virtual bool call_fsstat(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_fsstat(session);
        }
        return true;
    }
    virtual bool call_fsinfo(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_fsinfo(session);
        }
        return true;
    }
    virtual bool call_pathconf(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_pathconf(session);
        }
        return true;
    }
    virtual bool call_commit(const Session& session/*, const TypeData() data*/)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->call_commit(session);
        }
        return true;
    }

private:
    Storage analyzers;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
