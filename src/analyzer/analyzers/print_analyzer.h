//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PRINT_ANALYZER_H
#define PRINT_ANALYZER_H
//------------------------------------------------------------------------------
#include <ostream>
#include <string>

#include "base_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

class PrintAnalyzer : public BaseAnalyzer
{
public:
    PrintAnalyzer(std::ostream& o):out(o)
    {
    }
    virtual ~PrintAnalyzer()
    {
    }

    virtual bool call_null       (const RPCOperation& operation);
    virtual bool call_getattr    (const RPCOperation& operation);
    virtual bool call_setattr    (const RPCOperation& operation);
    virtual bool call_lookup     (const RPCOperation& operation);
    virtual bool call_access     (const RPCOperation& operation);
    virtual bool call_readlink   (const RPCOperation& operation);
    virtual bool call_read       (const RPCOperation& operation);
    virtual bool call_write      (const RPCOperation& operation);
    virtual bool call_create     (const RPCOperation& operation);
    virtual bool call_mkdir      (const RPCOperation& operation);
    virtual bool call_symlink    (const RPCOperation& operation);
    virtual bool call_mknod      (const RPCOperation& operation);
    virtual bool call_remove     (const RPCOperation& operation);
    virtual bool call_rmdir      (const RPCOperation& operation);
    virtual bool call_rename     (const RPCOperation& operation);
    virtual bool call_link       (const RPCOperation& operation);
    virtual bool call_readdir    (const RPCOperation& operation);
    virtual bool call_readdirplus(const RPCOperation& operation);
    virtual bool call_fsstat     (const RPCOperation& operation);
    virtual bool call_fsinfo     (const RPCOperation& operation);
    virtual bool call_pathconf   (const RPCOperation& operation);
    virtual bool call_commit     (const RPCOperation& operation);
    virtual void print(std::ostream& out);

private:
    PrintAnalyzer(const PrintAnalyzer&);            // undefined
    PrintAnalyzer& operator=(const PrintAnalyzer&); // undefined

    std::ostream& out;
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PRINT_ANALYZER_H
//------------------------------------------------------------------------------
