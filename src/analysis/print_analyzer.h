//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
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
#ifndef PRINT_ANALYZER_H
#define PRINT_ANALYZER_H
//------------------------------------------------------------------------------
#include <ostream>

#include "analysis/ianalyzer.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class PrintAnalyzer : public IAnalyzer
{
public:
    PrintAnalyzer(std::ostream& o) : out(o)
    {
    }
    ~PrintAnalyzer()
    {
    }

    void null(const struct RPCProcedure* proc,
            const struct NULLargs* args,
            const struct NULLres* res) override final;
    void getattr3(const struct RPCProcedure* proc,
            const struct GETATTR3args* args,
            const struct GETATTR3res* res) override final;
    void setattr3(const struct RPCProcedure* proc,
            const struct SETATTR3args* args,
            const struct SETATTR3res* res) override final;
    void lookup3(const struct RPCProcedure* proc,
            const struct LOOKUP3args* args,
            const struct LOOKUP3res* res) override final;
    void access3(const struct RPCProcedure* proc,
            const struct ACCESS3args* args,
            const struct ACCESS3res* res) override final;
    void readlink3(const struct RPCProcedure* proc,
            const struct READLINK3args* args,
            const struct READLINK3res* res) override final;
    void read3(const struct RPCProcedure* proc,
            const struct READ3args* args,
            const struct READ3res* res) override final;
    void write3(const struct RPCProcedure* proc,
            const struct WRITE3args* args,
            const struct WRITE3res* res) override final;
    void create3(const struct RPCProcedure* proc,
            const struct CREATE3args* args,
            const struct CREATE3res* res) override final;
    void mkdir3(const struct RPCProcedure* proc,
            const struct MKDIR3args* args,
            const struct MKDIR3res* res) override final;
    void symlink3(const struct RPCProcedure* proc,
            const struct SYMLINK3args* args,
            const struct SYMLINK3res* res) override final;
    void mknod3(const struct RPCProcedure* proc,
            const struct MKNOD3args* args,
            const struct MKNOD3res* res) override final;
    void remove3(const struct RPCProcedure* proc,
            const struct REMOVE3args* args,
            const struct REMOVE3res* res) override final;
    void rmdir3(const struct RPCProcedure* proc,
            const struct RMDIR3args* args,
            const struct RMDIR3res* res) override final;
    void rename3(const struct RPCProcedure* proc,
            const struct RENAME3args* args,
            const struct RENAME3res* res) override final;
    void link3(const struct RPCProcedure* proc,
            const struct LINK3args* args,
            const struct LINK3res* res) override final;
    void readdir3(const struct RPCProcedure* proc,
            const struct READDIR3args* args,
            const struct READDIR3res* res) override final;
    void readdirplus3(const struct RPCProcedure* proc,
            const struct READDIRPLUS3args* args,
            const struct READDIRPLUS3res* res) override final;
    void fsstat3(const struct RPCProcedure* proc,
            const struct FSSTAT3args* args,
            const struct FSSTAT3res* res) override final;
    void fsinfo3(const struct RPCProcedure* proc,
            const struct FSINFO3args* args,
            const struct FSINFO3res* res) override final;
    void pathconf3(const struct RPCProcedure* proc,
            const struct PATHCONF3args* args,
            const struct PATHCONF3res* res) override final;
    void commit3(const struct RPCProcedure* proc,
            const struct COMMIT3args* args,
            const struct COMMIT3res* res) override final;

/*
    void null(const struct RPCProcedure* proc,
            const struct rpcgen::NULL3args* args,
            const struct rpcgen::NULL3res* res) override final;
    void getattr3(const struct RPCProcedure* proc,
            const struct rpcgen::GETATTR3args* args,
            const struct rpcgen::GETATTR3res* res) override final;
    void setattr3(const struct RPCProcedure* proc,
            const struct rpcgen::SETATTR3args* args,
            const struct rpcgen::SETATTR3res* res) override final;
    void lookup3(const struct RPCProcedure* proc,
            const struct rpcgen::LOOKUP3args* args,
            const struct rpcgen::LOOKUP3res* res) override final;
    void access3(const struct RPCProcedure* proc,
            const struct rpcgen::ACCESS3args* args,
            const struct rpcgen::ACCESS3res* res) override final;
    void readlink3(const struct RPCProcedure* proc,
            const struct rpcgen::READLINK3args* args,
            const struct rpcgen::READLINK3res* res) override final;
    void read3(const struct RPCProcedure* proc,
            const struct rpcgen::READ3args* args,
            const struct rpcgen::READ3res* res) override final;
    void write3(const struct RPCProcedure* proc,
            const struct rpcgen::WRITE3args* args,
            const struct rpcgen::WRITE3res* res) override final;
    void create3(const struct RPCProcedure* proc,
            const struct rpcgen::CREATE3args* args,
            const struct rpcgen::CREATE3res* res) override final;
    void mkdir3(const struct RPCProcedure* proc,
            const struct rpcgen::MKDIR3args* args,
            const struct rpcgen::MKDIR3res* res) override final;
    void symlink3(const struct RPCProcedure* proc,
            const struct rpcgen::SYMLINK3args* args,
            const struct rpcgen::SYMLINK3res* res) override final;
    void mknod3(const struct RPCProcedure* proc,
            const struct rpcgen::MKNOD3args* args,
            const struct rpcgen::MKNOD3res* res) override final;
    void remove3(const struct RPCProcedure* proc,
            const struct rpcgen::REMOVE3args* args,
            const struct rpcgen::REMOVE3res* res) override final;
    void rmdir3(const struct RPCProcedure* proc,
            const struct rpcgen::RMDIR3args* args,
            const struct rpcgen::RMDIR3res* res) override final;
    void rename3(const struct RPCProcedure* proc,
            const struct rpcgen::RENAME3args* args,
            const struct rpcgen::RENAME3res* res) override final;
    void link3(const struct RPCProcedure* proc,
            const struct rpcgen::LINK3args* args,
            const struct rpcgen::LINK3res* res) override final;
    void readdir3(const struct RPCProcedure* proc,
            const struct rpcgen::READDIR3args* args,
            const struct rpcgen::READDIR3res* res) override final;
    void readdirplus3(const struct RPCProcedure* proc,
            const struct rpcgen::READDIRPLUS3args* args,
            const struct rpcgen::READDIRPLUS3res* res) override final;
    void fsstat3(const struct RPCProcedure* proc,
            const struct rpcgen::FSSTAT3args* args,
            const struct rpcgen::FSSTAT3res* res) override final;
    void fsinfo3(const struct RPCProcedure* proc,
            const struct rpcgen::FSINFO3args* args,
            const struct rpcgen::FSINFO3res* res) override final;
    void pathconf3(const struct RPCProcedure* proc,
            const struct rpcgen::PATHCONF3args* args,
            const struct rpcgen::PATHCONF3res* res) override final;
    void commit3(const struct RPCProcedure* proc,
            const struct rpcgen::COMMIT3args* args,
            const struct rpcgen::COMMIT3res* res) override final;
*/

    void null(const struct RPCProcedure*      proc,
              const struct rpcgen::NULL4args* args,
              const struct rpcgen::NULL4res*  res) override final;

    void compound4(const struct RPCProcedure*          proc,
                   const struct rpcgen::COMPOUND4args* args,
                   const struct rpcgen::COMPOUND4res*  res) override final;

    void flush_statistics() override final;

private:
    PrintAnalyzer(const PrintAnalyzer&)            = delete;
    PrintAnalyzer& operator=(const PrintAnalyzer&) = delete;

    std::ostream& out;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//PRINT_ANALYZER_H
//------------------------------------------------------------------------------
