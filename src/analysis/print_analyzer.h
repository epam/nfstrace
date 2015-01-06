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

#include "api/plugin_api.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

namespace NFS3  = NST::API::NFS3;
namespace NFS4  = NST::API::NFS4;
namespace NFS41 = NST::API::NFS41;

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
              const struct NFS3::NULL3args*,
              const struct NFS3::NULL3res*) override final;
    void getattr3(const struct RPCProcedure*         proc,
                  const struct NFS3::GETATTR3args* args,
                  const struct NFS3::GETATTR3res*  res) override final;
    void setattr3(const struct RPCProcedure*         proc,
                  const struct NFS3::SETATTR3args* args,
                  const struct NFS3::SETATTR3res*  res) override final;
    void lookup3(const struct RPCProcedure*        proc,
                 const struct NFS3::LOOKUP3args* args,
                 const struct NFS3::LOOKUP3res*  res) override final;
    void access3(const struct RPCProcedure*        proc,
                 const struct NFS3::ACCESS3args* args,
                 const struct NFS3::ACCESS3res*  res) override final;
    void readlink3(const struct RPCProcedure*          proc,
                   const struct NFS3::READLINK3args* args,
                   const struct NFS3::READLINK3res*  res) override final;
    void read3(const struct RPCProcedure*      proc,
               const struct NFS3::READ3args* args,
               const struct NFS3::READ3res*  res) override final;
    void write3(const struct RPCProcedure*       proc,
                const struct NFS3::WRITE3args* args,
                const struct NFS3::WRITE3res*  res) override final;
    void create3(const struct RPCProcedure*        proc,
                 const struct NFS3::CREATE3args* args,
                 const struct NFS3::CREATE3res*  res) override final;
    void mkdir3(const struct RPCProcedure*       proc,
                const struct NFS3::MKDIR3args* args,
                const struct NFS3::MKDIR3res*  res) override final;
    void symlink3(const struct RPCProcedure*         proc,
                  const struct NFS3::SYMLINK3args* args,
                  const struct NFS3::SYMLINK3res*  res) override final;
    void mknod3(const struct RPCProcedure*       proc,
                const struct NFS3::MKNOD3args* args,
                const struct NFS3::MKNOD3res*  res) override final;
    void remove3(const struct RPCProcedure*        proc,
                 const struct NFS3::REMOVE3args* args,
                 const struct NFS3::REMOVE3res*  res) override final;
    void rmdir3(const struct RPCProcedure*       proc,
                const struct NFS3::RMDIR3args* args,
                const struct NFS3::RMDIR3res*  res) override final;
    void rename3(const struct RPCProcedure*        proc,
                 const struct NFS3::RENAME3args* args,
                 const struct NFS3::RENAME3res*  res) override final;
    void link3(const struct RPCProcedure*      proc,
               const struct NFS3::LINK3args* args,
               const struct NFS3::LINK3res*  res) override final;
    void readdir3(const struct RPCProcedure*         proc,
                  const struct NFS3::READDIR3args* args,
                  const struct NFS3::READDIR3res*  res) override final;
    void readdirplus3(const struct RPCProcedure*             proc,
                      const struct NFS3::READDIRPLUS3args* args,
                      const struct NFS3::READDIRPLUS3res*  res) override final;
    void fsstat3(const struct RPCProcedure*        proc,
                 const struct NFS3::FSSTAT3args* args,
                 const struct NFS3::FSSTAT3res*  res) override final;
    void fsinfo3(const struct RPCProcedure*        proc,
                 const struct NFS3::FSINFO3args* args,
                 const struct NFS3::FSINFO3res*  res) override final;
    void pathconf3(const struct RPCProcedure*          proc,
                   const struct NFS3::PATHCONF3args* args,
                   const struct NFS3::PATHCONF3res*  res) override final;
    void commit3(const struct RPCProcedure*        proc,
                 const struct NFS3::COMMIT3args* args,
                 const struct NFS3::COMMIT3res*  res) override final;

    void null(const struct RPCProcedure*      proc,
              const struct NFS4::NULL4args* args,
              const struct NFS4::NULL4res*  res) override final;
    void compound4(const struct RPCProcedure*          proc,
                   const struct NFS4::COMPOUND4args* args,
                   const struct NFS4::COMPOUND4res*  res) override final;

    void nfs4_operation(const struct NFS4::nfs_argop4*                 op);
    void nfs4_operation(const struct NFS4::nfs_resop4*                 op);

    void nfs4_operation(const struct NFS4::ACCESS4args*              args);
    void nfs4_operation(const struct NFS4::ACCESS4res*               res );

    void nfs4_operation(const struct NFS4::CLOSE4args*               args);
    void nfs4_operation(const struct NFS4::CLOSE4res*                res );

    void nfs4_operation(const struct NFS4::COMMIT4args*              args);
    void nfs4_operation(const struct NFS4::COMMIT4res*               res );

    void nfs4_operation(const struct NFS4::CREATE4args*              args);
    void nfs4_operation(const struct NFS4::CREATE4res*               res );

    void nfs4_operation(const struct NFS4::DELEGPURGE4args*          args);
    void nfs4_operation(const struct NFS4::DELEGPURGE4res*           res );

    void nfs4_operation(const struct NFS4::DELEGRETURN4args*         args);
    void nfs4_operation(const struct NFS4::DELEGRETURN4res*          res );

    void nfs4_operation(const struct NFS4::GETATTR4args*             args);
    void nfs4_operation(const struct NFS4::GETATTR4res*              res );

    void nfs4_operation(const struct NFS4::LINK4args*                args);
    void nfs4_operation(const struct NFS4::LINK4res*                 res );

    void nfs4_operation(const struct NFS4::LOCK4args*                args);
    void nfs4_operation(const struct NFS4::LOCK4res*                 res );

    void nfs4_operation(const struct NFS4::LOCKT4args*               args);
    void nfs4_operation(const struct NFS4::LOCKT4res*                res );

    void nfs4_operation(const struct NFS4::LOCKU4args*               args);
    void nfs4_operation(const struct NFS4::LOCKU4res*                res );

    void nfs4_operation(const struct NFS4::LOOKUP4args*              args);
    void nfs4_operation(const struct NFS4::LOOKUP4res*               res );

    void nfs4_operation(const struct NFS4::NVERIFY4args*             args);
    void nfs4_operation(const struct NFS4::NVERIFY4res*              res );

    void nfs4_operation(const struct NFS4::OPEN4args*                args);
    void nfs4_operation(const struct NFS4::OPEN4res*                 res );

    void nfs4_operation(const struct NFS4::OPENATTR4args*            args);
    void nfs4_operation(const struct NFS4::OPENATTR4res*             res );

    void nfs4_operation(const struct NFS4::OPEN_CONFIRM4args*        args);
    void nfs4_operation(const struct NFS4::OPEN_CONFIRM4res*         res );

    void nfs4_operation(const struct NFS4::OPEN_DOWNGRADE4args*      args);
    void nfs4_operation(const struct NFS4::OPEN_DOWNGRADE4res*       res );

    void nfs4_operation(const struct NFS4::PUTFH4args*               args);
    void nfs4_operation(const struct NFS4::PUTFH4res*                res );

    void nfs4_operation(const struct NFS4::READ4args*                args);
    void nfs4_operation(const struct NFS4::READ4res*                 res );

    void nfs4_operation(const struct NFS4::READDIR4args*             args);
    void nfs4_operation(const struct NFS4::READDIR4res*              res );

    void nfs4_operation(const struct NFS4::REMOVE4args*              args);
    void nfs4_operation(const struct NFS4::REMOVE4res*               res );

    void nfs4_operation(const struct NFS4::RENAME4args*              args);
    void nfs4_operation(const struct NFS4::RENAME4res*               res );

    void nfs4_operation(const struct NFS4::RENEW4args*               args);
    void nfs4_operation(const struct NFS4::RENEW4res*                res );

    void nfs4_operation(const struct NFS4::SECINFO4args*             args);
    void nfs4_operation(const struct NFS4::SECINFO4res*              res );

    void nfs4_operation(const struct NFS4::SETATTR4args*             args);
    void nfs4_operation(const struct NFS4::SETATTR4res*              res );

    void nfs4_operation(const struct NFS4::SETCLIENTID4args*         args);
    void nfs4_operation(const struct NFS4::SETCLIENTID4res*          res );

    void nfs4_operation(const struct NFS4::SETCLIENTID_CONFIRM4args* args);
    void nfs4_operation(const struct NFS4::SETCLIENTID_CONFIRM4res*  res );

    void nfs4_operation(const struct NFS4::VERIFY4args*              args);
    void nfs4_operation(const struct NFS4::VERIFY4res*               res );

    void nfs4_operation(const struct NFS4::WRITE4args*               args);
    void nfs4_operation(const struct NFS4::WRITE4res*                res );

    void nfs4_operation(const struct NFS4::RELEASE_LOCKOWNER4args*   args);
    void nfs4_operation(const struct NFS4::RELEASE_LOCKOWNER4res*    res );

    void nfs4_operation(const struct NFS4::GET_DIR_DELEGATION4args*  args);
    void nfs4_operation(const struct NFS4::GET_DIR_DELEGATION4res*   res );

    void nfs4_operation(const struct NFS4::GETFH4res*                 res);

    void nfs4_operation(const struct NFS4::LOOKUPP4res*               res);

    void nfs4_operation(const struct NFS4::PUTPUBFH4res*              res);

    void nfs4_operation(const struct NFS4::PUTROOTFH4res*             res);

    void nfs4_operation(const struct NFS4::READLINK4res*              res);

    void nfs4_operation(const struct NFS4::RESTOREFH4res*             res);

    void nfs4_operation(const struct NFS4::SAVEFH4res*                res);

    void nfs4_operation(const struct NFS4::ILLEGAL4res*               res);

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
