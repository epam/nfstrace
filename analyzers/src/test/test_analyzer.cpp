//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Example of usage Plugin-API.
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
#include <iostream>
#include <string>

#include <api/plugin_api.h> // include plugin development definitions
//------------------------------------------------------------------------------
class TestAnalyzer : public IAnalyzer
{
public:
    TestAnalyzer(const char* opts)
        : options(opts)
    {
        std::cout << "TestAnalyzer::TestAnalyzer(" << options << ')' << std::endl;
    }

    ~TestAnalyzer()
    {
        std::cout << "TestAnalyzer::~TestAnalyzer()" << std::endl;
    }

    // NFSv3 procedures

    void null(const RPCProcedure* /*proc*/,
              const struct NFS3::NULL3args* /*args*/,
              const struct NFS3::NULL3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::null()" << std::endl;
    }

    void getattr3(const RPCProcedure* /*proc*/,
                  const struct NFS3::GETATTR3args* /*args*/,
                  const struct NFS3::GETATTR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::getattr3()" << std::endl;
    }

    void setattr3(const RPCProcedure* /*proc*/,
                  const struct NFS3::SETATTR3args* /*args*/,
                  const struct NFS3::SETATTR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::setattr3()" << std::endl;
    }

    void lookup3(const RPCProcedure* /*proc*/,
                 const struct NFS3::LOOKUP3args* /*args*/,
                 const struct NFS3::LOOKUP3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::lookup3()" << std::endl;
    }

    void access3(const RPCProcedure* /*proc*/,
                 const struct NFS3::ACCESS3args* /*args*/,
                 const struct NFS3::ACCESS3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::access3()" << std::endl;
    }

    void readlink3(const RPCProcedure* /*proc*/,
                   const struct NFS3::READLINK3args* /*args*/,
                   const struct NFS3::READLINK3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::readlink3()" << std::endl;
    }

    void read3(const RPCProcedure* /*proc*/,
               const struct NFS3::READ3args* /*args*/,
               const struct NFS3::READ3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::read3()" << std::endl;
    }

    void write3(const RPCProcedure* /*proc*/,
                const struct NFS3::WRITE3args* /*args*/,
                const struct NFS3::WRITE3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::write3()" << std::endl;
    }

    void create3(const RPCProcedure* /*proc*/,
                 const struct NFS3::CREATE3args* /*args*/,
                 const struct NFS3::CREATE3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::create3()" << std::endl;
    }

    void mkdir3(const RPCProcedure* /*proc*/,
                const struct NFS3::MKDIR3args* /*args*/,
                const struct NFS3::MKDIR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::mkdir3()" << std::endl;
    }

    void symlink3(const RPCProcedure* /*proc*/,
                  const struct NFS3::SYMLINK3args* /*args*/,
                  const struct NFS3::SYMLINK3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::symlink3()" << std::endl;
    }

    void mknod3(const RPCProcedure* /*proc*/,
                const struct NFS3::MKNOD3args* /*args*/,
                const struct NFS3::MKNOD3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::mknod3()" << std::endl;
    }

    void remove3(const RPCProcedure* /*proc*/,
                 const struct NFS3::REMOVE3args* /*args*/,
                 const struct NFS3::REMOVE3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::remove3()" << std::endl;
    }

    void rmdir3(const RPCProcedure* /*proc*/,
                const struct NFS3::RMDIR3args* /*args*/,
                const struct NFS3::RMDIR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::rmdir3()" << std::endl;
    }

    void rename3(const RPCProcedure* /*proc*/,
                 const struct NFS3::RENAME3args* /*args*/,
                 const struct NFS3::RENAME3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::rename3()" << std::endl;
    }

    void link3(const RPCProcedure* /*proc*/,
               const struct NFS3::LINK3args* /*args*/,
               const struct NFS3::LINK3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::link3()" << std::endl;
    }

    void readdir3(const RPCProcedure* /*proc*/,
                  const struct NFS3::READDIR3args* /*args*/,
                  const struct NFS3::READDIR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::readdir3()" << std::endl;
    }

    void readdirplus3(const RPCProcedure* /*proc*/,
                      const struct NFS3::READDIRPLUS3args* /*args*/,
                      const struct NFS3::READDIRPLUS3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::readdirplus3()" << std::endl;
    }

    void fsstat3(const RPCProcedure* /*proc*/,
                 const struct NFS3::FSSTAT3args* /*args*/,
                 const struct NFS3::FSSTAT3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::fsstat3()" << std::endl;
    }

    void fsinfo3(const RPCProcedure* /*proc*/,
                 const struct NFS3::FSINFO3args* /*args*/,
                 const struct NFS3::FSINFO3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::fsinfo3()" << std::endl;
    }

    void pathconf3(const RPCProcedure* /*proc*/,
                   const struct NFS3::PATHCONF3args* /*args*/,
                   const struct NFS3::PATHCONF3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::pathconf3()" << std::endl;
    }

    void commit3(const RPCProcedure* /*proc*/,
                 const struct NFS3::COMMIT3args* /*args*/,
                 const struct NFS3::COMMIT3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::commit3()" << std::endl;
    }

    // NFSv4.0 procedures

    void null4(const RPCProcedure* /*proc*/,
               const struct NFS4::NULL4args* /*args*/,
               const struct NFS4::NULL4res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::null4()" << std::endl;
    }
    void compound4(const RPCProcedure* /*proc*/,
                   const struct NFS4::COMPOUND4args* /*args*/,
                   const struct NFS4::COMPOUND4res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::compound4()" << std::endl;
    }

    // NFSv4.0 operations

    void access40(const RPCProcedure* /* proc */,
                  const struct NFS4::ACCESS4args* /* args */,
                  const struct NFS4::ACCESS4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void close40(const RPCProcedure* /* proc */,
                 const struct NFS4::CLOSE4args* /* args */,
                 const struct NFS4::CLOSE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void commit40(const RPCProcedure* /* proc */,
                  const struct NFS4::COMMIT4args* /* args */,
                  const struct NFS4::COMMIT4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void create40(const RPCProcedure* /* proc */,
                  const struct NFS4::CREATE4args* /* args */,
                  const struct NFS4::CREATE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void delegpurge40(const RPCProcedure* /* proc */,
                      const struct NFS4::DELEGPURGE4args* /* args */,
                      const struct NFS4::DELEGPURGE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void delegreturn40(const RPCProcedure* /* proc */,
                       const struct NFS4::DELEGRETURN4args* /* args */,
                       const struct NFS4::DELEGRETURN4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void getattr40(const RPCProcedure* /* proc */,
                   const struct NFS4::GETATTR4args* /* args */,
                   const struct NFS4::GETATTR4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void getfh40(const RPCProcedure* /* proc */,
                 const struct NFS4::GETFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void link40(const RPCProcedure* /* proc */,
                const struct NFS4::LINK4args* /* args */,
                const struct NFS4::LINK4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void lock40(const RPCProcedure* /* proc */,
                const struct NFS4::LOCK4args* /* args */,
                const struct NFS4::LOCK4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void lockt40(const RPCProcedure* /* proc */,
                 const struct NFS4::LOCKT4args* /* args */,
                 const struct NFS4::LOCKT4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void locku40(const RPCProcedure* /* proc */,
                 const struct NFS4::LOCKU4args* /* args */,
                 const struct NFS4::LOCKU4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void lookup40(const RPCProcedure* /* proc */,
                  const struct NFS4::LOOKUP4args* /* args */,
                  const struct NFS4::LOOKUP4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void lookupp40(const RPCProcedure* /* proc */,
                   const struct NFS4::LOOKUPP4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void nverify40(const RPCProcedure* /* proc */,
                   const struct NFS4::NVERIFY4args* /* args */,
                   const struct NFS4::NVERIFY4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void open40(const RPCProcedure* /* proc */,
                const struct NFS4::OPEN4args* /* args */,
                const struct NFS4::OPEN4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void openattr40(const RPCProcedure* /* proc */,
                    const struct NFS4::OPENATTR4args* /* args */,
                    const struct NFS4::OPENATTR4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void open_confirm40(const RPCProcedure* /* proc */,
                        const struct NFS4::OPEN_CONFIRM4args* /* args */,
                        const struct NFS4::OPEN_CONFIRM4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void open_downgrade40(const RPCProcedure* /* proc */,
                          const struct NFS4::OPEN_DOWNGRADE4args* /* args */,
                          const struct NFS4::OPEN_DOWNGRADE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void putfh40(const RPCProcedure* /* proc */,
                 const struct NFS4::PUTFH4args* /* args */,
                 const struct NFS4::PUTFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void putpubfh40(const RPCProcedure* /* proc */,
                    const struct NFS4::PUTPUBFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void putrootfh40(const RPCProcedure* /* proc */,
                     const struct NFS4::PUTROOTFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void read40(const RPCProcedure* /* proc */,
                const struct NFS4::READ4args* /* args */,
                const struct NFS4::READ4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void readdir40(const RPCProcedure* /* proc */,
                   const struct NFS4::READDIR4args* /* args */,
                   const struct NFS4::READDIR4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void readlink40(const RPCProcedure* /* proc */,
                    const struct NFS4::READLINK4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void remove40(const RPCProcedure* /* proc */,
                  const struct NFS4::REMOVE4args* /* args */,
                  const struct NFS4::REMOVE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void rename40(const RPCProcedure* /* proc */,
                  const struct NFS4::RENAME4args* /* args */,
                  const struct NFS4::RENAME4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void renew40(const RPCProcedure* /* proc */,
                 const struct NFS4::RENEW4args* /* args */,
                 const struct NFS4::RENEW4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void restorefh40(const RPCProcedure* /* proc */,
                     const struct NFS4::RESTOREFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void savefh40(const RPCProcedure* /* proc */,
                  const struct NFS4::SAVEFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void secinfo40(const RPCProcedure* /* proc */,
                   const struct NFS4::SECINFO4args* /* args */,
                   const struct NFS4::SECINFO4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void setattr40(const RPCProcedure* /* proc */,
                   const struct NFS4::SETATTR4args* /* args */,
                   const struct NFS4::SETATTR4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void setclientid40(const RPCProcedure* /* proc */,
                       const struct NFS4::SETCLIENTID4args* /* args */,
                       const struct NFS4::SETCLIENTID4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void setclientid_confirm40(const RPCProcedure* /* proc */,
                               const struct NFS4::SETCLIENTID_CONFIRM4args* /* args */,
                               const struct NFS4::SETCLIENTID_CONFIRM4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void verify40(const RPCProcedure* /* proc */,
                  const struct NFS4::VERIFY4args* /* args */,
                  const struct NFS4::VERIFY4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void write40(const RPCProcedure* /* proc */,
                 const struct NFS4::WRITE4args* /* args */,
                 const struct NFS4::WRITE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void release_lockowner40(const RPCProcedure* /* proc */,
                             const struct NFS4::RELEASE_LOCKOWNER4args* /* args */,
                             const struct NFS4::RELEASE_LOCKOWNER4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void get_dir_delegation40(const RPCProcedure* /* proc */,
                              const struct NFS4::GET_DIR_DELEGATION4args* /* args */,
                              const struct NFS4::GET_DIR_DELEGATION4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void illegal40(const RPCProcedure* /* proc */,
                   const struct NFS4::ILLEGAL4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }

    // NFSv4.1 procedures

    void compound41(const RPCProcedure* /*proc*/,
                    const struct NFS41::COMPOUND4args* /*args*/,
                    const struct NFS41::COMPOUND4res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::compound4()" << std::endl;
    }

    // NFSv4.1 operations

    void access41(const RPCProcedure* /* proc */,
                  const struct NFS41::ACCESS4args* /* args */,
                  const struct NFS41::ACCESS4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void close41(const RPCProcedure* /* proc */,
                 const struct NFS41::CLOSE4args* /* args */,
                 const struct NFS41::CLOSE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void commit41(const RPCProcedure* /* proc */,
                  const struct NFS41::COMMIT4args* /* args */,
                  const struct NFS41::COMMIT4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void create41(const RPCProcedure* /* proc */,
                  const struct NFS41::CREATE4args* /* args */,
                  const struct NFS41::CREATE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void delegpurge41(const RPCProcedure* /* proc */,
                      const struct NFS41::DELEGPURGE4args* /* args */,
                      const struct NFS41::DELEGPURGE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void delegreturn41(const RPCProcedure* /* proc */,
                       const struct NFS41::DELEGRETURN4args* /* args */,
                       const struct NFS41::DELEGRETURN4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void getattr41(const RPCProcedure* /* proc */,
                   const struct NFS41::GETATTR4args* /* args */,
                   const struct NFS41::GETATTR4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void getfh41(const RPCProcedure* /* proc */,
                 const struct NFS41::GETFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void link41(const RPCProcedure* /* proc */,
                const struct NFS41::LINK4args* /* args */,
                const struct NFS41::LINK4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void lock41(const RPCProcedure* /* proc */,
                const struct NFS41::LOCK4args* /* args */,
                const struct NFS41::LOCK4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void lockt41(const RPCProcedure* /* proc */,
                 const struct NFS41::LOCKT4args* /* args */,
                 const struct NFS41::LOCKT4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void locku41(const RPCProcedure* /* proc */,
                 const struct NFS41::LOCKU4args* /* args */,
                 const struct NFS41::LOCKU4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void lookup41(const RPCProcedure* /* proc */,
                  const struct NFS41::LOOKUP4args* /* args */,
                  const struct NFS41::LOOKUP4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void lookupp41(const RPCProcedure* /* proc */,
                   const struct NFS41::LOOKUPP4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void nverify41(const RPCProcedure* /* proc */,
                   const struct NFS41::NVERIFY4args* /* args */,
                   const struct NFS41::NVERIFY4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void open41(const RPCProcedure* /* proc */,
                const struct NFS41::OPEN4args* /* args */,
                const struct NFS41::OPEN4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void openattr41(const RPCProcedure* /* proc */,
                    const struct NFS41::OPENATTR4args* /* args */,
                    const struct NFS41::OPENATTR4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void open_confirm41(const RPCProcedure* /* proc */,
                        const struct NFS41::OPEN_CONFIRM4args* /* args */,
                        const struct NFS41::OPEN_CONFIRM4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void open_downgrade41(const RPCProcedure* /* proc */,
                          const struct NFS41::OPEN_DOWNGRADE4args* /* args */,
                          const struct NFS41::OPEN_DOWNGRADE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void putfh41(const RPCProcedure* /* proc */,
                 const struct NFS41::PUTFH4args* /* args */,
                 const struct NFS41::PUTFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void putpubfh41(const RPCProcedure* /* proc */,
                    const struct NFS41::PUTPUBFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void putrootfh41(const RPCProcedure* /* proc */,
                     const struct NFS41::PUTROOTFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void read41(const RPCProcedure* /* proc */,
                const struct NFS41::READ4args* /* args */,
                const struct NFS41::READ4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void readdir41(const RPCProcedure* /* proc */,
                   const struct NFS41::READDIR4args* /* args */,
                   const struct NFS41::READDIR4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void readlink41(const RPCProcedure* /* proc */,
                    const struct NFS41::READLINK4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void remove41(const RPCProcedure* /* proc */,
                  const struct NFS41::REMOVE4args* /* args */,
                  const struct NFS41::REMOVE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void rename41(const RPCProcedure* /* proc */,
                  const struct NFS41::RENAME4args* /* args */,
                  const struct NFS41::RENAME4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void renew41(const RPCProcedure* /* proc */,
                 const struct NFS41::RENEW4args* /* args */,
                 const struct NFS41::RENEW4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void restorefh41(const RPCProcedure* /* proc */,
                     const struct NFS41::RESTOREFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void savefh41(const RPCProcedure* /* proc */,
                  const struct NFS41::SAVEFH4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void secinfo41(const RPCProcedure* /* proc */,
                   const struct NFS41::SECINFO4args* /* args */,
                   const struct NFS41::SECINFO4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void setattr41(const RPCProcedure* /* proc */,
                   const struct NFS41::SETATTR4args* /* args */,
                   const struct NFS41::SETATTR4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void setclientid41(const RPCProcedure* /* proc */,
                       const struct NFS41::SETCLIENTID4args* /* args */,
                       const struct NFS41::SETCLIENTID4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void setclientid_confirm41(const RPCProcedure* /* proc */,
                               const struct NFS41::SETCLIENTID_CONFIRM4args* /* args */,
                               const struct NFS41::SETCLIENTID_CONFIRM4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void verify41(const RPCProcedure* /* proc */,
                  const struct NFS41::VERIFY4args* /* args */,
                  const struct NFS41::VERIFY4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void write41(const RPCProcedure* /* proc */,
                 const struct NFS41::WRITE4args* /* args */,
                 const struct NFS41::WRITE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void release_lockowner41(const RPCProcedure* /* proc */,
                             const struct NFS41::RELEASE_LOCKOWNER4args* /* args */,
                             const struct NFS41::RELEASE_LOCKOWNER4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void backchannel_ctl41(const RPCProcedure* /* proc */,
                           const struct NFS41::BACKCHANNEL_CTL4args* /* args */,
                           const struct NFS41::BACKCHANNEL_CTL4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void bind_conn_to_session41(const RPCProcedure* /* proc */,
                                const struct NFS41::BIND_CONN_TO_SESSION4args* /* args */,
                                const struct NFS41::BIND_CONN_TO_SESSION4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void exchange_id41(const RPCProcedure* /* proc */,
                       const struct NFS41::EXCHANGE_ID4args* /* args */,
                       const struct NFS41::EXCHANGE_ID4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void create_session41(const RPCProcedure* /* proc */,
                          const struct NFS41::CREATE_SESSION4args* /* args */,
                          const struct NFS41::CREATE_SESSION4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void destroy_session41(const RPCProcedure* /* proc */,
                           const struct NFS41::DESTROY_SESSION4args* /* args */,
                           const struct NFS41::DESTROY_SESSION4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void free_stateid41(const RPCProcedure* /* proc */,
                        const struct NFS41::FREE_STATEID4args* /* args */,
                        const struct NFS41::FREE_STATEID4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void get_dir_delegation41(const RPCProcedure* /* proc */,
                              const struct NFS41::GET_DIR_DELEGATION4args* /* args */,
                              const struct NFS41::GET_DIR_DELEGATION4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void getdeviceinfo41(const RPCProcedure* /* proc */,
                         const struct NFS41::GETDEVICEINFO4args* /* args */,
                         const struct NFS41::GETDEVICEINFO4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void getdevicelist41(const RPCProcedure* /* proc */,
                         const struct NFS41::GETDEVICELIST4args* /* args */,
                         const struct NFS41::GETDEVICELIST4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void layoutcommit41(const RPCProcedure* /* proc */,
                        const struct NFS41::LAYOUTCOMMIT4args* /* args */,
                        const struct NFS41::LAYOUTCOMMIT4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void layoutget41(const RPCProcedure* /* proc */,
                     const struct NFS41::LAYOUTGET4args* /* args */,
                     const struct NFS41::LAYOUTGET4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void layoutreturn41(const RPCProcedure* /* proc */,
                        const struct NFS41::LAYOUTRETURN4args* /* args */,
                        const struct NFS41::LAYOUTRETURN4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void secinfo_no_name41(const RPCProcedure* /* proc */,
                           const NFS41::SECINFO_NO_NAME4args* /* args */,
                           const NFS41::SECINFO_NO_NAME4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void sequence41(const RPCProcedure* /* proc */,
                    const struct NFS41::SEQUENCE4args* /* args */,
                    const struct NFS41::SEQUENCE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void set_ssv41(const RPCProcedure* /* proc */,
                   const struct NFS41::SET_SSV4args* /* args */,
                   const struct NFS41::SET_SSV4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void test_stateid41(const RPCProcedure* /* proc */,
                        const struct NFS41::TEST_STATEID4args* /* args */,
                        const struct NFS41::TEST_STATEID4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void want_delegation41(const RPCProcedure* /* proc */,
                           const struct NFS41::WANT_DELEGATION4args* /* args */,
                           const struct NFS41::WANT_DELEGATION4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void destroy_clientid41(const RPCProcedure* /* proc */,
                            const struct NFS41::DESTROY_CLIENTID4args* /* args */,
                            const struct NFS41::DESTROY_CLIENTID4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void reclaim_complete41(const RPCProcedure* /* proc */,
                            const struct NFS41::RECLAIM_COMPLETE4args* /* args */,
                            const struct NFS41::RECLAIM_COMPLETE4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }
    void illegal41(const RPCProcedure* /* proc */,
                   const struct NFS41::ILLEGAL4res* /* res */) override final
    {
        std::cout << "TestAnalyzer" << std::endl;
    }

    virtual void flush_statistics() override
    {
        std::cout << "TestAnalyzer::flush_statistics()" << std::endl;
    }

private:
    std::string options;
};

extern "C" {

const char* usage()
{
    return "TestAnalyzer: any options";
}

IAnalyzer* create(const char* opts)
{
    return new TestAnalyzer(opts);
}

void destroy(IAnalyzer* instance)
{
    delete instance;
}

const AnalyzerRequirements* requirements()
{
    static const AnalyzerRequirements requirements{true};
    return &requirements;
}

NST_PLUGIN_ENTRY_POINTS(&usage, &create, &destroy, nullptr)

} //extern "C"
//------------------------------------------------------------------------------
