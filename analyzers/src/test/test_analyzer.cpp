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
    TestAnalyzer(const char* opts):options(opts)
    {
        std::cout << "TestAnalyzer::TestAnalyzer(" << options << ')' << std::endl;
    }

    ~TestAnalyzer()
    {
        std::cout << "TestAnalyzer::~TestAnalyzer()" << std::endl;
    }

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

    void null(const RPCProcedure* /*proc*/,
              const struct NFS4::NULL4args* /*args*/,
              const struct NFS4::NULL4res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::null()" << std::endl;
    }
    void compound4(const RPCProcedure* /*proc*/,
                           const struct NFS4::COMPOUND4args* /*args*/,
                           const struct NFS4::COMPOUND4res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::compound4()" << std::endl;
    }

    virtual void flush_statistics()
    {
        std::cout << "TestAnalyzer::flush_statistics()" << std::endl;
    }
private:
    std::string options;
};

extern "C"
{

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

NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

}//extern "C"
//------------------------------------------------------------------------------
