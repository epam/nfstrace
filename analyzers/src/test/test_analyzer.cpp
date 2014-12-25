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
                      const struct rpcgen::NULL3args* /*args*/,
                      const struct rpcgen::NULL3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::null()" << std::endl;
    }

    void getattr3(const RPCProcedure* /*proc*/,
                          const struct rpcgen::GETATTR3args* /*args*/,
                          const struct rpcgen::GETATTR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::getattr3()" << std::endl;
    }

    void setattr3(const RPCProcedure* /*proc*/,
                          const struct rpcgen::SETATTR3args* /*args*/,
                          const struct rpcgen::SETATTR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::setattr3()" << std::endl;
    }

    void lookup3(const RPCProcedure* /*proc*/,
                         const struct rpcgen::LOOKUP3args* /*args*/,
                         const struct rpcgen::LOOKUP3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::lookup3()" << std::endl;
    }

    void access3(const RPCProcedure* /*proc*/,
                         const struct rpcgen::ACCESS3args* /*args*/,
                         const struct rpcgen::ACCESS3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::access3()" << std::endl;
    }

    void readlink3(const RPCProcedure* /*proc*/,
                           const struct rpcgen::READLINK3args* /*args*/,
                           const struct rpcgen::READLINK3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::readlink3()" << std::endl;
    }

    void read3(const RPCProcedure* /*proc*/,
                       const struct rpcgen::READ3args* /*args*/,
                       const struct rpcgen::READ3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::read3()" << std::endl;
    }

    void write3(const RPCProcedure* /*proc*/,
                        const struct rpcgen::WRITE3args* /*args*/,
                        const struct rpcgen::WRITE3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::write3()" << std::endl;
    }

    void create3(const RPCProcedure* /*proc*/,
                         const struct rpcgen::CREATE3args* /*args*/,
                         const struct rpcgen::CREATE3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::create3()" << std::endl;
    }

    void mkdir3(const RPCProcedure* /*proc*/,
                        const struct rpcgen::MKDIR3args* /*args*/,
                        const struct rpcgen::MKDIR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::mkdir3()" << std::endl;
    }

    void symlink3(const RPCProcedure* /*proc*/,
                          const struct rpcgen::SYMLINK3args* /*args*/,
                          const struct rpcgen::SYMLINK3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::symlink3()" << std::endl;
    }

    void mknod3(const RPCProcedure* /*proc*/,
                        const struct rpcgen::MKNOD3args* /*args*/,
                        const struct rpcgen::MKNOD3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::mknod3()" << std::endl;
    }

    void remove3(const RPCProcedure* /*proc*/,
                         const struct rpcgen::REMOVE3args* /*args*/,
                         const struct rpcgen::REMOVE3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::remove3()" << std::endl;
    }

    void rmdir3(const RPCProcedure* /*proc*/,
                        const struct rpcgen::RMDIR3args* /*args*/,
                        const struct rpcgen::RMDIR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::rmdir3()" << std::endl;
    }

    void rename3(const RPCProcedure* /*proc*/,
                         const struct rpcgen::RENAME3args* /*args*/,
                         const struct rpcgen::RENAME3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::rename3()" << std::endl;
    }

    void link3(const RPCProcedure* /*proc*/,
                       const struct rpcgen::LINK3args* /*args*/,
                       const struct rpcgen::LINK3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::link3()" << std::endl;
    }

    void readdir3(const RPCProcedure* /*proc*/,
                          const struct rpcgen::READDIR3args* /*args*/,
                          const struct rpcgen::READDIR3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::readdir3()" << std::endl;
    }

    void readdirplus3(const RPCProcedure* /*proc*/,
                              const struct rpcgen::READDIRPLUS3args* /*args*/,
                              const struct rpcgen::READDIRPLUS3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::readdirplus3()" << std::endl;
    }

    void fsstat3(const RPCProcedure* /*proc*/,
                         const struct rpcgen::FSSTAT3args* /*args*/,
                         const struct rpcgen::FSSTAT3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::fsstat3()" << std::endl;
    }

    void fsinfo3(const RPCProcedure* /*proc*/,
                         const struct rpcgen::FSINFO3args* /*args*/,
                         const struct rpcgen::FSINFO3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::fsinfo3()" << std::endl;
    }

    void pathconf3(const RPCProcedure* /*proc*/,
                           const struct rpcgen::PATHCONF3args* /*args*/,
                           const struct rpcgen::PATHCONF3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::pathconf3()" << std::endl;
    }

    void commit3(const RPCProcedure* /*proc*/,
                         const struct rpcgen::COMMIT3args* /*args*/,
                         const struct rpcgen::COMMIT3res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::commit3()" << std::endl;
    }

    void null(const RPCProcedure* /*proc*/,
              const struct rpcgen::NULL4args* /*args*/,
              const struct rpcgen::NULL4res* /*res*/) override final
    {
        std::cout << "TestAnalyzer::null()" << std::endl;
    }
    void compound4(const RPCProcedure* /*proc*/,
                           const struct rpcgen::COMPOUND4args* /*args*/,
                           const struct rpcgen::COMPOUND4res* /*res*/) override final
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
