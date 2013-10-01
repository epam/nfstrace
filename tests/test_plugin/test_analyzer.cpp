//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Example of usage Plugin-API.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <string>

#include <plugin_api.h> // include plugin development definitions
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
class TestAnalyzer : public IAnalyzer
{
public:
    TestAnalyzer(const char* opts):options(opts)
    {
        std::cout << "TestAnalyzer::TestAnalyzer(" << options << ")" << std::endl;
    }

    ~TestAnalyzer()
    {
        std::cout << "TestAnalyzer::~TestAnalyzer()" << std::endl;
    }

    virtual void null(const struct RPCProcedure* proc,
                      const struct NULLargs* args,
                      const struct NULLres* res)
    {
        std::cout << "TestAnalyzer::null()" << std::endl;
    }

    virtual void getattr3(const struct RPCProcedure* proc,
                          const struct GETATTR3args* args,
                          const struct GETATTR3res* res)
    {
        std::cout << "TestAnalyzer::getattr3()" << std::endl;
    }

    virtual void setattr3(const struct RPCProcedure* proc,
                          const struct SETATTR3args* args,
                          const struct SETATTR3res* res)
    {
        std::cout << "TestAnalyzer::setattr3()" << std::endl;
    }

    virtual void lookup3(const struct RPCProcedure* proc,
                         const struct LOOKUP3args* args,
                         const struct LOOKUP3res* res)
    {
        std::cout << "TestAnalyzer::lookup3()" << std::endl;
    }

    virtual void access3(const struct RPCProcedure* proc,
                         const struct ACCESS3args* args,
                         const struct ACCESS3res* res)
    {
        std::cout << "TestAnalyzer::access3()" << std::endl;
    }

    virtual void readlink3(const struct RPCProcedure* proc,
                           const struct READLINK3args* args,
                           const struct READLINK3res* res)
    {
        std::cout << "TestAnalyzer::readlink3()" << std::endl;
    }

    virtual void read3(const struct RPCProcedure* proc,
                       const struct READ3args* args,
                       const struct READ3res* res)
    {
        std::cout << "TestAnalyzer::read3()" << std::endl;
    }

    virtual void write3(const struct RPCProcedure* proc,
                        const struct WRITE3args* args,
                        const struct WRITE3res* res)
    {
        std::cout << "TestAnalyzer::write3()" << std::endl;
    }

    virtual void create3(const struct RPCProcedure* proc,
                         const struct CREATE3args* args,
                         const struct CREATE3res* res)
    {
        std::cout << "TestAnalyzer::create3()" << std::endl;
    }

    virtual void mkdir3(const struct RPCProcedure* proc,
                        const struct MKDIR3args* args,
                        const struct MKDIR3res* res)
    {
        std::cout << "TestAnalyzer::mkdir3()" << std::endl;
    }

    virtual void symlink3(const struct RPCProcedure* proc,
                          const struct SYMLINK3args* args,
                          const struct SYMLINK3res* res)
    {
        std::cout << "TestAnalyzer::symlink3()" << std::endl;
    }

    virtual void mknod3(const struct RPCProcedure* proc,
                        const struct MKNOD3args* args,
                        const struct MKNOD3res* res)
    {
        std::cout << "TestAnalyzer::mknod3()" << std::endl;
    }

    virtual void remove3(const struct RPCProcedure* proc,
                         const struct REMOVE3args* args,
                         const struct REMOVE3res* res)
    {
        std::cout << "TestAnalyzer::remove3()" << std::endl;
    }

    virtual void rmdir3(const struct RPCProcedure* proc,
                        const struct RMDIR3args* args,
                        const struct RMDIR3res* res)
    {
        std::cout << "TestAnalyzer::rmdir3()" << std::endl;
    }

    virtual void rename3(const struct RPCProcedure* proc,
                         const struct RENAME3args* args,
                         const struct RENAME3res* res)
    {
        std::cout << "TestAnalyzer::rename3()" << std::endl;
    }

    virtual void link3(const struct RPCProcedure* proc,
                       const struct LINK3args* args,
                       const struct LINK3res* res)
    {
        std::cout << "TestAnalyzer::link3()" << std::endl;
    }

    virtual void readdir3(const struct RPCProcedure* proc,
                          const struct READDIR3args* args,
                          const struct READDIR3res* res)
    {
        std::cout << "TestAnalyzer::readdir3()" << std::endl;
    }

    virtual void readdirplus3(const struct RPCProcedure* proc,
                              const struct READDIRPLUS3args* args,
                              const struct READDIRPLUS3res* res)
    {
        std::cout << "TestAnalyzer::readdirplus3()" << std::endl;
    }

    virtual void fsstat3(const struct RPCProcedure* proc,
                         const struct FSSTAT3args* args,
                         const struct FSSTAT3res* res)
    {
        std::cout << "TestAnalyzer::fsstat3()" << std::endl;
    }

    virtual void fsinfo3(const struct RPCProcedure* proc,
                         const struct FSINFO3args* args,
                         const struct FSINFO3res* res)
    {
        std::cout << "TestAnalyzer::fsinfo3()" << std::endl;
    }

    virtual void pathconf3(const struct RPCProcedure* proc,
                           const struct PATHCONF3args* args,
                           const struct PATHCONF3res* res)
    {
        std::cout << "TestAnalyzer::pathconf3()" << std::endl;
    }

    virtual void commit3(const struct RPCProcedure* proc,
                         const struct COMMIT3args* args,
                         const struct COMMIT3res* res)
    {
        std::cout << "TestAnalyzer::commit3()" << std::endl;
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

}
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
