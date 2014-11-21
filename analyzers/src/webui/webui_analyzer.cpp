//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: WebUI analyzer
// Copyright (c) 2013-2014 EPAM Systems
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

#include <iostream>
#include <string>

#include <api/plugin_api.h> // include plugin development definitions
#include <net/abstract_tcp_service.h>

using namespace NST::net;

static const char * TestResponse = "{copy:32,remove:46,getattr:154}";

class JsonTcpService : public AbstractTcpService
{
public:
	JsonTcpService() = delete;
	JsonTcpService(int port, std::size_t workersAmount, int backlog = 15) :
		AbstractTcpService(port, workersAmount, backlog)
	{}
private:
	class Task : public AbstractTask
	{
	public:
		Task(JsonTcpService& service, int socket) :
			AbstractTask(socket),
			_service(service)
		{}
		Task() = delete;

		virtual void execute() override
		{
			/*ssize_t bytesSent = */send(socket(), TestResponse, strlen(TestResponse), MSG_NOSIGNAL);
			// TODO: Check result
		}
	private:
		JsonTcpService& _service;
	};

	virtual AbstractTask * createTask(int socket)
	{
		return new Task(*this, socket);
	}
};

class WebUiAnalyzer : public IAnalyzer
{
public:
    WebUiAnalyzer(int port, std::size_t workersAmount) :
	_jsonTcpService(port, workersAmount)
    {
        std::cout << "WebUiAnalyzer::WebUiAnalyzer(" << port << ", " << workersAmount << ')' << std::endl;
    }

    ~WebUiAnalyzer()
    {
        std::cout << "WebUiAnalyzer::~WebUiAnalyzer()" << std::endl;
    }

    void null(const struct RPCProcedure* /*proc*/,
                      const struct rpcgen::NULL3args* /*args*/,
                      const struct rpcgen::NULL3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::null()" << std::endl;
    }

    void getattr3(const struct RPCProcedure* /*proc*/,
                          const struct rpcgen::GETATTR3args* /*args*/,
                          const struct rpcgen::GETATTR3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::getattr3()" << std::endl;
    }

    void setattr3(const struct RPCProcedure* /*proc*/,
                          const struct rpcgen::SETATTR3args* /*args*/,
                          const struct rpcgen::SETATTR3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::setattr3()" << std::endl;
    }

    void lookup3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::LOOKUP3args* /*args*/,
                         const struct rpcgen::LOOKUP3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::lookup3()" << std::endl;
    }

    void access3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::ACCESS3args* /*args*/,
                         const struct rpcgen::ACCESS3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::access3()" << std::endl;
    }

    void readlink3(const struct RPCProcedure* /*proc*/,
                           const struct rpcgen::READLINK3args* /*args*/,
                           const struct rpcgen::READLINK3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::readlink3()" << std::endl;
    }

    void read3(const struct RPCProcedure* /*proc*/,
                       const struct rpcgen::READ3args* /*args*/,
                       const struct rpcgen::READ3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::read3()" << std::endl;
    }

    void write3(const struct RPCProcedure* /*proc*/,
                        const struct rpcgen::WRITE3args* /*args*/,
                        const struct rpcgen::WRITE3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::write3()" << std::endl;
    }

    void create3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::CREATE3args* /*args*/,
                         const struct rpcgen::CREATE3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::create3()" << std::endl;
    }

    void mkdir3(const struct RPCProcedure* /*proc*/,
                        const struct rpcgen::MKDIR3args* /*args*/,
                        const struct rpcgen::MKDIR3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::mkdir3()" << std::endl;
    }

    void symlink3(const struct RPCProcedure* /*proc*/,
                          const struct rpcgen::SYMLINK3args* /*args*/,
                          const struct rpcgen::SYMLINK3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::symlink3()" << std::endl;
    }

    void mknod3(const struct RPCProcedure* /*proc*/,
                        const struct rpcgen::MKNOD3args* /*args*/,
                        const struct rpcgen::MKNOD3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::mknod3()" << std::endl;
    }

    void remove3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::REMOVE3args* /*args*/,
                         const struct rpcgen::REMOVE3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::remove3()" << std::endl;
    }

    void rmdir3(const struct RPCProcedure* /*proc*/,
                        const struct rpcgen::RMDIR3args* /*args*/,
                        const struct rpcgen::RMDIR3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::rmdir3()" << std::endl;
    }

    void rename3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::RENAME3args* /*args*/,
                         const struct rpcgen::RENAME3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::rename3()" << std::endl;
    }

    void link3(const struct RPCProcedure* /*proc*/,
                       const struct rpcgen::LINK3args* /*args*/,
                       const struct rpcgen::LINK3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::link3()" << std::endl;
    }

    void readdir3(const struct RPCProcedure* /*proc*/,
                          const struct rpcgen::READDIR3args* /*args*/,
                          const struct rpcgen::READDIR3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::readdir3()" << std::endl;
    }

    void readdirplus3(const struct RPCProcedure* /*proc*/,
                              const struct rpcgen::READDIRPLUS3args* /*args*/,
                              const struct rpcgen::READDIRPLUS3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::readdirplus3()" << std::endl;
    }

    void fsstat3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::FSSTAT3args* /*args*/,
                         const struct rpcgen::FSSTAT3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::fsstat3()" << std::endl;
    }

    void fsinfo3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::FSINFO3args* /*args*/,
                         const struct rpcgen::FSINFO3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::fsinfo3()" << std::endl;
    }

    void pathconf3(const struct RPCProcedure* /*proc*/,
                           const struct rpcgen::PATHCONF3args* /*args*/,
                           const struct rpcgen::PATHCONF3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::pathconf3()" << std::endl;
    }

    void commit3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::COMMIT3args* /*args*/,
                         const struct rpcgen::COMMIT3res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::commit3()" << std::endl;
    }

    void null(const struct RPCProcedure* /*proc*/,
              const struct rpcgen::NULL4args* /*args*/,
              const struct rpcgen::NULL4res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::null()" << std::endl;
    }
    void compound4(const struct RPCProcedure* /*proc*/,
                           const struct rpcgen::COMPOUND4args* /*args*/,
                           const struct rpcgen::COMPOUND4res* /*res*/) override final
    {
        std::cout << "WebUiAnalyzer::compound4()" << std::endl;
    }

    virtual void flush_statistics()
    {
        std::cout << "WebUiAnalyzer::flush_statistics()" << std::endl;
    }
private:
    JsonTcpService _jsonTcpService;
};

extern "C"
{

const char* usage()
{
    return "WebUiAnalyzer: any options";
}

IAnalyzer* create(const char* /*opts*/)
{
    // TODO: Extract port and workers amount from options string
    return new WebUiAnalyzer(8888, 10U);
}

void destroy(IAnalyzer* instance)
{
    delete instance;
}

NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

} //extern "C"
