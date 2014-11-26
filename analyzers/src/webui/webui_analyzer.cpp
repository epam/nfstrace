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
#include <atomic>
#include <jsoncpp/json/json.h>

#include <api/plugin_api.h> // include plugin development definitions
#include <net/abstract_tcp_service.h>

#define WEB_API_VERSION "0.0.1"

using namespace NST::net;

class WebUiAnalyzer;

class JsonTcpService : public AbstractTcpService
{
public:
	JsonTcpService() = delete;
	JsonTcpService(WebUiAnalyzer& analyzer, int port, std::size_t workersAmount, int backlog = 15) :
		AbstractTcpService(port, workersAmount, backlog),
		_analyzer(analyzer)
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

		void execute() override final;
	private:
		JsonTcpService& _service;
	};

	AbstractTask * createTask(int socket) override final
	{
		return new Task(*this, socket);
	}

	WebUiAnalyzer& _analyzer;
};

class WebUiAnalyzer : public IAnalyzer
{
public:
    struct NfsV3Stat
    {
	    std::atomic_int nullOpsAmount;
	    std::atomic_int getattrOpsAmount;
	    std::atomic_int setattrOpsAmount;
	    std::atomic_int lookupOpsAmount;
	    std::atomic_int accessOpsAmount;
	    std::atomic_int readlinkOpsAmount;
	    std::atomic_int readOpsAmount;
	    std::atomic_int writeOpsAmount;
	    std::atomic_int createOpsAmount;
	    std::atomic_int mkdirOpsAmount;
	    std::atomic_int symlinkOpsAmount;
	    std::atomic_int mkdnodOpsAmount;
	    std::atomic_int removeOpsAmount;
	    std::atomic_int rmdirOpsAmount;
	    std::atomic_int renameOpsAmount;
	    std::atomic_int linkOpsAmount;
	    std::atomic_int readdirOpsAmount;
	    std::atomic_int readdirplusOpsAmount;
	    std::atomic_int fsstatOpsAmount;
	    std::atomic_int fsinfoOpsAmount;
	    std::atomic_int pathconfOpsAmount;
	    std::atomic_int commitOpsAmount;

	    NfsV3Stat() :
		    nullOpsAmount(0),
		    getattrOpsAmount(0),
		    setattrOpsAmount(0),
		    lookupOpsAmount(0),
		    accessOpsAmount(0),
		    readlinkOpsAmount(0),
		    readOpsAmount(0),
		    writeOpsAmount(0),
		    createOpsAmount(0),
		    mkdirOpsAmount(0),
		    symlinkOpsAmount(0),
		    mkdnodOpsAmount(0),
		    removeOpsAmount(0),
		    rmdirOpsAmount(0),
		    renameOpsAmount(0),
		    linkOpsAmount(0),
		    readdirOpsAmount(0),
		    readdirplusOpsAmount(0),
		    fsstatOpsAmount(0),
		    fsinfoOpsAmount(0),
		    pathconfOpsAmount(0),
		    commitOpsAmount(0)
	    {}
    };
    struct NfsV4Stat
    {
	    std::atomic_int nullOpsAmount;
	    std::atomic_int compoundOpsAmount;

	    NfsV4Stat() :
		    nullOpsAmount(0),
		    compoundOpsAmount(0)
	    {}
    };

    WebUiAnalyzer(int port, std::size_t workersAmount) :
	_jsonTcpService(*this, port, workersAmount),
	_nfsV3Stat(),
	_nfsV4Stat()
    {
        //std::cout << "WebUiAnalyzer::WebUiAnalyzer(" << port << ", " << workersAmount << ')' << std::endl;
    }

    ~WebUiAnalyzer()
    {
        //std::cout << "WebUiAnalyzer::~WebUiAnalyzer()" << std::endl;
    }

    void null(const struct RPCProcedure* /*proc*/,
                      const struct rpcgen::NULL3args* /*args*/,
                      const struct rpcgen::NULL3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::null()" << std::endl;
	_nfsV3Stat.nullOpsAmount++;
    }

    void getattr3(const struct RPCProcedure* /*proc*/,
                          const struct rpcgen::GETATTR3args* /*args*/,
                          const struct rpcgen::GETATTR3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::getattr3()" << std::endl;
	_nfsV3Stat.getattrOpsAmount++;
    }

    void setattr3(const struct RPCProcedure* /*proc*/,
                          const struct rpcgen::SETATTR3args* /*args*/,
                          const struct rpcgen::SETATTR3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::setattr3()" << std::endl;
	_nfsV3Stat.setattrOpsAmount++;
    }

    void lookup3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::LOOKUP3args* /*args*/,
                         const struct rpcgen::LOOKUP3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::lookup3()" << std::endl;
	_nfsV3Stat.lookupOpsAmount++;
    }

    void access3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::ACCESS3args* /*args*/,
                         const struct rpcgen::ACCESS3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::access3()" << std::endl;
	_nfsV3Stat.accessOpsAmount++;
    }

    void readlink3(const struct RPCProcedure* /*proc*/,
                           const struct rpcgen::READLINK3args* /*args*/,
                           const struct rpcgen::READLINK3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::readlink3()" << std::endl;
	_nfsV3Stat.readlinkOpsAmount++;
    }

    void read3(const struct RPCProcedure* /*proc*/,
                       const struct rpcgen::READ3args* /*args*/,
                       const struct rpcgen::READ3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::read3()" << std::endl;
	_nfsV3Stat.readOpsAmount++;
    }

    void write3(const struct RPCProcedure* /*proc*/,
                        const struct rpcgen::WRITE3args* /*args*/,
                        const struct rpcgen::WRITE3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::write3()" << std::endl;
	_nfsV3Stat.writeOpsAmount++;
    }

    void create3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::CREATE3args* /*args*/,
                         const struct rpcgen::CREATE3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::create3()" << std::endl;
	_nfsV3Stat.createOpsAmount++;
    }

    void mkdir3(const struct RPCProcedure* /*proc*/,
                        const struct rpcgen::MKDIR3args* /*args*/,
                        const struct rpcgen::MKDIR3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::mkdir3()" << std::endl;
	_nfsV3Stat.mkdirOpsAmount++;
    }

    void symlink3(const struct RPCProcedure* /*proc*/,
                          const struct rpcgen::SYMLINK3args* /*args*/,
                          const struct rpcgen::SYMLINK3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::symlink3()" << std::endl;
	_nfsV3Stat.symlinkOpsAmount++;
    }

    void mknod3(const struct RPCProcedure* /*proc*/,
                        const struct rpcgen::MKNOD3args* /*args*/,
                        const struct rpcgen::MKNOD3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::mknod3()" << std::endl;
	_nfsV3Stat.mkdnodOpsAmount++;
    }

    void remove3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::REMOVE3args* /*args*/,
                         const struct rpcgen::REMOVE3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::remove3()" << std::endl;
	_nfsV3Stat.removeOpsAmount++;
    }

    void rmdir3(const struct RPCProcedure* /*proc*/,
                        const struct rpcgen::RMDIR3args* /*args*/,
                        const struct rpcgen::RMDIR3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::rmdir3()" << std::endl;
	_nfsV3Stat.rmdirOpsAmount++;
    }

    void rename3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::RENAME3args* /*args*/,
                         const struct rpcgen::RENAME3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::rename3()" << std::endl;
	_nfsV3Stat.renameOpsAmount++;
    }

    void link3(const struct RPCProcedure* /*proc*/,
                       const struct rpcgen::LINK3args* /*args*/,
                       const struct rpcgen::LINK3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::link3()" << std::endl;
	_nfsV3Stat.linkOpsAmount++;
    }

    void readdir3(const struct RPCProcedure* /*proc*/,
                          const struct rpcgen::READDIR3args* /*args*/,
                          const struct rpcgen::READDIR3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::readdir3()" << std::endl;
	_nfsV3Stat.readdirOpsAmount++;
    }

    void readdirplus3(const struct RPCProcedure* /*proc*/,
                              const struct rpcgen::READDIRPLUS3args* /*args*/,
                              const struct rpcgen::READDIRPLUS3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::readdirplus3()" << std::endl;
	_nfsV3Stat.readdirplusOpsAmount++;
    }

    void fsstat3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::FSSTAT3args* /*args*/,
                         const struct rpcgen::FSSTAT3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::fsstat3()" << std::endl;
	_nfsV3Stat.fsstatOpsAmount++;
    }

    void fsinfo3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::FSINFO3args* /*args*/,
                         const struct rpcgen::FSINFO3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::fsinfo3()" << std::endl;
	_nfsV3Stat.fsinfoOpsAmount++;
    }

    void pathconf3(const struct RPCProcedure* /*proc*/,
                           const struct rpcgen::PATHCONF3args* /*args*/,
                           const struct rpcgen::PATHCONF3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::pathconf3()" << std::endl;
	_nfsV3Stat.pathconfOpsAmount++;
    }

    void commit3(const struct RPCProcedure* /*proc*/,
                         const struct rpcgen::COMMIT3args* /*args*/,
                         const struct rpcgen::COMMIT3res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::commit3()" << std::endl;
	_nfsV3Stat.commitOpsAmount++;
    }

    void null(const struct RPCProcedure* /*proc*/,
              const struct rpcgen::NULL4args* /*args*/,
              const struct rpcgen::NULL4res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::null()" << std::endl;
	_nfsV4Stat.nullOpsAmount++;
    }
    void compound4(const struct RPCProcedure* /*proc*/,
                           const struct rpcgen::COMPOUND4args* /*args*/,
                           const struct rpcgen::COMPOUND4res* /*res*/) override final
    {
        //std::cout << "WebUiAnalyzer::compound4()" << std::endl;
	_nfsV4Stat.compoundOpsAmount++;
    }

    void flush_statistics() override final
    {
        std::cout << "WebUiAnalyzer::flush_statistics()" << std::endl;
    }

    const NfsV3Stat& getNfsV3Stat() const
    {
	    return _nfsV3Stat;
    }

    const NfsV4Stat& getNfsV4Stat() const
    {
	    return _nfsV4Stat;
    }
private:
    JsonTcpService _jsonTcpService;
    NfsV3Stat _nfsV3Stat;
    NfsV4Stat _nfsV4Stat;
};

//------------------------------------------------------------------------------

void JsonTcpService::Task::execute()
{
	Json::Value root(Json::objectValue);
	root["api_version"] = Json::Value(WEB_API_VERSION);
	Json::Value nfsV3Stat(Json::objectValue);
	nfsV3Stat["null"] = Json::Value(_service._analyzer.getNfsV3Stat().nullOpsAmount.load());
	nfsV3Stat["getattr"] = Json::Value(_service._analyzer.getNfsV3Stat().getattrOpsAmount.load());
	nfsV3Stat["setattr"] = Json::Value(_service._analyzer.getNfsV3Stat().setattrOpsAmount.load());
	nfsV3Stat["lookup"] = Json::Value(_service._analyzer.getNfsV3Stat().lookupOpsAmount.load());
	nfsV3Stat["access"] = Json::Value(_service._analyzer.getNfsV3Stat().accessOpsAmount.load());
	nfsV3Stat["readlink"] = Json::Value(_service._analyzer.getNfsV3Stat().readlinkOpsAmount.load());
	nfsV3Stat["read"] = Json::Value(_service._analyzer.getNfsV3Stat().readOpsAmount.load());
	nfsV3Stat["write"] = Json::Value(_service._analyzer.getNfsV3Stat().writeOpsAmount.load());
	nfsV3Stat["create"] = Json::Value(_service._analyzer.getNfsV3Stat().createOpsAmount.load());
	nfsV3Stat["mkdir"] = Json::Value(_service._analyzer.getNfsV3Stat().mkdirOpsAmount.load());
	nfsV3Stat["symlink"] = Json::Value(_service._analyzer.getNfsV3Stat().symlinkOpsAmount.load());
	nfsV3Stat["mkdnod"] = Json::Value(_service._analyzer.getNfsV3Stat().mkdnodOpsAmount.load());
	nfsV3Stat["remove"] = Json::Value(_service._analyzer.getNfsV3Stat().removeOpsAmount.load());
	nfsV3Stat["rmdir"] = Json::Value(_service._analyzer.getNfsV3Stat().rmdirOpsAmount.load());
	nfsV3Stat["rename"] = Json::Value(_service._analyzer.getNfsV3Stat().renameOpsAmount.load());
	nfsV3Stat["link"] = Json::Value(_service._analyzer.getNfsV3Stat().linkOpsAmount.load());
	nfsV3Stat["readdir"] = Json::Value(_service._analyzer.getNfsV3Stat().readdirOpsAmount.load());
	nfsV3Stat["readdirplus"] = Json::Value(_service._analyzer.getNfsV3Stat().readdirplusOpsAmount.load());
	nfsV3Stat["fsstat"] = Json::Value(_service._analyzer.getNfsV3Stat().fsstatOpsAmount.load());
	nfsV3Stat["fsinfo"] = Json::Value(_service._analyzer.getNfsV3Stat().fsinfoOpsAmount.load());
	nfsV3Stat["pathconf"] = Json::Value(_service._analyzer.getNfsV3Stat().pathconfOpsAmount.load());
	nfsV3Stat["commit"] = Json::Value(_service._analyzer.getNfsV3Stat().commitOpsAmount.load());
	root["nfs_v3"] = nfsV3Stat;
	Json::Value nfsV4Stat(Json::objectValue);
	nfsV4Stat["null"] = Json::Value(_service._analyzer.getNfsV4Stat().nullOpsAmount.load());
	nfsV4Stat["compound"] = Json::Value(_service._analyzer.getNfsV4Stat().compoundOpsAmount.load());
	root["nfs_v4"] = nfsV4Stat;
	Json::StyledWriter writer;
	std::string json = writer.write(root);

	/*ssize_t bytesSent = */send(socket(), json.data(), json.size(), MSG_NOSIGNAL);
	// TODO: Check result
}

//------------------------------------------------------------------------------

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
