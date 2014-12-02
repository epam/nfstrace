//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: WebUI analyzer class
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

#include "webui_analyzer.h"

WebUiAnalyzer::WebUiAnalyzer(std::size_t workersAmount, int port, const std::string& host, std::size_t maxServingDurationMs, int backlog) :
	_jsonTcpService(*this, workersAmount, port, host, maxServingDurationMs, backlog),
	_nfsV3Stat(),
	_nfsV4Stat()
{
	//std::cout << "WebUiAnalyzer::WebUiAnalyzer(" << port << ", " << workersAmount << ')' << std::endl;
}

/*WebUiAnalyzer::~WebUiAnalyzer()
{
	//std::cout << "WebUiAnalyzer::~WebUiAnalyzer()" << std::endl;
}*/

void WebUiAnalyzer::null(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::NULL3args* /*args*/,
		const struct rpcgen::NULL3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::null()" << std::endl;
	_nfsV3Stat.nullOpsAmount++;
}

void WebUiAnalyzer::getattr3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::GETATTR3args* /*args*/,
		const struct rpcgen::GETATTR3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::getattr3()" << std::endl;
	_nfsV3Stat.getattrOpsAmount++;
}

void WebUiAnalyzer::setattr3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::SETATTR3args* /*args*/,
		const struct rpcgen::SETATTR3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::setattr3()" << std::endl;
	_nfsV3Stat.setattrOpsAmount++;
}

void WebUiAnalyzer::lookup3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::LOOKUP3args* /*args*/,
		const struct rpcgen::LOOKUP3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::lookup3()" << std::endl;
	_nfsV3Stat.lookupOpsAmount++;
}

void WebUiAnalyzer::access3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::ACCESS3args* /*args*/,
		const struct rpcgen::ACCESS3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::access3()" << std::endl;
	_nfsV3Stat.accessOpsAmount++;
}

void WebUiAnalyzer::readlink3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::READLINK3args* /*args*/,
		const struct rpcgen::READLINK3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::readlink3()" << std::endl;
	_nfsV3Stat.readlinkOpsAmount++;
}

void WebUiAnalyzer::read3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::READ3args* /*args*/,
		const struct rpcgen::READ3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::read3()" << std::endl;
	_nfsV3Stat.readOpsAmount++;
}

void WebUiAnalyzer::write3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::WRITE3args* /*args*/,
		const struct rpcgen::WRITE3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::write3()" << std::endl;
	_nfsV3Stat.writeOpsAmount++;
}

void WebUiAnalyzer::create3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::CREATE3args* /*args*/,
		const struct rpcgen::CREATE3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::create3()" << std::endl;
	_nfsV3Stat.createOpsAmount++;
}

void WebUiAnalyzer::mkdir3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::MKDIR3args* /*args*/,
		const struct rpcgen::MKDIR3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::mkdir3()" << std::endl;
	_nfsV3Stat.mkdirOpsAmount++;
}

void WebUiAnalyzer::symlink3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::SYMLINK3args* /*args*/,
		const struct rpcgen::SYMLINK3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::symlink3()" << std::endl;
	_nfsV3Stat.symlinkOpsAmount++;
}

void WebUiAnalyzer::mknod3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::MKNOD3args* /*args*/,
		const struct rpcgen::MKNOD3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::mknod3()" << std::endl;
	_nfsV3Stat.mknodOpsAmount++;
}

void WebUiAnalyzer::remove3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::REMOVE3args* /*args*/,
		const struct rpcgen::REMOVE3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::remove3()" << std::endl;
	_nfsV3Stat.removeOpsAmount++;
}

void WebUiAnalyzer::rmdir3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::RMDIR3args* /*args*/,
		const struct rpcgen::RMDIR3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::rmdir3()" << std::endl;
	_nfsV3Stat.rmdirOpsAmount++;
}

void WebUiAnalyzer::rename3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::RENAME3args* /*args*/,
		const struct rpcgen::RENAME3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::rename3()" << std::endl;
	_nfsV3Stat.renameOpsAmount++;
}

void WebUiAnalyzer::link3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::LINK3args* /*args*/,
		const struct rpcgen::LINK3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::link3()" << std::endl;
	_nfsV3Stat.linkOpsAmount++;
}

void WebUiAnalyzer::readdir3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::READDIR3args* /*args*/,
		const struct rpcgen::READDIR3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::readdir3()" << std::endl;
	_nfsV3Stat.readdirOpsAmount++;
}

void WebUiAnalyzer::readdirplus3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::READDIRPLUS3args* /*args*/,
		const struct rpcgen::READDIRPLUS3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::readdirplus3()" << std::endl;
	_nfsV3Stat.readdirplusOpsAmount++;
}

void WebUiAnalyzer::fsstat3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::FSSTAT3args* /*args*/,
		const struct rpcgen::FSSTAT3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::fsstat3()" << std::endl;
	_nfsV3Stat.fsstatOpsAmount++;
}

void WebUiAnalyzer::fsinfo3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::FSINFO3args* /*args*/,
		const struct rpcgen::FSINFO3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::fsinfo3()" << std::endl;
	_nfsV3Stat.fsinfoOpsAmount++;
}

void WebUiAnalyzer::pathconf3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::PATHCONF3args* /*args*/,
		const struct rpcgen::PATHCONF3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::pathconf3()" << std::endl;
	_nfsV3Stat.pathconfOpsAmount++;
}

void WebUiAnalyzer::commit3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::COMMIT3args* /*args*/,
		const struct rpcgen::COMMIT3res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::commit3()" << std::endl;
	_nfsV3Stat.commitOpsAmount++;
}

void WebUiAnalyzer::null(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::NULL4args* /*args*/,
		const struct rpcgen::NULL4res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::null()" << std::endl;
	_nfsV4Stat.nullOpsAmount++;
}
void WebUiAnalyzer::compound4(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::COMPOUND4args* /*args*/,
		const struct rpcgen::COMPOUND4res* /*res*/)
{
	//std::cout << "WebUiAnalyzer::compound4()" << std::endl;
	_nfsV4Stat.compoundOpsAmount++;
}

void WebUiAnalyzer::flush_statistics()
{
	//std::cout << "WebUiAnalyzer::flush_statistics()" << std::endl;
}
