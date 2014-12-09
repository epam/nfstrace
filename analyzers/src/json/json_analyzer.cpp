//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: JSON analyzer class
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

#include "json_analyzer.h"

JsonAnalyzer::JsonAnalyzer(std::size_t workersAmount, int port, const std::string& host, std::size_t maxServingDurationMs, int backlog) :
	_jsonTcpService(*this, workersAmount, port, host, maxServingDurationMs, backlog),
	_nfsV3Stat(),
	_nfsV4Stat()
{
	//std::cout << "JsonAnalyzer::JsonAnalyzer(" << port << ", " << workersAmount << ')' << std::endl;
}

/*JsonAnalyzer::~JsonAnalyzer()
{
	//std::cout << "JsonAnalyzer::~JsonAnalyzer()" << std::endl;
}*/

void JsonAnalyzer::null(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::NULL3args* /*args*/,
		const struct rpcgen::NULL3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::null()" << std::endl;
	_nfsV3Stat.nullOpsAmount++;
}

void JsonAnalyzer::getattr3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::GETATTR3args* /*args*/,
		const struct rpcgen::GETATTR3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::getattr3()" << std::endl;
	_nfsV3Stat.getattrOpsAmount++;
}

void JsonAnalyzer::setattr3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::SETATTR3args* /*args*/,
		const struct rpcgen::SETATTR3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::setattr3()" << std::endl;
	_nfsV3Stat.setattrOpsAmount++;
}

void JsonAnalyzer::lookup3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::LOOKUP3args* /*args*/,
		const struct rpcgen::LOOKUP3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::lookup3()" << std::endl;
	_nfsV3Stat.lookupOpsAmount++;
}

void JsonAnalyzer::access3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::ACCESS3args* /*args*/,
		const struct rpcgen::ACCESS3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::access3()" << std::endl;
	_nfsV3Stat.accessOpsAmount++;
}

void JsonAnalyzer::readlink3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::READLINK3args* /*args*/,
		const struct rpcgen::READLINK3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::readlink3()" << std::endl;
	_nfsV3Stat.readlinkOpsAmount++;
}

void JsonAnalyzer::read3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::READ3args* /*args*/,
		const struct rpcgen::READ3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::read3()" << std::endl;
	_nfsV3Stat.readOpsAmount++;
}

void JsonAnalyzer::write3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::WRITE3args* /*args*/,
		const struct rpcgen::WRITE3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::write3()" << std::endl;
	_nfsV3Stat.writeOpsAmount++;
}

void JsonAnalyzer::create3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::CREATE3args* /*args*/,
		const struct rpcgen::CREATE3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::create3()" << std::endl;
	_nfsV3Stat.createOpsAmount++;
}

void JsonAnalyzer::mkdir3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::MKDIR3args* /*args*/,
		const struct rpcgen::MKDIR3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::mkdir3()" << std::endl;
	_nfsV3Stat.mkdirOpsAmount++;
}

void JsonAnalyzer::symlink3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::SYMLINK3args* /*args*/,
		const struct rpcgen::SYMLINK3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::symlink3()" << std::endl;
	_nfsV3Stat.symlinkOpsAmount++;
}

void JsonAnalyzer::mknod3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::MKNOD3args* /*args*/,
		const struct rpcgen::MKNOD3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::mknod3()" << std::endl;
	_nfsV3Stat.mknodOpsAmount++;
}

void JsonAnalyzer::remove3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::REMOVE3args* /*args*/,
		const struct rpcgen::REMOVE3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::remove3()" << std::endl;
	_nfsV3Stat.removeOpsAmount++;
}

void JsonAnalyzer::rmdir3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::RMDIR3args* /*args*/,
		const struct rpcgen::RMDIR3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::rmdir3()" << std::endl;
	_nfsV3Stat.rmdirOpsAmount++;
}

void JsonAnalyzer::rename3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::RENAME3args* /*args*/,
		const struct rpcgen::RENAME3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::rename3()" << std::endl;
	_nfsV3Stat.renameOpsAmount++;
}

void JsonAnalyzer::link3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::LINK3args* /*args*/,
		const struct rpcgen::LINK3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::link3()" << std::endl;
	_nfsV3Stat.linkOpsAmount++;
}

void JsonAnalyzer::readdir3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::READDIR3args* /*args*/,
		const struct rpcgen::READDIR3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::readdir3()" << std::endl;
	_nfsV3Stat.readdirOpsAmount++;
}

void JsonAnalyzer::readdirplus3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::READDIRPLUS3args* /*args*/,
		const struct rpcgen::READDIRPLUS3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::readdirplus3()" << std::endl;
	_nfsV3Stat.readdirplusOpsAmount++;
}

void JsonAnalyzer::fsstat3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::FSSTAT3args* /*args*/,
		const struct rpcgen::FSSTAT3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::fsstat3()" << std::endl;
	_nfsV3Stat.fsstatOpsAmount++;
}

void JsonAnalyzer::fsinfo3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::FSINFO3args* /*args*/,
		const struct rpcgen::FSINFO3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::fsinfo3()" << std::endl;
	_nfsV3Stat.fsinfoOpsAmount++;
}

void JsonAnalyzer::pathconf3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::PATHCONF3args* /*args*/,
		const struct rpcgen::PATHCONF3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::pathconf3()" << std::endl;
	_nfsV3Stat.pathconfOpsAmount++;
}

void JsonAnalyzer::commit3(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::COMMIT3args* /*args*/,
		const struct rpcgen::COMMIT3res* /*res*/)
{
	//std::cout << "JsonAnalyzer::commit3()" << std::endl;
	_nfsV3Stat.commitOpsAmount++;
}

void JsonAnalyzer::null(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::NULL4args* /*args*/,
		const struct rpcgen::NULL4res* /*res*/)
{
	//std::cout << "JsonAnalyzer::null()" << std::endl;
	_nfsV4Stat.nullOpsAmount++;
}
void JsonAnalyzer::compound4(const struct RPCProcedure* /*proc*/,
		const struct rpcgen::COMPOUND4args* /*args*/,
		const struct rpcgen::COMPOUND4res* /*res*/)
{
	//std::cout << "JsonAnalyzer::compound4()" << std::endl;
	_nfsV4Stat.compoundOpsAmount++;
}

void JsonAnalyzer::flush_statistics()
{
	//std::cout << "JsonAnalyzer::flush_statistics()" << std::endl;
}
