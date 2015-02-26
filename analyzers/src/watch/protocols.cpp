
#include "protocols.h"

AbstractProtocol::AbstractProtocol(const char* n, std::size_t i)
: name{n}
, amount{i}
{
}

AbstractProtocol::~AbstractProtocol()
{
}

const char* AbstractProtocol::printProcedure(std::size_t)
{
    return nullptr;
}

std::string AbstractProtocol::getProtocolName()
{
    return name;
}

unsigned int AbstractProtocol::getAmount()
{
    return amount;
}
//------------------------------------------------------------------------------
NFSv3Protocol::NFSv3Protocol()
: AbstractProtocol{"NFS v3", ProcEnumNFS3::count}
{
}

NFSv3Protocol::~NFSv3Protocol()
{
}

const char* NFSv3Protocol::printProcedure(std::size_t i)
{
    if( i > ProcEnumNFS3::count) return nullptr;
    return  print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(i));
}
//------------------------------------------------------------------------------
NFSv4Protocol::NFSv4Protocol()
: AbstractProtocol{"NFS v4", ProcEnumNFS4::count}
{
}

NFSv4Protocol::~NFSv4Protocol()
{
}

const char* NFSv4Protocol::printProcedure(std::size_t i)
{
    if( i > ProcEnumNFS4::count) return nullptr;
    return  print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(i));
}
//------------------------------------------------------------------------------
NFSv41Protocol::NFSv41Protocol()
: AbstractProtocol{"NFS v41", ProcEnumNFS41::count}
{
}

NFSv41Protocol::~NFSv41Protocol()
{
}

const char* NFSv41Protocol::printProcedure(std::size_t i)
{
    if( i > ProcEnumNFS41::count) return nullptr;
    return  print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(i));
}
//------------------------------------------------------------------------------
