//------------------------------------------------------------------------------
// Author: Dzianis Huznou 
// Description: Entry for all operations under plugin_api.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "plugin_api_struct.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

std::ostream& operator<<(std::ostream& out, const Session& session)
{
    switch(session.ip_type)
    {
        case Session::v4:
        {
            uint32_t ip = session.ip.v4.addr[Session::Source];
            out << ((ip >> 24) & 0xFF);
            out << '.';
            out << ((ip >> 16) & 0xFF);
            out << '.';
            out << ((ip >> 8) & 0xFF);
            out << '.';
            out << ((ip >> 0) & 0xFF);
            out << ':' << session.port[Session::Source];
        }
            out << " --> ";
        {
            uint32_t ip = session.ip.v4.addr[Session::Destination];
            out << ((ip >> 24) & 0xFF);
            out << '.';
            out << ((ip >> 16) & 0xFF);
            out << '.';
            out << ((ip >> 8) & 0xFF);
            out << '.';
            out << ((ip >> 0) & 0xFF);
            out << ':' << session.port[Session::Destination];
        }
        break;
        case Session::v6:
            out << "IPv6 is not supported yet.";
        break;
    }
    switch(session.type)
    {
        case Session::TCP:
            out << " [TCP]";
            break;
        case Session::UDP:
            out << " [UDP]";
            break;
    }
    return out;
}

namespace {
const char* Titles[ProcEnum::count] =
{
  "NULL",       "GETATTR",      "SETATTR",  "LOOKUP",
  "ACCESS",     "READLINK",     "READ",     "WRITE",
  "CREATE",     "MKDIR",        "SYMLINK",  "MKNOD",
  "REMOVE",     "RMDIR",        "RENAME",   "LINK",
  "READDIR",    "READDIRPLUS",  "FSSTAT",   "FSINFO",
  "PATHCONF",   "COMMIT"
};
}

std::ostream& operator<<(std::ostream& out, const ProcEnum::NFSProcedure proc)
{
    return out << Titles[proc];
}

//------------------------------------------------------------------------------
