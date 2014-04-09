//------------------------------------------------------------------------------
// Author: Dzianis Huznou 
// Description: Entry for all operations under plugin_api.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <arpa/inet.h>  // for inet_ntop(), ntohs()
#include <sys/socket.h> // for AF_INET/AF_INET6

#include "plugin_api_struct.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

std::ostream& operator<<(std::ostream& out, const Session& session)
{
    switch(session.ip_type)
    {
        case Session::IPType::v4:
        {
            static_assert(sizeof(session.ip.v4.addr[Session::Source]) == sizeof(struct in_addr), "they should be equal");

            char buf[INET_ADDRSTRLEN];
            {
                const char* str = inet_ntop(AF_INET, &(session.ip.v4.addr[Session::Source]), buf, sizeof(buf));
                out << (str ? str : "Invalid IPv4 address of source host")
                    << ':' << ntohs(session.port[Session::Source]);
            }
            out << " --> ";
            {
                const char* str = inet_ntop(AF_INET, &(session.ip.v4.addr[Session::Destination]), buf, sizeof(buf));
                out << (str ? str : "Invalid IPv4 address of destination host")
                    << ':' << ntohs(session.port[Session::Destination]);
            }
        }
        break;
        case Session::IPType::v6:
        {
            static_assert(sizeof(session.ip.v6.addr[Session::Source]) == sizeof(struct in6_addr), "they should be equal");

            char buf[INET6_ADDRSTRLEN];
            {
                const char* str = inet_ntop(AF_INET6, &(session.ip.v6.addr[Session::Source]), buf, sizeof(buf));
                out << (str ? str : "Invalid IPv6 address of source host")
                    << ':' << ntohs(session.port[Session::Source]);
            }
            out << " --> ";
            {
                const char* str = inet_ntop(AF_INET6, &(session.ip.v6.addr[Session::Destination]), buf, sizeof(buf));
                out << (str ? str : "Invalid IPv6 address of destination host")
                    << ':' << ntohs(session.port[Session::Destination]);
            }
        }
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
