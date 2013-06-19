//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PRINT_ANALYZER_H
#define PRINT_ANALYZER_H
//------------------------------------------------------------------------------
#include <iostream>
#include <sstream>

#include "../filter/rpc/rpc_message.h"
#include "base_analyzer.h"
#include "nfs_data.h"
//------------------------------------------------------------------------------
using namespace NST::filter::rpc;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer 
{

struct ProcNFS3 // counters definition for NFS v3 procedures. See: RFC 1813
{
    enum Ops
    {
        NFS_NULL        = 0,
        NFS_GETATTR     = 1,
        NFS_SETATTR     = 2,
        NFS_LOOKUP      = 3,
        NFS_ACCESS      = 4,
        NFS_READLINK    = 5,
        NFS_READ        = 6,
        NFS_WRITE       = 7,
        NFS_CREATE      = 8,
        NFS_MKDIR       = 9,
        NFS_SYMLINK     = 10,
        NFS_MKNOD       = 11,
        NFS_REMOVE      = 12,
        NFS_RMDIR       = 13,
        NFS_RENAME      = 14,
        NFS_LINK        = 15,
        NFS_READDIR     = 16,
        NFS_READDIRPLUS = 17,
        NFS_FSSTAT      = 18,
        NFS_FSINFO      = 19,
        NFS_PATHCONF    = 20,
        NFS_COMMIT      = 21,
        num             = 22,
    };

    static const char* titles[num];
};

class PrintAnalyzer : public BaseAnalyzer
{
public:
    PrintAnalyzer()
    {
    }
    virtual ~PrintAnalyzer()
    {
    }

    virtual void process(NFSData* data)
    {
        std::cout << "###\n";
        std::cout << "Source: " << session_addr(NFSData::Session::Source, data) << ";";
        std::cout << "Destination: " << session_addr(NFSData::Session::Destination, data) << "\n";
        std::cout << rpc_info(data) << "\n";
    }
    virtual void result()
    {
    }

private:
    std::string rpc_info(NFSData* data)
    {
        const MessageHeader* msg = (MessageHeader*)data->rpc_message;
        std::stringstream message(std::ios_base::out);
        message << "XID: " << msg->xid() << " ";
        switch(msg->type())
        {
            case SUNRPC_CALL:
            {
                const CallHeader* call = static_cast<const CallHeader*>(msg);

                uint32_t rpcvers = call->rpcvers();
                uint32_t prog = call->prog();
                uint32_t vers = call->vers();
                uint32_t proc = call->proc();

                if(rpcvers != 2)    return 0;
                if(prog != 100003)  return 0;  // portmap NFS v3 TCP 2049
                if(vers != 3)       return 0;  // NFS v3

                message << "Call: " << ProcNFS3::titles[proc];
            }
            break;
            case SUNRPC_REPLY:
            {
                const ReplyHeader* reply = static_cast<const ReplyHeader*>(msg);
                switch(reply->stat())
                {
                    case SUNRPC_MSG_ACCEPTED:
                    {
                        message << "Reply accepted.";
                        // TODO: check accepted reply
                    }
                    break;
                    case SUNRPC_MSG_DENIED:
                    {
                        message << "Reply denied.";
                        // TODO: check rejected reply
                    }
                    break;
                }
            }
            break;
        }
        return message.str();
    }

    std::string session_addr(NFSData::Session::Direction dir, NFSData* data)
    {
        std::stringstream session(std::ios_base::out);
        switch(data->session.ip_type)
        {
            case NFSData::Session::v4:
                session << ipv4_string(data->session.ip.v4.addr[dir]);
                break;
            case NFSData::Session::v6:
                session << ipv6_string(data->session.ip.v6.addr[dir]);
                break;
        }
        session << ":" << data->session.port[dir];
        switch(data->session.type)
        {
            case NFSData::Session::TCP:
                session << " (TCP)";
                break;
            case NFSData::Session::UDP:
                session << " (UPD)";
                break;
        }
        return session.str();
    }

    std::string ipv6_string(uint8_t ip[16])
    {
        std::stringstream address(std::ios_base::out);
        address << "IPV6";
        return address.str();
    }

    std::string ipv4_string(uint32_t ip /*host byte order*/ )
    {
        std::stringstream address(std::ios_base::out);
        address << ((ip >> 24) & 0xFF);
        address << '.';
        address << ((ip >> 16) & 0xFF);
        address << '.';
        address << ((ip >> 8) & 0xFF);
        address << '.';
        address << ((ip >> 0) & 0xFF);
        return address.str();
    }
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PRINT_ANALYZER_H
//------------------------------------------------------------------------------
