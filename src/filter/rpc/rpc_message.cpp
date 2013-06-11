//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Implementation of Sun RPC functions
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include "rpc_message.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace rpc
{

AuthSYS::AuthSYS(const OpaqueAuthHeader* header)
{
    const char* data = header->opaque_data();
    // parse AUTH_SYS parameters
    m_stamp = ntohl(*((uint32_t*)data));
    data += sizeof(uint32_t);

    uint32_t machinename_len = ntohl(*((uint32_t*)data));
    data += sizeof(uint32_t);

    m_machinename = std::string(data, machinename_len);
    data += rpc_roundup(machinename_len); // round up length to 4 byte words

    m_uid = ntohl(*((uint32_t*)data));
    data += sizeof(uint32_t);

    m_gid = ntohl(*((uint32_t*)data));
    data += sizeof(uint32_t);

    m_guid_count = ntohl(*((uint32_t*)data));
    data += sizeof(uint32_t);

    for(unsigned int i=0; i<m_guid_count; i++)
    {
        m_guids[i] = ntohl(((uint32_t*)data)[i]);
    }
}

uint32_t rpc_roundup(uint32_t a)
{
    uint32_t mod = a % 4;
    uint32_t ret = a + ((mod)? 4-mod : 0);
    return ret;
}

std::ostream& operator<<(std::ostream& out, const OpaqueAuthHeader& a)
{

    switch(a.flavor())
    {
        case AUTH_NONE:
        {
            out << "AUTH_NONE";
        }
        break;
        case AUTH_SYS:
        {
            out << "AUTH_SYS";
        }
        break;
        default:
            out << "UNKNOWN id:" << a.flavor();
    }

    out << " len:" << a.len();

    switch(a.flavor())
    {
        case AUTH_NONE:
        {
        }
        break;
        case AUTH_SYS:
        {
            out << AuthSYS(&a);
        }
        break;
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const AuthSYS& a)
{
    out << " stamp:" << a.stamp();
    out << " machinename:" << a.machinename();
    out << " uid:" << a.uid();
    out << " gid:" << a.gid();
    out << " gids[" << a.guid_count() << "]: ";
    const uint32_t* guids = a.guids();
    for(unsigned int i=0; i<a.guid_count(); i++)
    {
        out << guids[i] << ' ';
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const CallHeader& a)
{
    out << "XID:" << a.xid();
    out << " type:" << a.type();
    out << " rpcvers:" << a.rpcvers();
    out << " prog:" << a.prog();
    out << " vers:" << a.vers();
    out << " proc:" << a.proc();

    const OpaqueAuthHeader* cred = a.credential();
    const OpaqueAuthHeader* verf = a.verifier();

    out << " credential:[" << *cred << "]";
    out << " verifier:[" << *verf << "]";

    return out;
}

} // namespace rpc
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------

