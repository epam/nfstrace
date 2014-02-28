//------------------------------------------------------------------------------
// Author: Pavel Karneliuk (Dzianis Huznou)
// Description: Wrapper for pcap handle.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef HANDLE_H
#define HANDLE_H
//------------------------------------------------------------------------------
#include <pcap/pcap.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

class Handle
{
public:
    inline Handle(pcap_t* p = nullptr) : handle{p}{}
    inline Handle(const Handle&)            = delete;
    inline Handle& operator=(const Handle&) = delete;
    inline ~Handle()
    {
        if(handle)
        {
            pcap_close(handle);
        }
    }

    inline void operator=(pcap_t* p)       { handle = p; }
    inline      operator bool     () const { return handle; }
    inline      operator pcap_t*  () const { return handle; }

private:
    pcap_t* handle;
};

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//HANDLE_H
//------------------------------------------------------------------------------
