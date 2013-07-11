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
namespace filter
{
namespace pcap
{

class Handle
{
public:
    inline Handle(pcap_t* p = NULL):handle(p){}
    inline ~Handle()
    {
        if(handle)
        {
            pcap_close(handle);
        }
    }

    inline void operator=(pcap_t* p) { handle = p; }
    inline      operator bool   () const { return NULL != handle; }
    inline      operator pcap_t*() const { return handle; }

private:
    Handle(const Handle&);            // undefined
    Handle& operator=(const Handle&); // undefined

    pcap_t* handle;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//HANDLE_H
//------------------------------------------------------------------------------
