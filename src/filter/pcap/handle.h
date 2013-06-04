//------------------------------------------------------------------------------
// Author: Pavel Karneliuk (Dzianis Huznou)
// Description: High level interface for passing info Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef HANDLE_H
#define HANDLE_H
//------------------------------------------------------------------------------
#include <string>
#include <iostream>

#include <pcap/pcap.h>

#include "pcap_error.h"
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
    Handle(pcap_t* p = NULL):handle(p){}
    ~Handle()
    {
        if(handle)
        {
            pcap_close(handle);
        }
    }
    Handle(const Handle&);            // undefined
    Handle& operator=(const Handle&); // undefined

    inline void operator=(pcap_t* p) { handle = p; }
    inline      operator bool   () { return NULL != handle; }
    inline      operator pcap_t*() const { return handle; }

private:
    pcap_t* handle;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//HANDLE_H
//------------------------------------------------------------------------------
