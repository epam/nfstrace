//------------------------------------------------------------------------------
// Author: Pavel Karneliuk (Dzianis Huznou)
// Description: High level interface for passing info Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BASE_READER_H
#define BASE_READER_H
//------------------------------------------------------------------------------
#include <ostream>
#include <string>

#include <pcap/pcap.h>

#include "handle.h"
#include "pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

class BaseReader
{
protected:
    BaseReader()
    {
    }
    virtual ~BaseReader()
    {
    }

public:
    bool loop(void* user, pcap_handler callback, int count=0)
    {
        const int err = pcap_loop(handle, count, callback, (u_char*)user);
        if(err == -1) throw PcapError("pcap_loop", pcap_geterr(handle));

        return err == 0; // count is exhausted
    }

    void                 break_loop() { pcap_breakloop(handle); }
    inline const Handle& get_handle() const { return handle; }

    inline        const int   datalink             () const { return pcap_datalink(handle); }
    inline static const char* datalink_name        (const int dlt) { return pcap_datalink_val_to_name(dlt);        }
    inline static const char* datalink_description (const int dlt) { return pcap_datalink_val_to_description(dlt); }

    std::string last_error() const { return std::string(pcap_geterr(handle)); }

    virtual void print_statistic(std::ostream& out) const = 0;

protected:
    Handle handle;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_READER_H
//------------------------------------------------------------------------------
