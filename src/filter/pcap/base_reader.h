//------------------------------------------------------------------------------
// Author: Pavel Karneliuk (Dzianis Huznou)
// Description: High level interface for passing info Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BASE_READER_H
#define BASE_READER_H
//------------------------------------------------------------------------------
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
public:
    BaseReader() {}
    virtual ~BaseReader() {}

    /*
       Processor - class that implements following functions accessible from BaseReader:
       u_char* get_user()
       static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)

       The callback() function will be called for each packet filtered by BPF.
       The result of get_user() will be passed to callback() as u_char *user.
    */
    template<class Processor>
    inline bool loop(Processor& p, int count=0)
    {
        return loop(p.Processor::get_user(), &Processor::callback, count);
    }

    bool loop(void* user, pcap_handler callback, int count)
    {
        return -1 != pcap_loop(handle, count, callback, (u_char*)user);
    }

    inline void          break_loop() { pcap_breakloop(handle); }
    inline const Handle& get_handle() const { return handle; }

    std::string last_error() const { return std::string(pcap_geterr(handle)); }

protected:
    Handle handle;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_READER_H
//------------------------------------------------------------------------------
