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
       void before_callback(pcap_t* handle)
       void  after_callback(pcap_t* handle)
       u_char* get_user()
       static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)

       The before_callback() function will be called before call BaseReader::loop().
       The callback() function will be called for each packet filtered by BPF.
       The result of get_user() will be passed to callback() as u_char *user.
       The after_callback() function will be called after exit BaseReader::loop().
    */
    template<class Processor>
    inline bool loop(Processor& p, unsigned int count=0)
    {
        p.Processor::before_callback(handle);
        bool result = loop(p.Processor::get_user(), &Processor::callback, count);
        p.Processor::after_callback(handle);
        return result;
    }

    bool loop(void* user, pcap_handler callback, unsigned int count=0) throw (PcapError)
    {
        int err = pcap_loop(handle, count, callback, (u_char*)user);
        if(err == -1)
        {
            throw PcapError("pcap_loop", pcap_geterr(handle));
        }
        if(err == -2)   // pcap_breakloop() called
        {
            return false;
        }
        return true; // count iterations are done
    }

    inline void break_loop() { pcap_breakloop(handle); }

protected:
    Handle handle;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_READER_H
//------------------------------------------------------------------------------
