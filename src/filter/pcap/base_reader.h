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

    bool loop(void* user, pcap_handler callback, unsigned int count=0)
    {
        return -1 != pcap_loop(handle, count, callback, (u_char*)user);
    }

    inline void break_loop() { pcap_breakloop(handle); }

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
