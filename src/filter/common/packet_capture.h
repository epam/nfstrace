//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class for capturing libpcap packets and pass them to a Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H
//------------------------------------------------------------------------------
#include <string>
#include <iostream>

#include <pcap/pcap.h>

#include "../pcap/pcap_error.h"
//------------------------------------------------------------------------------
using NST::filter::pcap::PcapError;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class PacketCapture
{
public:
    PacketCapture(const std::string& interface, const std::string& filter, int snaplen, int to_ms) throw (PcapError);
    ~PacketCapture();

    bool set_buffer_size(int size);

    /*
        Processor - class that implements following functions accessible from PacketCapture:
            void before_callback(pcap_t* handle)
            void  after_callback(pcap_t* handle)
            u_char* get_user()
     static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)

        The before_callback() function will be called before call PacketCapture::loop().
        The callback() function will be called for each packet filtered by BPF.
        The result of get_user() will be passed to callback() as u_char *user.
        The after_callback() function will be called after exit PacketCapture::loop().
    */
    template<class Processor>
    inline bool loop(Processor& p, unsigned int count=0)
    {
        p.Processor::before_callback(handle);
        bool result = loop(p.Processor::get_user(), &Processor::callback, count);
        p.Processor::after_callback(handle);
        return result;
    }

    bool loop(void* user, pcap_handler callback, unsigned int count=0) throw (PcapError);

    inline void break_loop() { pcap_breakloop(handle); }
    inline int  datalink  () { return pcap_datalink(handle); }

    void print_statistic(std::ostream& out) const throw (PcapError);
    void print_datalink (std::ostream& out) const;

    static const std::string get_default_device() throw (PcapError);

private:
    class BPF
    {
    public:
        BPF(pcap_t* handle, const char* filter, bpf_u_int32 netmask)
        {
            if(pcap_compile(handle, &bpf, filter, 1 /*optimize*/, netmask) < 0)
            {
                throw PcapError("pcap_compile", pcap_geterr(handle));
            }
        }
        ~BPF()
        {
            pcap_freecode(&bpf);
        }
        BPF(const BPF&);            // undefined
        BPF& operator=(const BPF&); // undefined

        inline operator bpf_program*() { return &bpf; }

    private:
        bpf_program bpf;
    };

    class Handle
    {
    public:
        Handle(pcap_t* p):handle(p){}
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

    Handle handle;
};

class SampleProcessor  // Sample of parameter to PacketCapture::loop<Processor>()
{
public:
    SampleProcessor()
    {
    }
    ~SampleProcessor()
    {
    }

private:
    friend class PacketCapture;

    void before_callback(pcap_t* handle)
    {
    }
    void after_callback(pcap_t* handle)
    {
    }

    u_char* get_user()
    {
        return (u_char*)this;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
    }
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_CAPTURE_H
//------------------------------------------------------------------------------
