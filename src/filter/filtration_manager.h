//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside filter module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FILTRATION_MANAGER
#define FILTRATION_MANAGER
//------------------------------------------------------------------------------
#include <pcap/pcap.h>
#include <algorithm> // std::for_each macros
#include <vector> // std::vector

#include "../auxiliary/thread.h"
#include "pcap/packet_capture.h"
#include "pcap/packet_reader.h"
#include "pcap/base_reader.h"
#include "pcap/pcap_error.h"
#include "processing_thread.h"
//------------------------------------------------------------------------------
using NST::filter::pcap::PacketCapture;
using NST::filter::pcap::PacketReader;
using NST::filter::pcap::BaseReader; // Will be removed after creation of appropriate processor
using NST::filter::pcap::PcapError;
using NST::auxiliary::Thread;
using NST::filter::ProcessingThread;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
//------------------------------------------------------------------------------
// REMOVED AFTER CREATING APPROPRIATE PROCESSOR
class DumpToFileProcessor
{
public:
    DumpToFileProcessor(const std::string& path_to_file): path(path_to_file),dumper(NULL)
    {
    }
    ~DumpToFileProcessor()
    {
        if(dumper)
        {
            pcap_dump_close(dumper);
        }
    }

    void before_callback(pcap_t* handle)
    {
        dumper = pcap_dump_open(handle, path.c_str());
        if(NULL == dumper)
        {
            throw PcapError("pcap_dump_open", pcap_geterr(handle));
        }
    }

    void after_callback(pcap_t* handle)
    {
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
        dumper = NULL;
    }

    u_char* get_user()
    {
        return (u_char*)dumper;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        pcap_dumper_t* dumper = (pcap_dumper_t*) user;

        pcap_dump((u_char*)dumper, pkthdr, packet);
    }

private:
    const std::string path;
    pcap_dumper_t* dumper;
};
//------------------------------------------------------------------------------

class FiltrationManager
{
public:
    FiltrationManager(int threads_limit) : limit(threads_limit), threads(limit) {}

    ~FiltrationManager()
    {
        std::for_each(threads.begin(), threads.end(), destroy_thread);
    }

    void dump_to_file(const std::string &interface, const std::string &filter, int snaplen, int ms, const std::string &file)
    {
        PacketCapture* reader = new PacketCapture(interface, filter, snaplen, ms);
        DumpToFileProcessor* processor = new DumpToFileProcessor(file);
        ProcessingThread<PacketCapture, DumpToFileProcessor>* proc_thread = new ProcessingThread<PacketCapture, DumpToFileProcessor>(reader, processor);
        proc_thread->create();
        threads.push_back((Thread*)proc_thread);
    }

    void stop_all()
    {
        std::for_each(threads.begin(), threads.end(), stop_thread);
    }

private:
    static void destroy_thread(Thread *thread)
    {
        delete thread;
    }

    static void stop_thread(Thread* thread)
    {
        thread->stop();
    }
private:
    int limit;
    std::vector<Thread*> threads;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTRATION_MANAGER
//------------------------------------------------------------------------------
