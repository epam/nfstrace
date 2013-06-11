//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside filter module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FILTRATION_MANAGER_H
#define FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
#include <algorithm> // std::for_each macros
#include <memory> // std::auto_ptr
#include <vector> // std::vector

#include <pcap/pcap.h>

#include "../controller/running_status.h"
#include "common/simply_nfs_filtrator.h"
#include "../auxiliary/thread_group.h"
#include "pcap/packet_capture.h"
#include "pcap/packet_reader.h"
#include "processing_thread.h"
#include "pcap/base_reader.h" // Will be removed after creation of appropriate processor
#include "pcap/pcap_error.h" // Will be removed after creation of appropriate processor
//------------------------------------------------------------------------------
using NST::controller::RunningStatus;
using NST::filter::pcap::PacketCapture;
using NST::filter::pcap::PacketReader;
using NST::filter::ProcessingThread;
using NST::filter::pcap::BaseReader; // Will be removed after creation of appropriate processor
using NST::filter::pcap::PcapError;
using NST::auxiliary::ThreadGroup;
using NST::auxiliary::Thread;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class FiltrationManager
{
    typedef ProcessingThread<PacketCapture, SimplyNFSFiltrator> OnlineDumpingThread;
    // OnlineAnalyzingThread and OfflineAnalyzingThread typedefs will be added later.
public:
    FiltrationManager(RunningStatus &running_status) : excpts_holder(running_status)
    {
    }
    ~FiltrationManager()
    {
        thread_group.stop();
    }

    void dump_to_file(const std::string &interface, const std::string &filter, int snaplen, int ms, const std::string &file)
    {
        std::auto_ptr<PacketCapture>        reader      (new PacketCapture(interface, filter, snaplen, ms));
        std::auto_ptr<SimplyNFSFiltrator>   processor   (new SimplyNFSFiltrator(file));
        std::auto_ptr<OnlineDumpingThread>  proc_thread (new OnlineDumpingThread(reader.release(), processor.release(), excpts_holder));

        thread_group.add((Thread*)proc_thread.release());
    }

    void start()
    {
        thread_group.start();
    }

    void stop()
    {
        thread_group.stop();
    }

private:
    FiltrationManager(const FiltrationManager& object); // Uncopyable object
    FiltrationManager& operator=(const FiltrationManager& object); // Uncopyable object

private:
    ThreadGroup thread_group;
    RunningStatus &excpts_holder;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
