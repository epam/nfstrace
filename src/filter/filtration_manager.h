//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside filter module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FILTRATION_MANAGER_H
#define FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
#include <memory> // std::auto_ptr

#include "../auxiliary/filtered_data.h"
#include "../auxiliary/thread_group.h"
#include "../controller/running_status.h"
#include "common/filtration_processor.h"
#include "common/dumping_transmission.h"
#include "common/queueing_transmission.h"
#include "pcap/capture_reader.h"
#include "pcap/file_reader.h"
#include "processing_thread.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredDataQueue;
using NST::auxiliary::ThreadGroup;
using NST::controller::RunningStatus;
using NST::filter::pcap::CaptureReader;
using NST::filter::pcap::FileReader;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class FiltrationManager
{
public:
    FiltrationManager(RunningStatus& s) : status(s)
    {
    }
    ~FiltrationManager()
    {
    }

    void dump_to_file(const std::string& file, const std::string& interface, const std::string& bpf, int snaplen, int ms)
    {
        typedef FiltrationProcessor<CaptureReader, DumpingTransmission> Processor;
        typedef ProcessingThread<Processor> OnlineDumping;

        std::auto_ptr<CaptureReader>        reader (new CaptureReader(interface, bpf, snaplen, ms));
        std::auto_ptr<DumpingTransmission>  writer (new DumpingTransmission(reader->get_handle(), file));

        std::auto_ptr<Processor>      processor (new Processor(reader, writer));
        std::auto_ptr<OnlineDumping>  thread    (new OnlineDumping(processor, status));

        threads.add(thread.release());
    }

    void capture_to_queue(FilteredDataQueue& queue, const std::string& interface, const std::string& bpf, int snaplen, int ms)
    {
        typedef FiltrationProcessor<CaptureReader, QueueingTransmission> Processor;
        typedef ProcessingThread<Processor> OnlineAnalyzing;

        std::auto_ptr<CaptureReader>        reader (new CaptureReader(interface, bpf, snaplen, ms));
        std::auto_ptr<QueueingTransmission> writer (new QueueingTransmission(queue));

        std::auto_ptr<Processor>     processor (new Processor(reader, writer));
        std::auto_ptr<OnlineAnalyzing>  thread (new OnlineAnalyzing(processor, status));

        threads.add(thread.release());
    }

    void read_from_file(const std::string& file)
    {
        // TODO: implement Offline analyzing mode
    }

    void start()
    {
        threads.start();
    }

    void stop()
    {
        threads.stop();
    }

private:
    FiltrationManager(const FiltrationManager&);            // undefined
    FiltrationManager& operator=(const FiltrationManager&); // undefined

    ThreadGroup threads;
    RunningStatus &status;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
