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
#include "../controller/parameters.h"
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
using NST::controller::Parameters;
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

    void dump_to_file(const Parameters& params)
    {
        typedef FiltrationProcessor<CaptureReader, DumpingTransmission> Processor;
        typedef ProcessingThread<Processor> OnlineDumping;

        std::auto_ptr<CaptureReader>        reader = create_capture_reader(params);
        std::auto_ptr<DumpingTransmission>  writer (new DumpingTransmission(reader->get_handle(), params.output_file()));

        std::auto_ptr<Processor>      processor (new Processor(reader, writer));
        std::auto_ptr<OnlineDumping>  thread    (new OnlineDumping(processor, status));

        threads.add(thread.release());
        throw Exception("Dumping mode is turned off in this version");
    }

    void capture_to_queue(FilteredDataQueue& queue, const Parameters& params)
    {
        typedef FiltrationProcessor<CaptureReader, QueueingTransmission> Processor;
        typedef ProcessingThread<Processor> OnlineAnalyzing;

        std::auto_ptr<CaptureReader>        reader = create_capture_reader(params);
        std::auto_ptr<QueueingTransmission> writer (new QueueingTransmission(queue));

        std::auto_ptr<Processor>     processor (new Processor(reader, writer));
        std::auto_ptr<OnlineAnalyzing>  thread (new OnlineAnalyzing(processor, status));

        threads.add(thread.release());
    }

    void read_to_queue(FilteredDataQueue& queue, const Parameters& params)
    {
        typedef FiltrationProcessor<FileReader, QueueingTransmission> Processor;
        typedef ProcessingThread<Processor> OfflineAnalyzing;

        std::auto_ptr<FileReader>           reader (new FileReader(params.input_file()));
        std::auto_ptr<QueueingTransmission> writer (new QueueingTransmission(queue));

        std::auto_ptr<Processor>      processor (new Processor(reader, writer));
        std::auto_ptr<OfflineAnalyzing>  thread (new OfflineAnalyzing(processor, status));

        threads.add(thread.release());
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

    std::auto_ptr<CaptureReader> create_capture_reader(const Parameters& params)
    {
        const int read_timeout = 250; // milliseconds
        std::auto_ptr<CaptureReader> reader (new CaptureReader(params.interface(),
                                                               params.filter(),
                                                               params.snaplen(),
                                                               read_timeout,
                                                               params.buffer_size()
                                                               ));
        return reader;
    }

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
