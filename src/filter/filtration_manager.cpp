//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manager for all instances created inside filter module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <memory> // std::auto_ptr

#include "common/filtration_processor.h"
#include "common/dumping.h"
#include "common/queueing.h"
#include "filtration_manager.h"
#include "pcap/capture_reader.h"
#include "pcap/file_reader.h"
#include "processing_thread.h"
//------------------------------------------------------------------------------
using NST::filter::pcap::CaptureReader;
using NST::filter::pcap::FileReader;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

static std::auto_ptr<CaptureReader> create_capture_reader(const Parameters& params)
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

FiltrationManager::FiltrationManager(RunningStatus& s) : status(s)
{
}
FiltrationManager::~FiltrationManager()
{
}

void FiltrationManager::dump_to_file(const Parameters& params)
{
    typedef FiltrationProcessor<CaptureReader, Dumping> Processor;
    typedef ProcessingThread<Processor> OnlineDumping;

    std::auto_ptr<CaptureReader> reader = create_capture_reader(params);
    std::auto_ptr<Dumping>       writer (new Dumping(reader->get_handle(),
                                                     params.output_file(),
                                                     params.compression(),
                                                     params.dumping_size()));

    std::auto_ptr<Processor>     processor (new Processor(reader, writer));
    std::auto_ptr<OnlineDumping> thread    (new OnlineDumping(processor, status));

    threads.add(thread.release());
}

void FiltrationManager::capture_to_queue(FilteredDataQueue& queue, const Parameters& params)
{
    typedef FiltrationProcessor<CaptureReader, Queueing> Processor;
    typedef ProcessingThread<Processor> OnlineAnalyzing;

    std::auto_ptr<CaptureReader> reader = create_capture_reader(params);
    std::auto_ptr<Queueing>      writer (new Queueing(queue));

    std::auto_ptr<Processor>       processor (new Processor(reader, writer));
    std::auto_ptr<OnlineAnalyzing> thread    (new OnlineAnalyzing(processor, status));

    threads.add(thread.release());
}

void FiltrationManager::read_to_queue(FilteredDataQueue& queue, const Parameters& params)
{
    typedef FiltrationProcessor<FileReader, Queueing> Processor;
    typedef ProcessingThread<Processor> OfflineAnalyzing;

    std::auto_ptr<FileReader> reader (new FileReader(params.input_file()));
    std::auto_ptr<Queueing>   writer (new Queueing(queue));

    std::auto_ptr<Processor>        processor (new Processor(reader, writer));
    std::auto_ptr<OfflineAnalyzing> thread    (new OfflineAnalyzing(processor, status));

    threads.add(thread.release());
}

void FiltrationManager::start()
{
    threads.start();
}

void FiltrationManager::stop()
{
    threads.stop();
}

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
