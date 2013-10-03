//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manager for all instances created inside filter module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "../auxiliary/unique_ptr.h"
#include "common/filtration_processor.h"
#include "common/dumping.h"
#include "common/queueing.h"
#include "filtration_manager.h"
#include "pcap/async_capture_reader.h"
#include "pcap/capture_reader.h"
#include "pcap/file_reader.h"
#include "processing_thread.h"
//------------------------------------------------------------------------------
using NST::auxiliary::UniquePtr;
using NST::filter::pcap::AsyncCaptureReader;
using NST::filter::pcap::CaptureReader;
using NST::filter::pcap::FileReader;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

template <typename CaptureReaderType>
static UniquePtr<CaptureReaderType> create_capture_reader(const Parameters& params)
{
    const int read_timeout = 250; // milliseconds
    UniquePtr<CaptureReaderType> reader (new CaptureReaderType(
                                            params.interface(),
                                            params.filter(),
                                            params.snaplen(),
                                            read_timeout,
                                            params.buffer_size()
                                            )
                                        );
    return reader;
}

FiltrationManager::FiltrationManager(RunningStatus& s, const Parameters& params) : status(s)
{
    if(params.tmp_buffering())
    {
        typedef FiltrationProcessor<AsyncCaptureReader, Dumping> AsyncProcessor;
        typedef ProcessingThread<AsyncProcessor> OnlineDumping;

        UniquePtr<AsyncCaptureReader> reader = create_capture_reader<AsyncCaptureReader>(params);
        UniquePtr<Dumping>            writer (new Dumping(reader->get_handle(),
                                                     params.output_file(),
                                                     params.dumping_cmd(),
                                                     params.dumping_size()));

        UniquePtr<AsyncProcessor>     processor (new AsyncProcessor(reader, writer));
        UniquePtr<Thread> thread      (new OnlineDumping(processor, status));

        threads.add(thread);
    }
    else
    {
        typedef FiltrationProcessor<CaptureReader, Dumping> Processor;
        typedef ProcessingThread<Processor> OnlineDumping;

        UniquePtr<CaptureReader> reader = create_capture_reader<CaptureReader>(params);
        UniquePtr<Dumping>       writer (new Dumping(reader->get_handle(),
                                                     params.output_file(),
                                                     params.dumping_cmd(),
                                                     params.dumping_size()));

        UniquePtr<Processor>     processor (new Processor(reader, writer));
        UniquePtr<Thread> thread    (new OnlineDumping(processor, status));

        threads.add(thread);
    }
}
FiltrationManager::FiltrationManager(RunningStatus& s, FilteredDataQueue& queue, const Parameters& params) : status(s)
{
    if(params.tmp_buffering())
    {
        typedef FiltrationProcessor<AsyncCaptureReader, Queueing> AsyncProcessor;
        typedef ProcessingThread<AsyncProcessor> OnlineAnalyzing;

        UniquePtr<AsyncCaptureReader>   reader = create_capture_reader<AsyncCaptureReader>(params);
        UniquePtr<Queueing>             writer (new Queueing(queue));

        UniquePtr<AsyncProcessor>       processor (new AsyncProcessor(reader, writer));
        UniquePtr<Thread> thread        (new OnlineAnalyzing(processor, status));

        threads.add(thread);
    }
    else
    {
        typedef FiltrationProcessor<CaptureReader, Queueing> Processor;
        typedef ProcessingThread<Processor> OnlineAnalyzing;

        UniquePtr<CaptureReader>   reader = create_capture_reader<CaptureReader>(params);
        UniquePtr<Queueing>        writer (new Queueing(queue));

        UniquePtr<Processor>       processor (new Processor(reader, writer));
        UniquePtr<Thread> thread   (new OnlineAnalyzing(processor, status));

        threads.add(thread);
    }
}
FiltrationManager::FiltrationManager(RunningStatus& s, FilteredDataQueue& queue, const std::string& ifile) : status(s)
{
    typedef FiltrationProcessor<FileReader, Queueing> Processor;
    typedef ProcessingThread<Processor> OfflineAnalyzing;

    UniquePtr<FileReader> reader (new FileReader(ifile));
    UniquePtr<Queueing>   writer (new Queueing(queue));

    UniquePtr<Processor>        processor (new Processor(reader, writer));
    UniquePtr<Thread> thread    (new OfflineAnalyzing(processor, status));

    threads.add(thread);
}
FiltrationManager::~FiltrationManager()
{
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
