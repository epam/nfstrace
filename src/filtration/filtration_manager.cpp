//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manager for all instances created inside filtration module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "filtration/common/filtration_processor.h"
#include "filtration/common/dumping.h"
#include "filtration/common/queueing.h"
#include "filtration/filtration_manager.h"
#include "filtration/pcap/capture_reader.h"
#include "filtration/pcap/file_reader.h"
#include "filtration/processing_thread.h"
//------------------------------------------------------------------------------
using NST::filtration::pcap::CaptureReader;
using NST::filtration::pcap::FileReader;
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

static std::unique_ptr<CaptureReader> create_capture_reader(const Parameters& params)
{
    return std::unique_ptr<CaptureReader>{
                                new CaptureReader{
                                        params.interface(),
                                        params.filtration(),
                                        params.snaplen(),
                                        params.timeout(),
                                        params.buffer_size()
                                     }
                                };
}

FiltrationManager::FiltrationManager(RunningStatus& s, const Parameters& params)
: status(s)
{
    using Processor     = FiltrationProcessor<CaptureReader, Dumping>;
    using OnlineDumping = ProcessingThread<Processor>;

    std::unique_ptr<CaptureReader> reader { create_capture_reader(params) };
    std::unique_ptr<Dumping>       writer { new Dumping{
                                                reader->get_handle(),
                                                params.output_file(),
                                                params.dumping_cmd(),
                                                params.dumping_size()
                                            }
                                          };

    std::unique_ptr<Processor>     processor {new Processor{reader, writer}};

    std::unique_ptr<Thread> thread{new OnlineDumping{processor, status}};

    threads.emplace_back(std::move(thread));
}
FiltrationManager::FiltrationManager(RunningStatus& s, FilteredDataQueue& queue, const Parameters& params)
: status(s)
{
    using Processor       = FiltrationProcessor<CaptureReader, Queueing>;
    using OnlineAnalyzing = ProcessingThread<Processor>;

    std::unique_ptr<CaptureReader> reader { create_capture_reader(params) };
    std::unique_ptr<Queueing>      writer { new Queueing(queue)           };

    std::unique_ptr<Processor>     processor{new Processor{reader, writer}};

    std::unique_ptr<Thread> thread{new OnlineAnalyzing{processor, status}};

    threads.emplace_back(std::move(thread));
}
FiltrationManager::FiltrationManager(RunningStatus& s, FilteredDataQueue& queue, const std::string& ifile)
: status(s)
{
    using Processor        = FiltrationProcessor<FileReader, Queueing>;
    using OfflineAnalyzing = ProcessingThread<Processor>;

    std::unique_ptr<FileReader> reader { new FileReader{ifile} };
    std::unique_ptr<Queueing>   writer { new Queueing{queue}   };

    std::unique_ptr<Processor> processor{new Processor{reader, writer}};

    std::unique_ptr<Thread>    thread{new OfflineAnalyzing{processor, status}};

    threads.emplace_back(std::move(thread));
}
FiltrationManager::~FiltrationManager()
{
    stop(); // additional checking before cleaning table
}

void FiltrationManager::start()
{
    for(auto& th : threads)
    {
        th->create();
    }
}

void FiltrationManager::stop()
{
    for(auto& th : threads)
    {
        th->stop();
    }
}

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
