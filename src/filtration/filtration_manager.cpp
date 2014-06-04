//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manager for all instances created inside filtration module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "filtration/dumping.h"
#include "filtration/filtration_manager.h"
#include "filtration/filtration_processor.h"
#include "filtration/pcap/capture_reader.h"
#include "filtration/pcap/file_reader.h"
#include "filtration/processing_thread.h"
#include "filtration/queuing.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

using CaptureReader = NST::filtration::pcap::CaptureReader;
using FileReader    = NST::filtration::pcap::FileReader;

using Parameters        = NST::controller::Parameters;
using RunningStatus     = NST::controller::RunningStatus;
using FilteredDataQueue = NST::utils::FilteredDataQueue;

namespace // unnamed
{

// FiltrationProcessor in separate processing thread
template
<
    typename Reader,
    typename Writer
>
class FiltrationImpl : public ProcessingThread
{
public:
    explicit FiltrationImpl(std::unique_ptr<Reader>& reader,
                            std::unique_ptr<Writer>& writer,
                            RunningStatus& status)
    : ProcessingThread {status}
    , processor{reader, writer}
    {
    }
    ~FiltrationImpl() = default;
    FiltrationImpl(const FiltrationImpl&)            = delete;
    FiltrationImpl& operator=(const FiltrationImpl&) = delete;

    virtual void stop() override final
    {
        processor.stop();
    }
private:

    virtual void run() override final
    {
        try
        {
            processor.run();
        }
        catch(...)
        {
            ProcessingThread::status.push_current_exception();
        }
    }

    FiltrationProcessor<Reader, Writer> processor;
};

// create Filtration thread emplaced in unique_ptr
template
<
    typename Reader,
    typename Writer
>
static auto create_thread(std::unique_ptr<Reader>& reader,
                          std::unique_ptr<Writer>& writer,
                          RunningStatus& status)
        -> std::unique_ptr<FiltrationImpl<Reader, Writer>>
{
    using Thread = FiltrationImpl<Reader, Writer>;

    return std::unique_ptr<Thread>{new Thread{reader, writer, status}};
}


// create CaptureReader from Parameters emplaced in unique_ptr
static auto create_capture_reader(const Parameters& params)
        -> std::unique_ptr<CaptureReader>
{
    auto& capture_params = params.capture_params();
    if(utils::Out message{}) // print parameters to user
    {
        message << capture_params;
    }
    return std::unique_ptr<CaptureReader>{ new CaptureReader{capture_params} };
}

} // unnamed namespace

// capture from network interface and dump to file  - OnlineDumping(Dumping)
void FiltrationManager::add_online_dumping(const Parameters& params)
{
    std::unique_ptr<CaptureReader> reader { create_capture_reader(params) };

    auto& dumping_params = params.dumping_params();
    if(utils::Out message{}) // print parameters to user
    {
        message << dumping_params;
    }
    std::unique_ptr<Dumping>       writer { new Dumping{ reader->get_handle(),
                                                         dumping_params
                                                       }
                                          };

    threads.emplace_back(create_thread(reader, writer, status));
}

// capture from network interface and pass to queue - OnlineAnalysis(Profiling)
void FiltrationManager::add_online_analysis(const Parameters& params,
                                            FilteredDataQueue& queue)
{
    std::unique_ptr<CaptureReader> reader { create_capture_reader(params) };
    std::unique_ptr<Queueing>      writer { new Queueing{queue}           };

    threads.emplace_back(create_thread(reader, writer, status));
}

// read from file and pass to queue - OfflineAnalysis(Analysis)
void FiltrationManager::add_offline_analysis(const std::string& ifile,
                                             FilteredDataQueue& queue)
{
    std::unique_ptr<FileReader> reader { new FileReader{ifile} };

    {
        utils::Out message; // print parameters to user
        message << *reader.get();
    }
    std::unique_ptr<Queueing>   writer { new Queueing{queue}   };

    threads.emplace_back(create_thread(reader, writer, status));
}

FiltrationManager::FiltrationManager(RunningStatus& s)
: status(s)
{
    if(utils::Out message{utils::Out::Level::All})
    {
        message << "Libpcap version: " << pcap::library_version();
    }
}

FiltrationManager::~FiltrationManager()
{
    stop(); // additional checking before cleaning table
}

void FiltrationManager::start()
{
    for(auto& th : threads)
    {
        th->start();
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