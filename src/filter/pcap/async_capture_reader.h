//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Asynchronous Buffered Capturing pcap frames from an interface
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ASYNC_CAPTURE_READER_H
#define ASYNC_CAPTURE_READER_H
//------------------------------------------------------------------------------
#include <pthread.h>

#include "../../auxiliary/conditional_variable.h"
#include "../../auxiliary/mutex.h"
#include "capture_reader.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

class AsyncCaptureReader : public CaptureReader
{
public:

    AsyncCaptureReader(const std::string& interface,
                       const std::string& filter,
                       int snaplen,
                       int to_ms,
                       int buffer_size);
    ~AsyncCaptureReader();

    bool loop(void*const user, const pcap_handler user_callback);

    void break_loop();

private:
    // thread for capturing pcap packets as soon as possible
    static void* capturing_thread(void *arg);

    const int persistent_capture_cycles;
    volatile bool do_capturing;
    volatile int  fd_dump;

    volatile pthread_t user_loop_tid;
    NST::auxiliary::Mutex mutex;
    NST::auxiliary::ConditionalVariable condition;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//ASYNC_CAPTURE_READER_H
//------------------------------------------------------------------------------
