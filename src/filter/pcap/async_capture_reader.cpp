//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Implementation of Asynchronous Buffered Capturing
/*
    The prototype of special CaptureReader - AsyncCaptureReader.
    Implements buffering of capturing pcap packets in tmpfile().
    The capturing pcap packets is doing in encapsulated pthread
    that is created and joined in loop() call.
    That thread will capture packets and dump them to a pcap 
    'savefile' created by ::tmpfile(). After capturing some packets
    it will 'close' tmpfile and pass FD of tmpfile to a thread
    that invoke the loop() - it is 'user' thread. The loop in
    loop() waits a completion of filling tmpfile, then read data 
    from it.and pass captured packets to an user callback.while
    capturing thread continues capturing files from interface.

    The implementation isn't well done. It uses volatile bool do_capturing;
    for breaking internal loops. So, live-lock is expected.
    Error handling isn't good too.
*/
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <stdio.h>  // fdopen() fileno()
#include <iostream>

#include <unistd.h>

#include "../../auxiliary/logger.h"
#include "async_capture_reader.h"
#include "bpf.h"
#include "file_reader.h"
#include "pcap_error.h"
#include "packet_dumper.h"
//------------------------------------------------------------------------------
using NST::auxiliary::ConditionalVariable;
using NST::auxiliary::Mutex;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

AsyncCaptureReader::AsyncCaptureReader(
                    const std::string& interface,
                    const std::string& filter,
                    int snaplen,
                    int to_ms,
                    int buffer_size)
                    : CaptureReader(interface, filter, snaplen, to_ms, buffer_size)
                    , persistent_capture_cycles(buffer_size/snaplen)
                    , do_capturing(false)
                    , fd_dump(-1)
                    , user_loop_tid(0)
{
}
AsyncCaptureReader::~AsyncCaptureReader()
{
}

bool AsyncCaptureReader::loop(void*const user, const pcap_handler user_callback)
{
    user_loop_tid = pthread_self(); // Wait me if somethig happens!

    bool done = false;  // we must return something

    do_capturing = true;    // set it to 'true' only once
    pthread_t capturing_tid = 0;
    int err = pthread_create(&capturing_tid, NULL, capturing_thread, this);

    if(err != 0)
    {
        LOG("Spawn capturing thread in AsyncCaptureReader failed.");
    }
    else while(do_capturing) // do_capturing means do processing too
    {
        // WAIT COMPLETION OF CAPTURING PORTION OF DATA TO FILE in special thread
        int dumped_fd = -1;
        Mutex::Lock lock(mutex);
        {
            condition.wait(mutex);
            dumped_fd = fd_dump;    // take out FD of dumped tmp file from volatile variable
            fd_dump = -1;           // reset volatile variable
        }

        TRACE("FD of current dump file is: %i", dumped_fd);
        if(dumped_fd == -1) // 'special' case like program should be closed or SOMETHING GOING WRONG???
        {
            do_capturing = false;
            break;
        }

        FILE* dumping = fdopen(dumped_fd, "r");
        if(dumping == NULL)
        {
            do_capturing = false;
            break;
        }

        rewind(dumping);    // move to beginning of dumped file

        try
        {
            // dumping will be closed in destroy of FileReader dump_reader instance
            // open pcap device for reading from dumped file
            FileReader dump_reader(dumping);

            // pass collected in dump file packets to user callback
            done = dump_reader.loop(user, user_callback, 0/*unlimited*/);
        }
        catch(Exception& e)
        {
            std::cout << e.what() << std::endl;
            pthread_cancel(capturing_tid);
            void *res;
            pthread_join(capturing_tid, &res);
            throw;  // yep, it is DISASTER somewhere in FiltrationProcessor
        }
    }

    void *res;
    pthread_join(capturing_tid, &res);

    user_loop_tid = 0; // I am go out, bye!

    return done;
}

void AsyncCaptureReader::break_loop()
{
    {
        Mutex::Lock lock(mutex);
        do_capturing = false;
        BaseReader::break_loop();   // break loop in internal capturing thread
    }

    if(user_loop_tid != 0)
    {
        // so wait that user thread
        void *res;
        pthread_join(user_loop_tid, &res);
    }
}

// dump packet to file
static void capturing_callback(u_char *dumper, const struct pcap_pkthdr *pkthdr, const u_char* packet)
{
    pcap_dump(dumper, pkthdr, packet);
}

// thread for capturing pcap packets as soon as possible
void* AsyncCaptureReader::capturing_thread(void *arg)
{
    AsyncCaptureReader* const me = (AsyncCaptureReader*)arg;

    while(me->do_capturing) try
    {
        // init pcap dumper by new tmp file
        PacketDumper dumper(me->handle, ::tmpfile());

        // looping
        const bool done = me->BaseReader::loop(dumper.get_dumper(), capturing_callback, me->persistent_capture_cycles);

        dumper.flush(); // enshure that data flushed
        FILE* stream = dumper.get_stream();

        {   // set FD of created file
            Mutex::Lock lock(me->mutex);
                me->fd_dump = dup(fileno(stream)); // TODO: check -1 (achieving limit of FD per process) , nice achievement ;)
                me->condition.signal(); // notify user thread completion about
        }
        TRACE("size of dumped file: %li", ftell(stream));

        if(!done)
        {
            return NULL;  // it was pcap_breakloop() - go out!
        }
    }
    catch(PcapError& e)
    {
        LOG("capturing thread in AsyncCaptureReader fails with error: %s", e.what());

        // unblock user thread
        Mutex::Lock lock(me->mutex);
            me->do_capturing = false;   // stop all internal loops!
            me->condition.signal();     // notify user thread
    }

    return NULL;
}

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
