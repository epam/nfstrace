//------------------------------------------------------------------------------
// Author: Pavel Karneliuk (Dzianis Huznou)
// Description: High level interface for passing info Processor.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef BASE_READER_H
#define BASE_READER_H
//------------------------------------------------------------------------------
#include <ostream>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include <pcap/pcap.h>
#include <signal.h>

#include "filtration/pcap/pcap_error.h"
#include "utils/noncopyable.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{
inline const char* library_version()
{
    return pcap_lib_version();
}

class BaseReader : utils::noncopyable
{
protected:
    BaseReader(const std::string& input)
        : handle{nullptr}
        , source{input}
        , in_loop{false}
        , loop_exit_status{0}
        , pcap_loop_thread{}
    {
    }

    virtual ~BaseReader()
    {
        if(handle)
        {
            pcap_close(handle);
        }
    }

public:
    bool loop(void* user, pcap_handler callback, int count = 0)
    {
        std::unique_lock<std::mutex> lck { loop_mutex };
        
        in_loop = true;
        pcap_loop_thread = std::thread([this, count, callback, user](){
            /* We put pcap_loop in separate thread main reason is because we need to stop loop when stop
               is called.
               Please check following links:
               https://github.com/the-tcpdump-group/libpcap/issues/734
               https://linux.die.net/man/3/pcap_breakloop
               https://www.tcpdump.org/manpages/pcap_breakloop.3pcap.html
            */
            const int err{pcap_loop(handle, count, callback, (u_char*)user)};
            loop_finished(err);
        });

        while (in_loop) {
            loop_cond.wait(lck);
        }

        if (loop_exit_status == -1) {
            throw PcapError("pcap_loop", pcap_geterr(handle));
        }

        return loop_exit_status == 0;
    }

    void stop() {
        break_loop();
        /// TODO: Maybe it is better to reuse pthreads here without std::thread
        ::pthread_cancel(pcap_loop_thread.native_handle());
        pcap_loop_thread.join();
        loop_finished(0);
    }

    inline void               break_loop() { pcap_breakloop(handle); }
    inline pcap_t*&           get_handle() { return handle; }
    inline int                datalink() const { return pcap_datalink(handle); }
    inline static const char* datalink_name(const int dlt) { return pcap_datalink_val_to_name(dlt); }
    inline static const char* datalink_description(const int dlt) { return pcap_datalink_val_to_description(dlt); }
    virtual void print_statistic(std::ostream& out) const = 0;

private:
    void loop_finished(int status) {
        std::unique_lock<std::mutex> lck { loop_mutex };
        in_loop = false;
        loop_exit_status = status;
        loop_cond.notify_all();
    }

protected:
    pcap_t*           handle;
    const std::string source;
    std::atomic<bool> in_loop;
    int loop_exit_status;
    std::thread pcap_loop_thread;
    std::condition_variable loop_cond;
    std::mutex loop_mutex;
};

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif // BASE_READER_H
//------------------------------------------------------------------------------
