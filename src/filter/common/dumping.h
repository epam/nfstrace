//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Dump filtered packets to .pcap file
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef DUMPING_H
#define DUMPING_H
//------------------------------------------------------------------------------
#include <cerrno>
#include <cstring> // memcpy()
#include <exception> // std::terminate()
#include <string>
#include <sstream>

#include <unistd.h>
#include <sys/time.h>

#include "../../auxiliary/logger.h"
#include "../../auxiliary/unique_ptr.h"
#include "../pcap/handle.h"
#include "../pcap/packet_dumper.h"
//------------------------------------------------------------------------------
using NST::filter::pcap::Handle;
using NST::filter::pcap::PacketDumper;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class Dumping
{
public:

    class Collection
    {
    public:
        inline Collection():dumper(NULL)
        {
            reset();
            timerclear(&last);
        }

        inline void operator=(Dumping& d) // initialization
        {
            dumper = &d;
            reset();
        }
        inline ~Collection()
        {
        }

//        Collection(const Collection&);            // undefiend
//        Collection& operator=(const Collection&); // undefiend
        inline Collection(const Collection& p) // move
        {

        }
        inline Collection& operator=(const Collection& p) // move
        {
            return *this;
        }

        inline void reset()
        {
            payload_len = 0;
        }

        inline void push(const PacketInfo& info, const uint32_t len)
        {
            if(timercmp(&last, &info.header->ts, !=))  // timestamps aren't equal
            {
                last = info.header->ts;
                // direct dumping without waiting completeness of analysis and complete() call
                dumper->dump(info.header, info.packet);
            }
            else
            {
                TRACE("The packet was collected before");
            }

            // copy payload
            memcpy(payload+payload_len, info.data, len);
            payload_len += len;
        }

        inline void skip_first(const uint32_t len)
        {
        }

        void complete(const PacketInfo& info)
        {
            assert(dumper);
            reset();
            dumper = NULL;
        }

        inline const uint32_t    size() const { return payload_len;    }
        inline const uint8_t*    data() const { return payload;        }
        inline    operator bool const() const { return dumper != NULL; }

    private:
        Dumping* dumper;
        uint8_t payload[4096];
        uint32_t payload_len;
        struct  timeval last;   // use timestamp as unique ID of packet
    };

    Dumping(const Handle& h, const std::string& path, const std::string& cmd, uint32_t size_limit)
        : handle(h)
        , base(path)
        , name(path)
        , command(cmd)
        , part(0)
        , size(0)
        , limit(size_limit)
    {
        open_dumping_file(name);
    }
    ~Dumping()
    {
        close_dumping_file();
    }

    inline void dump(const pcap_pkthdr* header, const u_char* packet)
    {
        if(limit)
        {
            if(size + sizeof(pcap_pkthdr) + header->caplen > limit)
            {
                close_dumping_file();

                ++part;
                char suffix[64];
                sprintf(suffix, "-%u", part);
                name = base + suffix;
                size = 0;
                open_dumping_file(name);

                dumper->truncate_all_pcap_data_and_header();
            }
            size += sizeof(pcap_pkthdr) + header->caplen;
        }

        dumper->dump(header, packet);
    }

private:

    inline void open_dumping_file(const std::string& file_path)
    {
        const char* path = file_path.c_str();
        LOG("Dumping packets to file:%s", path);
        dumper.reset(new PacketDumper(handle, path));
    }

    inline void close_dumping_file()
    {
        dumper.reset(); // close current dumper
        exec_command();
    }

    void exec_command()
    {
        if(command.empty()) return;

        NST::auxiliary::Logger::get_global().flush();   // force flush buffer

        if(pid_t pid = fork()) // spawn child process
        {
            // parrent process
            LOG("Try to execute(%s %s) in %u child process", command.c_str(), name.c_str(), pid);
            NST::auxiliary::Logger::get_global().flush();   // force flush buffer
            return;
        }

        // child process
        std::istringstream ss(command);
        std::vector<std::string> tokens;
        std::vector<char*> args;

        // TODO: this parser isn't works with dual quotes, like rm "a file.cpp"
        for(std::string arg; ss >> arg;)
        {
           tokens.push_back(arg);
           args  .push_back(const_cast<char*>(tokens.back().c_str()));
        }
        args.push_back(const_cast<char*>(name.c_str()));
        args.push_back(NULL);  // need terminating null pointer

        if(execvp(args[0], &args[0]) == -1)
        {
            LOG("execvp(%s,%s %s) return: %s", args[0], command.c_str(), name.c_str(), strerror(errno));
        }

        LOG("child process %u will be terminated.", getpid());
        std::terminate();
    }

    Dumping(const Dumping&);            // undefined
    Dumping& operator=(const Dumping&); // undefined

    NST::auxiliary::UniquePtr<PacketDumper> dumper;
    const Handle& handle;
    std::string base;
    std::string name;
    std::string command;
    uint32_t    part;
    uint32_t    size;
    const uint32_t limit;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//DUMPING_H
//------------------------------------------------------------------------------
