//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Structure describing command-line arguments.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "controller/cmdline_args.h"
//------------------------------------------------------------------------------
#define LIVE "live"
#define DUMP "dump"
#define STAT "stat"
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{
namespace cmdline
{

const char* const Args::profiling_mode = LIVE;
const char* const Args::dumping_mode   = DUMP;
const char* const Args::analysis_mode  = STAT;

// This array will be indexed via elements of Args::Names enumeration. Keep it in the same order.
Opt Args::options[Args::num] =
{
    {'i', "interface",  Opt::REQ, "",                    "listen interface, it is required for " LIVE " and " DUMP " modes", "INTERFACE",      nullptr, false},
    {'f', "filtration", Opt::REQ, "ip and port 2049",    "a packet filtration in libpcap BPF syntax",                        "BPF",            nullptr, false},
    {'s', "snaplen",    Opt::REQ, "65535",               "max length of raw captured packet. May be used ONLY FOR UDP",      "0..65535",       nullptr, false},
    {'t', "timeout",    Opt::REQ, "250",                 "set the read timeout that will be used on a capture",              "Milliseconds",   nullptr, false},
    {'m', "mode",       Opt::REQ, LIVE,                  "set runing mode",                                          LIVE "|" DUMP "|" STAT,   nullptr, false},
    {'a', "analysis",   Opt::MUL, "",                    "specify path to analysis module and pass desired options", "PATH#opt1,opt2=val,...", nullptr, false},
    {'I', "ifile",      Opt::REQ, "INTERFACE-BPF.pcap",  "input file for " STAT " mode, the '-' means stdin",        "PATH",   nullptr, false},
    {'O', "ofile",      Opt::REQ, "INTERFACE-BPF.pcap",  "output file for " DUMP " mode, the '-' means stdout",      "PATH",   nullptr, false},
    {'C', "command",    Opt::REQ, "",                    "execute command for each dumped file",                     nullptr,  nullptr, false},
    {'D', "dump-size",  Opt::REQ, "0",                   "size of dumping file portion, 0 = no limit",               "MBytes", nullptr, false},
    {'B', "bsize",      Opt::REQ, "20",                  "size of capturing kernel buffer",                          "MBytes", nullptr, false},
    {'M', "msg-header", Opt::REQ, "512",                 "RPC message will be truncated to this limit in bytes before passing to Analysis", "1..4000", nullptr, false},
    {'Q', "qcapacity",  Opt::REQ, "4096",                "initial queue capacity of RPC messages",                                         "1..65535", nullptr, false},
    {'v', "verbose",    Opt::NOA, "false",               "print out additional information and trace to console collected NFSv3 procedures", nullptr, nullptr, false},
    {'h', "help",       Opt::NOA, "false",               "print this help message and usage for modules passed via -a options, then exit", nullptr, nullptr, false}
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
