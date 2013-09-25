//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Structure describing command-line arguments.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "cmdline_args.h"
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

const char* const Args::profiling_mode  = LIVE;
const char* const Args::filtration_mode = DUMP;
const char* const Args::analysis_mode   = STAT;

// This array will be indexed via elements of Args::Names enumeration. Keep it in the same order.
Opt Args::options[Args::num] =
{
    {'i', "interface",  Opt::REQ, "",                    "listen interface, it is required for "LIVE" and "DUMP" modes","INTERFACE"},
    {'f', "filter",     Opt::REQ, "tcp port 2049",       "a packet filter in libpcap BPF syntax",               "BPF"},
    {'s', "snaplen",    Opt::REQ, "65535",               "max length of raw captured packet. May be used ONLY FOR UDP", "0..65535"},
    {'m', "mode",       Opt::REQ, LIVE,                  "set runing mode",                                     LIVE"|"DUMP"|"STAT },
    {'a', "analyzer",   Opt::REQ, "",                    "specify path to analysis module and pass desired options", "PATH#opt1,opt2=val,..." },
    {'I', "ifile",      Opt::REQ, "INTERFACE-BPF.pcap",  "input file for "STAT" mode, the '-' means stdin",     "PATH"},
    {'O', "ofile",      Opt::REQ, "INTERFACE-BPF.pcap",  "output file for "DUMP" mode, the '-' means stdout",   "PATH"},
    {'C', "command",    Opt::REQ, "",                    "execute command for each dumped file"},
    {'D', "dump-size",  Opt::REQ, "0",                   "size of dumping file portion in MBytes, 0 = no limit","0.."},
    {'B', "bsize",      Opt::REQ, "2",                   "size of capturing kernel buffer in MBytes",           "1.."},
    {'M', "msg-header", Opt::REQ, "512",                 "RPC message will be truncated to this limit in bytes before passing to Analysis", "1..4000"},
    {'Q', "qcapacity",  Opt::REQ, "256",                 "initial queue capacity of RPC messages",              "1..65535"},
    {'v', "verbose",    Opt::NOA, "false",               "print out additional information and trace to console collected NFSv3 procedures"},
    {'h', "help",       Opt::NOA, "false",               "print this help message and usage for analyzers passed via -a options, then exit"}
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
