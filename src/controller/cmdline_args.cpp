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

#define OB      "ob"    // Operation Breakdown
#define OFWS    "ofws"  // Overall File Working Set
#define OFDWS   "ofdws" // Overall File Data Working Set
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

const char* const Args::ob_analyzer     = OB;
const char* const Args::ofws_analyzer   = OFWS;
const char* const Args::ofdws_analyzer  = OFDWS;

// This array will be indexed via elements of Args::Names enumeration. Keep it in the same order.
Opt Args::options[Args::num] =
{
    {'i', "interface",  Opt::REQ,  NULL,                 "listen interface",                                    "INTERFACE"},
    {'f', "filter",     Opt::REQ, "tcp port 2049",       "a packet filter in libpcap BPF syntax",               "BPF"},
    {'s', "snaplen",    Opt::REQ, "65535",               "max length of raw captured packet",                   "0..65535"},
    {'m', "mode",       Opt::REQ,  LIVE,                 "set runing mode",                                     LIVE"|"DUMP"|"STAT },
    {'a', "analyzers",  Opt::REQ,  OB,                   "use specified analyzer",                              OB"|"OFWS"|"OFDWS"|PATH" },
    {'I', "ifile",      Opt::REQ, "INTERFACE-BPF.pcap",  "input file to "STAT" mode, the '-' means stdin",      "PATH"},
    {'O', "ofile",      Opt::REQ, "INTERFACE-BPF.pcap",  "output file to "DUMP" mode, the '-' means stdout",    "PATH"},
    {'C', "command",    Opt::REQ, "",                    "execute command for each dumped file"},
    {'D', "dump-size",  Opt::REQ, "0",                   "size of dumping file portion in MBytes, 0 = no limit","0.."},
    {'B', "bsize",      Opt::REQ, "2",                   "size of capturing kernel buffer in MBytes",           "1.."},
    {'M', "msg-header", Opt::REQ, "512",                 "RPC message will be truncated to this limit in bytes before passing to Analysis", "1..4000"},
    {'Q', "qcapacity",  Opt::REQ, "256",                 "initial queue capacity of RPC messages",              "1..65535"},
    {'L', "blsize",     Opt::REQ, "16",                  "block data size [KB]",                                "4..1024" },
    {'U', "busize",     Opt::REQ, "8",                   "size of bucket used by ofdws analyzer",               "1..32768"},
    {'v', "verbose",    Opt::NOA, "false",               "print out additional information"},
    {'h', "help",       Opt::NOA, "false",               "print this help message and exit"}
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
