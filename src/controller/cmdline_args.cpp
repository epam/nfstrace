//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Structure describing command-line arguments.
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
#include "controller/cmdline_args.h"
//------------------------------------------------------------------------------
#define LIVE  "live"
#define DUMP  "dump"
#define STAT  "stat"
#define DRAIN "drain"
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{
namespace cmdline
{

const char* const Args::profiling_mode {LIVE};
const char* const Args::dumping_mode   {DUMP};
const char* const Args::analysis_mode  {STAT};
const char* const Args::draining_mode  {DRAIN};

// This array will be indexed via elements of Args::Names enumeration. Keep it in the same order.
Opt Args::options[Args::num] =
{
    {'m', "mode",       Opt::REQ, LIVE,                  "set the running mode",                           DRAIN "|" LIVE "|" DUMP "|" STAT,   nullptr, false},
    {'i', "interface",  Opt::REQ, "PCAP-DEFAULT",        "listen interface, it is required for " LIVE " and " DUMP " modes", "INTERFACE",      nullptr, false},
    {'f', "filtration", Opt::REQ, "port 2049",           "specify the packet filter in BPF syntax(see pcap-filter(7)",       "BPF",            nullptr, false},
    {'s', "snaplen",    Opt::REQ, "65535",               "set the max length of captured raw packet (bigger packets will be truncated). Can be used ONLY FOR UDP", "1..65535", nullptr, false},
    {'t', "timeout",    Opt::REQ, "100",                 "set the read timeout that will be used while capturing",           "Milliseconds",   nullptr, false},
    {'b', "bsize",      Opt::REQ, "20",                  "set the size of operation system capture buffer in MBytes; note that this option is crucial for capturing performance ", "MBytes", nullptr, false},
    {'p', "promisc",    Opt::REQ, "true",                "put the capturing interface into promiscuous mode",                   nullptr,                  nullptr, false},
    {'d', "direction",  Opt::REQ, "inout",               "set the direction for which packets will be captured",                "in|out|inout",           nullptr, false},
    {'a', "analysis",   Opt::MUL, "",                    "specify the path to an analysis module and set it's options (if any)","PATH#opt1,opt2=val,...", nullptr, false},
    {'I', "ifile",      Opt::REQ, "PROGRAMNAME-BPF.pcap","specify the input file for " STAT " mode, the '-' means stdin",       "PATH",                   nullptr, false},
    {'O', "ofile",      Opt::REQ, "PROGRAMNAME-BPF.pcap","specify the output file for " DUMP " mode, the '-' means stdout",     "PATH",                   nullptr, false},
    {'o', "log",        Opt::REQ, "nfstrace_logfile",    "specify the log file path",                                           "PATH",                   nullptr, false},
    {'C', "command",    Opt::REQ, "",                    "execute command for each dumped file",                                "\"shell command\"",      nullptr, false},
    {'D', "dump-size",  Opt::REQ, "0",                   "set the size of dumping file portion, 0 means no limit",              "MBytes",                 nullptr, false},
    {'L', "list",       Opt::NOA, "false",               "list all available network interfaces and exit",                      nullptr,                  nullptr, false},
    {'M', "msg-header", Opt::REQ, "512",                 "Truncate RPC messages to this limit (specified in bytes) before passing to a pluggable analysis module", "1..4000", nullptr, false},
    {'Q', "qcapacity",  Opt::REQ, "4096",                "set the initial capacity of the queue with RPC messages",                                   "1..65535", nullptr, false},
    {'T', "trace",      Opt::NOA, "false",               "print collected NFSv3 or NFSv4 procedures, true if no modules were passed with -a option",  nullptr,    nullptr, false},
    {'Z', "droproot",   Opt::REQ, "",                    "drop root privileges, after opening the capture device",                                    "username", nullptr, false},
    {'v', "verbose",    Opt::REQ, "1",                   "specify verbosity level",                                                                   "0|1|2",    nullptr, false},
    {'h', "help",       Opt::NOA, "false",               "print help message and usage for modules passed with -a options, then exit",                nullptr,    nullptr, false}
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
