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

// Structure of elements of this array is decribed in cmdline_parser.h
Opt Args::options[Args::num] =
{
    {'i', "interface", Opt::REQ,  NULL,                         "listen interface",                 "INTERFACE"},
    {'p', "port",      Opt::REQ, "2049",                        "port of NFS communications",       "PORT"},
    {'s', "snaplen",   Opt::REQ, "65535",                       "max length of raw captured packet","0..65535"},
    {'m', "mode",      Opt::REQ,  LIVE,                         "set runing mode",                  LIVE"|"DUMP"|"STAT },
    {'I', "ifile",     Opt::REQ, "INTERFACE-PORT-SNAPLEN.pcap", "input file to " STAT" mode",       "PATH"},
    {'O', "ofile",     Opt::REQ, "INTERFACE-PORT-SNAPLEN.pcap", "output file to "DUMP" mode",       "PATH"},
    {'v', "verbose",   Opt::NOA, "false",                       "print out additional information"},
    {'h', "help",      Opt::NOA, "false",                       "print this help message and exit"},
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
