//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Structure describing command-line arguments.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "cmdline_args.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{
namespace cmdline
{

// Structure of elements of this array is decribed in cmdline_parser.h
Opt Args::options[Args::num] =
{
    {'i', "interface", Opt::REQUIRED,  NULL,   "listen interface", "INTERFACE"},
    {'p', "port",      Opt::REQUIRED, "2049",  "port of NFS communications", "PORT"},
    {'s', "snaplen",   Opt::REQUIRED, "65535", "max length of raw captured packet", "0..65535"},
    {'m', "mode",      Opt::REQUIRED, "dump",  "set runing mode", "dump|mon|stat"},
    {'w', "wfile",     Opt::REQUIRED, "INTERFACE-PORT-SNAPLEN.pcap",  "path to output file", "PATH"},
    {'h', "help",      Opt::NO,       "false", "print this help message and exit"},
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
