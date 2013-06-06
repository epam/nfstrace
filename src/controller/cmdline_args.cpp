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

Opt Args::options[Args::num] =
{
    {'i', "interface", Opt::REQUIRED,  NULL,   "listen interface", "INTERFACE"},
    {'p', "port",      Opt::REQUIRED, "2049",  "port of NFS communications", "PORT"},
    {'s', "snaplen",   Opt::REQUIRED, "65535", "max length of raw captured packet", "0..65535"},
    {'d', "dump",      Opt::NO,       "true",  "online dump mode"},
    {'w', "ofile",     Opt::REQUIRED, "INTERFACE-PORT-SNAPLEN.pcap",  "path to output file", "PATH"},
    {'h', "help",      Opt::NO,       "false", "print this help message and exit"},
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
