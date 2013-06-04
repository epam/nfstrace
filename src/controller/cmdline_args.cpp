//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Structure describing command-line arguments.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "cmdline_args.h"

namespace NST
{
namespace controller
{
namespace cmdline
{

// Struct Arg defined in cmdline_parser.h
Opt Args::options[Args::num] =
{
    {'i', "interface", Opt::REQUIRED, NULL,    "IP of host"},
    {'p', "port",      Opt::REQUIRED, "2049",  "port of nfs connection"},
    {'h', "help",      Opt::NO,       "false", "get help message"},
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
