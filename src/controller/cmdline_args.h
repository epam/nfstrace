//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Structure describing command-line arguments.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CMDLINE_ARGS_H
#define CMDLINE_ARGS_H
//------------------------------------------------------------------------------
#include "controller/cmdline_parser.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{
namespace cmdline
{

struct Args
{
    friend class CmdlineParser<Args>;

    enum Names
    {
        INTERFACE,
        FILTER,
        SNAPLEN,
        TIMEOUT,
        BSIZE,
        MODE,
        ANALYZERS,
        IFILE,
        OFILE,
        COMMAND,
        DSIZE,
        MSIZE,
        QSIZE,
        TRACE,
        VERBOSE,
        HELP,
        num
    };

    static const char* const profiling_mode;
    static const char* const dumping_mode;
    static const char* const analysis_mode;

private:
    static Opt options[num];

    Args() = delete;
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CMDLINE_PARSER_H
//------------------------------------------------------------------------------
