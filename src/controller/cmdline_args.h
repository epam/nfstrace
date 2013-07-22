//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Structure describing command-line arguments.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CMDLINE_ARGS_H
#define CMDLINE_ARGS_H
//------------------------------------------------------------------------------
#include "cmdline_parser.h"
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

    enum Names {
        INTERFACE,
        PORT,
        SNAPLEN,
        MODE,
        ANALYZERS,
        IFILE,
        OFILE,
        BSIZE,
        MSIZE,
        QSIZE,
        VERBOSE,
        HELP,
        num,
    };

    static const char* const profiling_mode;
    static const char* const filtration_mode;
    static const char* const analysis_mode;

    static const char* const ob_analyzer;
    static const char* const ofws_analyzer;
    static const char* const ofdws_analyzer;

private:
    static Opt options[num];

    explicit Args();  // undefined
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CMDLINE_PARSER_H
//------------------------------------------------------------------------------
