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
        DUMP,
        OFILE,
        HELP,
        num,
    };

private:
    static Opt options[num];

    explicit Args();  // undefined
};

typedef CmdlineParser<Args> Params;

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CMDLINE_PARSER_H
//------------------------------------------------------------------------------
