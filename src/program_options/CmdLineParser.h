//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: A template for headers.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CMD_LINE_PARSER_H
#define CMD_LINE_PARSER_H
//------------------------------------------------------------------------------
#include <getopt.h>

#include "ProgramOptions.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
/*
 * TODO: Here should be a very large comment that describes
 * program options and behavior on unexpected optargs
 */

namespace NST
{
namespace program_options
{

class CmdLineParser
{
public:
    static const char* GetHelpMessage();

    explicit CmdLineParser(const char *shortOpts = NULL,
                           const struct option * const longOpts = NULL);
    ~CmdLineParser();

    void Parse(int argc, char **argv);
private:
    static size_t GetLongOptLen(const struct option * const longOpts);

    ProgramOptions *_optsStorage;

    char *_shortRegex;
    struct option *_longOpts;
    size_t _longOptLen;

    /* making class noncopyable */
    CmdLineParser(const CmdLineParser &parser);
    const CmdLineParser& operator=(const CmdLineParser &parser);
};

} // namespace program_options
} // namespace NST
//------------------------------------------------------------------------------
#endif //CMD_LINE_PARSER_H
//------------------------------------------------------------------------------
