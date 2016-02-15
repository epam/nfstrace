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
        ArgMode,
        ArgInterface,
        ArgFilter,
        ArgSnaplen,
        ArgTimeout,
        ArgBSize,
        ArgPromisc,
        ArgDirection,
        ArgAnalyzers,
        ArgIFile,
        ArgOFile,
        ArgLogPath,
        ArgCommand,
        ArgDSize,
        ArgEnum,
        ArgMSize,
        ArgQSize,
        ArgTrace,
        ArgDropRoot,
        ArgVerbose,
        ArgHelp,
        num
    };

    static const char* const profiling_mode;
    static const char* const dumping_mode;
    static const char* const analysis_mode;
    static const char* const draining_mode;

private:
    static Opt options[num];

    Args() = delete;
};

} // namespace cmdline
} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif // CMDLINE_PARSER_H
//------------------------------------------------------------------------------
