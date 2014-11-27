//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class provides validation and access to application parameters
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
#ifndef PARAMETERS_H
#define PARAMETERS_H
//------------------------------------------------------------------------------
#include <string>
#include <vector>

#include "filtration/dumping.h"
#include "filtration/pcap/capture_reader.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

enum class RunningMode
{
    Profiling,
    Dumping,
    Analysis,
    Draining
};

struct AParams
{
    AParams(const std::string& p) : path{p}, args{} {}
    AParams(const std::string& p, const std::string& a) : path{p}, args{a} {}

    const std::string path;
    const std::string args;
};

/*! Protocol to analysis
 */
enum class NetProtocol
{
    NFS    = 0x01, //!< NFS protocol
    CIFS   = 0x02  //!< CIFS protocol
};

class Parameters
{
    using CaptureParams = filtration::pcap::CaptureReader::Params;
    using DumpingParams = filtration::Dumping::Params;

public:
    // initialize global instance
    Parameters(int argc, char** argv);
    ~Parameters();

    Parameters(const Parameters&)            = delete;
    Parameters& operator=(const Parameters&) = delete;

    bool show_help() const;
    bool show_list() const;

    // access helpers
    const std::string&  program_name() const;
    RunningMode         running_mode() const;
    std::string         input_file() const;
    const std::string   dropuser() const;
    unsigned short      queue_capacity() const;
    bool                trace() const;
    int                 verbose_level() const;
    const CaptureParams capture_params() const;
    const DumpingParams dumping_params() const;
    const std::vector<AParams>& analysis_modules() const;

    /*! Network protocol to analysis (CIFS or NFS, for example)
     * \return Protocol name
     */
    NetProtocol protocol() const;

    static unsigned short rpcmsg_limit();
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //PARAMETERS_H
//------------------------------------------------------------------------------
