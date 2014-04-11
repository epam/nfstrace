//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class provides validation and access to application parameters
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PARAMETERS_H
#define PARAMETERS_H
//------------------------------------------------------------------------------
#include <string>
#include <vector>

#include "filtration/dumping.h"
#include "filtration/pcap/capture_reader.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

enum class RunningMode
{
    Profiling,
    Dumping,
    Analysis
};

struct AParams
{
    AParams(const std::string& p) : path{p}, args{} {}
    AParams(const std::string& p, const std::string& a) : path{p}, args{a} {}

    const std::string path;
    const std::string args;
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

    // access helpers
    const std::string&  program_name() const;
    RunningMode         running_mode() const;
    std::string         input_file() const;
    unsigned short      queue_capacity() const;
    bool                trace() const;
    int                 verbose_level() const;
    const CaptureParams capture_params() const;
    const DumpingParams dumping_params() const;
    const std::vector<AParams>& analysis_modules() const;

    static unsigned short rpcmsg_limit();
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //PARAMETERS_H
//------------------------------------------------------------------------------
