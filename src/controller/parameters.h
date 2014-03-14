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

#include "controller/cmdline_args.h"
#include "controller/cmdline_parser.h"
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
    AParams(AParams&&) = default;

    const std::string path;
    const std::string args;
};

class Parameters : private cmdline::CmdlineParser<cmdline::Args>
{
    static Parameters* global;
public:
    Parameters(int argc, char** argv);
    Parameters(const Parameters&)            = delete;
    Parameters& operator=(const Parameters&) = delete;

    static Parameters* instance() { return global; }

    // access helpers
    const std::string&  program_name() const;
    RunningMode         running_mode() const;
    std::string         interface() const;
    int                 snaplen() const;
    int                 timeout() const;
    int                 buffer_size() const;
    std::string         filtration() const;
    std::string         input_file() const;
    std::string         output_file() const;
    std::string         dumping_cmd() const;
    unsigned int        dumping_size() const;
    unsigned short      rpcmsg_limit() const;
    unsigned short      queue_capacity() const;
    bool                trace() const;
    unsigned int        verbose_level() const;
    const std::vector<AParams>& analysis_modules() const;

protected:
    void set_multiple_value(int index, char *const v) override;

private:

    // cashed values
    unsigned short rpc_message_limit;
    std::string program;  // name of program in command line
    std::vector<AParams> analysiss_params;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //PARAMETERS_H
//------------------------------------------------------------------------------
