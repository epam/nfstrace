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
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

enum RunningMode
{
    Profiling,
    Filtration,
    Analysis
};

struct AParams
{
    AParams(const std::string& p) : path(p) {}
    AParams(const std::string& p, const std::string& a) : path(p), arguments(a) {}
    ~AParams() {}
    std::string path;
    std::string arguments;
};

class Parameters
{
public:
    inline static Parameters& instance()
    {
        static Parameters params;
        return params;
    }

    bool cmdline_args(int argc, char** argv);

    // access helpers
    const std::string&  program_name() const;
    RunningMode         running_mode() const;
    bool                is_verbose() const;
    const std::string   interface() const;
    unsigned short      snaplen() const;
    const std::string   filter() const;
    const std::string   input_file() const;
    const std::string   output_file() const;
    const std::string   dumping_cmd() const;
    unsigned int        dumping_size() const;
    unsigned int        buffer_size() const;
    unsigned short      rpcmsg_limit() const;
    unsigned short      queue_capacity() const;
    const std::vector<AParams> analyzers() const;
    unsigned int        block_size() const;
    unsigned int        bucket_size() const;

private:
    Parameters()
    {
    }
    ~Parameters()
    {
    }

    Parameters(const Parameters&);            // undefined
    Parameters& operator=(const Parameters&); // undefined

    // cashed values
    unsigned short rpc_message_limit;
    bool verbose;
    std::string program;  // name of program in command line
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //PARAMETERS_H
//------------------------------------------------------------------------------
