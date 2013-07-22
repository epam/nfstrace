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
    const RunningMode       running_mode() const;
    const bool              is_verbose() const;
    const std::string       interface() const;
    const unsigned short    snaplen() const;
    const std::string       filter() const;
    const std::string       input_file() const;
    const std::string       output_file() const;
    const unsigned int      buffer_size() const;
    const unsigned short    rpcmsg_limit() const;
    const unsigned short    queue_capacity() const;
    const std::vector<std::string> analyzers() const;

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
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //PARAMETERS_H
//------------------------------------------------------------------------------
