//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: A template for headers.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PROGRAM_OPTIONS_H
#define PROGRAM_OPTIONS_H
//------------------------------------------------------------------------------
#include <map>
#include <string>

#include <pthread.h>

#include "../auxiliary/mutex.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace program_options
{

enum e_ProgramOptionsStatus_t
{
    e_Ok,
    e_NoOption,
    e_OptionExists
};

typedef e_ProgramOptionsStatus_t optstatus_t;

class ProgramOptions
{
    friend std::ostream& operator<<(std::ostream& stream, ProgramOptions &opts);
    
public:
    static ProgramOptions* GetInstance();
    static void ReleaseInstance(ProgramOptions *instance);

    optstatus_t GetOption(const std::string &optName,
                          std::string &optVal);
    optstatus_t SetOption(const std::string &optName,
                          const std::string &optVal,
                          bool reset);

    ~ProgramOptions();

private:
    static ProgramOptions *_instance;

    ProgramOptions();
    ProgramOptions(const ProgramOptions &programOptions);
    const ProgramOptions& operator=(const ProgramOptions &programOptions);

    std::map<std::string, std::string> _options;
    bool exists(const std::string &optName) const;

    NST::auxiliary::Mutex mutex;
};

} // namespace program_options
} // namespace NST
//------------------------------------------------------------------------------
#endif //PROGRAM_OPTIONS_H
//------------------------------------------------------------------------------
