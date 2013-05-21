//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Container of options for application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include "ProgramOptions.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace program_options
{

using NST::auxiliary::Mutex;

std::ostream& operator<<(std::ostream& stream, ProgramOptions &opts)
{
    stream << "Options:" << std::endl;
    Mutex::Lock lock(opts.mutex);
    for (std::map<std::string, std::string>::const_iterator i = opts._options.begin();
            i != opts._options.end(); ++i) {
        stream << i->first << ": " << i->second << std::endl;
    }

    return stream;
}

ProgramOptions* ProgramOptions::_instance = NULL;

ProgramOptions* ProgramOptions::GetInstance()
{
    /* Options object will be automatically initialized on the first call
     * to GetInstance() method and will exist during the whole runtime,
     * actually this is the desired behavior.
     */
    static ProgramOptions opts;
    return &opts;
}

ProgramOptions::ProgramOptions()
{
}

ProgramOptions::~ProgramOptions()
{
}

optstatus_t ProgramOptions::GetOption(const std::string &optName,
                                      std::string &optVal)
{
    optstatus_t status = e_Ok;

    Mutex::Lock lock(mutex);
    if(this->exists(optName))
    {
        optVal = this->_options[optName];
    }
    else
    {
        status = e_NoOption;
    }
    return status;
}

optstatus_t ProgramOptions::SetOption(const std::string &optName,
                                      const std::string &optVal,
                                      bool reset)
{
    optstatus_t status = e_Ok;

    Mutex::Lock lock(mutex);
    if(!this->exists(optName) || reset)
    {
        this->_options[optName] = optVal;
    }
    else
    {
        status = e_OptionExists;
    }
    return status;
}

bool ProgramOptions::exists(const std::string &optName) const
{
    if(this->_options.count(optName))
        return true;
    return false;
}

} // namespace program_options
} // namespace NST
//------------------------------------------------------------------------------
