#ifndef _PROGRAMOPTIONSEXCEPTIONS_H_
#define _PROGRAMOPTIONSEXCEPTIONS_H_

#include <string>
#include "../auxiliary/exception.h"

namespace NST
{
namespace program_options
{

class ProgramOptionsException : public NST::auxiliary::Exception
{
public:
    explicit ProgramOptionsException(const std::string& what_arg)
        : NST::auxiliary::Exception(what_arg) { }

};


class InvalidConfigFileParameter : public ProgramOptionsException
{
public:
    explicit InvalidConfigFileParameter(const std::string& what_arg)
        : ProgramOptionsException(what_arg) { }
};


class UnknownOption : public ProgramOptionsException
{
public:
    explicit UnknownOption(const std::string& what_arg)
        : ProgramOptionsException(what_arg) { }
};


class ArgumentNotFound : public ProgramOptionsException
{
public:
    explicit ArgumentNotFound(const std::string& what_arg)
        : ProgramOptionsException(what_arg) { }
};

} /* namespace program_options */
} /* namespace NST */

#endif

