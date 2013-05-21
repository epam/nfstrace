//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Parser command line arguments. Based on getopt_long()
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <cstring>

#include "CmdLineParser.h"
#include "ProgramOptionsExceptions.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace program_options
{

static struct option defaultLongOpts[] =
{
    { "port", required_argument, 0, 0 },
    { "interface", required_argument, 0, 0 },
    { "help", no_argument, 0, 0},
    { NULL, 0, NULL, 0 }
};

static char defaultShortRegex[] = { ":hp:i:" };

const char* CmdLineParser::GetHelpMessage()
{
    return "Help!";
}

CmdLineParser::CmdLineParser(const char *shortOpts,
                             const struct option * const longOpts)
{
    this->_optsStorage = ProgramOptions::GetInstance();

    if(!shortOpts)
    {
        this->_shortRegex = defaultShortRegex;
    }
    else
    {
        /* the caller is responsible for passing NULL-terminated string */
        size_t len = strlen(shortOpts) + 1;
        this->_shortRegex = new char[len];
        strcpy(this->_shortRegex, shortOpts);
    }

    if(!longOpts)
    {
        this->_longOpts = defaultLongOpts;
        this->_longOptLen = CmdLineParser::GetLongOptLen(defaultLongOpts);
    }
    else
    {
        this->_longOptLen = CmdLineParser::GetLongOptLen(longOpts);
        this->_longOpts = new option[this->_longOptLen + 1];
        this->_longOpts[this->_longOptLen].name = NULL;
        this->_longOpts[this->_longOptLen].has_arg = 0;
        this->_longOpts[this->_longOptLen].flag = NULL;
        this->_longOpts[this->_longOptLen].val = 0;
        for(size_t i = 0; i < this->_longOptLen; ++i)
        {
            this->_longOpts[i].name = new char[strlen(longOpts[i].name) + 1];
            strcpy(const_cast<char*>(this->_longOpts[i].name),
                   longOpts[i].name);
            this->_longOpts[i].has_arg = longOpts[i].has_arg;
            this->_longOpts[i].flag = longOpts[i].flag;
            this->_longOpts[i].val = longOpts[i].val;
        }
    }
}

size_t CmdLineParser::GetLongOptLen(const struct option * const longOpts)
{
    if(!longOpts)
        return 0;

    size_t len = 0;
    struct option *optptr = const_cast<option*>(longOpts);
    /* the caller is responsible for passing pointer to array which
     * ends with the element containing zero values (see man 3 getopt)
     */
    while(optptr->name)
    {
        ++optptr;
        ++len;
    }
    return len;
}

CmdLineParser::~CmdLineParser()
{
    if(this->_shortRegex != defaultShortRegex)
    {
        delete [] this->_shortRegex;
    }

    if(this->_longOpts != defaultLongOpts)
    {
        for(size_t i = 0; i < this->_longOptLen; ++i)
        {
            delete [] this->_longOpts[i].name;
        }
        delete [] this->_longOpts;
    }
}

void CmdLineParser::Parse(int argc, char **argv)
{
    /* Assuming that argc and argv are the same as those passed to program */

    int opt = 0;
    int option_index = 0;

    while(1)
    {
        opt = getopt_long(argc, argv, this->_shortRegex,
                          this->_longOpts, &option_index);
        if(opt == -1)
            break;

        switch(opt)
        {
        case 0:
            /* long opt found */
            if(optarg)
            {
                this->_optsStorage->SetOption(
                    this->_longOpts[option_index].name,
                    optarg,
                    false);
            }
            else
            {
                this->_optsStorage->SetOption(
                    this->_longOpts[option_index].name,
                    "",
                    false);
            }
            break;

        case '?':
            throw UnknownOption("Unknow option found");
            break;

        case ':':
            throw ArgumentNotFound(
                std::string("Argument not found for opt ") +
                this->_longOpts[option_index].name);
            break;

        default:
            /* short opt found */
            if(optarg)
            {
                this->_optsStorage->SetOption(
                    std::string(1, opt),
                    optarg,
                    false);
            }
            else
            {
                this->_optsStorage->SetOption(
                    std::string(1, opt),
                    "",
                    false);
            }
        }
    }
}

} // namespace program_options
} // namespace NST
//------------------------------------------------------------------------------
