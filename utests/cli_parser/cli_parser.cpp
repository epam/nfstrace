//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Command-line arguments parsing tests.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <cassert>
#include <iostream>

#include "../../src/auxiliary/exception.h"
#include "../../src/controller/cmdline_parser.h"
//------------------------------------------------------------------------------
using namespace NST::controller::cmdline;
//------------------------------------------------------------------------------

// We define a structure of command-line parameters to test parser on them
struct Args
{
    friend class CmdlineParser<Args>;

    enum Names {
        INTERFACE = 0,
        PORT      = 1,
        HELP      = 2,
        VERBOSE   = 3,
        num       = 4,
    };

private:
    static Opt options[num];

    explicit Args();  // undefined
};

// Struct Arg defined in cmdline_parser.h
Opt Args::options[Args::num] =
{
    {'i', "interface", Opt::REQUIRED, NULL,    "This is a very long comment "
        "that let us see how option description is splitted on rows", "ITRF", NULL},
    {'p', "port",      Opt::REQUIRED, "2049",  "port of nfs connection", NULL},
    {0,   "help",      Opt::NO,       "false", "get help message",       NULL},
    {'v', "verbose",   Opt::NO,       "false", "interactive mode",       NULL},
};

/** This utility function is defined since getopt_long uses external variables
 * declared in getopt.h. We have to reset this variables to default values
 * before repeated using of getopt_long()
 */
void reset_getopt_options()
{
    optarg = 0;
    optopt = 0;
    optind = 0;
    opterr = 1;

}

/**
 * Test Arg conversion operators
 */
void check_arguments_conversions()
{
    // generate input arguments for tests
    // convert every member to char* to prevent warnings
    char* test_argv[] =
    {
        (char*)"cli_parser",
        (char*)"-i",
        (char*)"127.0.0.1",
        (char*)"--port=8080",
        (char*)"--help",
    };
    const int test_argc = sizeof(test_argv) / sizeof(test_argv[0]);

    try
    {
        CmdlineParser<Args> p;
        p.parse(test_argc, test_argv);

        // check arguments values
        assert(p[Args::INTERFACE] == "127.0.0.1");
        assert(p[Args::PORT].to_int() == 8080);
        assert(p[Args::HELP].to_bool() == true);
        assert(p[Args::VERBOSE].to_bool() == false);
    }
    catch(CLIError e)
    {
        std::cerr << e.what() << std::endl;
        exit(2);
    }
}

/**
 * Test checking for undefined options
 */
void check_unrecognized_option()
{
    // generate input arguments for tests
    // convert every member to char* to prevent warnings
    char* test_argv[] =
    {
        (char*)"cli_parser",
        (char*)"--wrong",      // undefined argument
        (char*)"-i",
        (char*)"127.0.0.1",
        (char*)"--port=8080",
        (char*)"--help"
    };
    // generate input data for tests
    const int test_argc = sizeof(test_argv) / sizeof(test_argv[0]);

    try
    {
        CmdlineParser<Args> p;
        p.parse(test_argc, test_argv);
    }
    catch(const CLIError& e)
    {
        std::string expected_msg = "Unrecognized option: '--wrong'";
        assert(expected_msg == e.what());
        return;
    }
    assert(false);
}


int main(int argc, char **argv)
{
    check_arguments_conversions();
    reset_getopt_options();
    check_unrecognized_option();

    return 0;
}


