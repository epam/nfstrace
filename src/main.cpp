//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Entry point of program.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <string>

#include "controller/cmdline_parser.h"
#include "controller/controller.h"
//------------------------------------------------------------------------------
using namespace NST::controller;
using namespace NST::controller::cmdline;
//------------------------------------------------------------------------------

struct Args
{
    friend class CmdlineParser<Args>;

    enum Names {
        INTERFACE = 0,
        PORT      = 1,
        HELP      = 2,
        num       = 3,
    };

private:
    static Opt options[num];

    explicit Args();  // undefined
};

// Struct Arg defined in cmdline_parser.h
Opt Args::options[Args::num] =
{
    {'i', "interface", Opt::REQUIRED, NULL,    "This is a very long comment "
        "that let us see how option description is splitted on rows"},
    {'p', "port",      Opt::REQUIRED, "2049",  "port of nfs connection"},
    {'h', "help",      Opt::NO,       "false", "get help message"},
};


int main(int argc, char **argv)
{
    Controller controller;

    try
    {
        CmdlineParser<Args> cli_parser;
        cli_parser.parse(argc, argv);
    }
    catch(const CLIError& e)
    {
        std::cerr << argv[0] << ": " << e.what() << std::endl;
        exit(2);
    }


    return 0;
}
//------------------------------------------------------------------------------

