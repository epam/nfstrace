//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Entry point of program.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <string>

#include "program_options/CmdLineParser.h"
#include "program_options/ProgramOptions.h"
//------------------------------------------------------------------------------
using namespace NST::program_options;
//------------------------------------------------------------------------------
int main(int argc, char **argv)
{
    ProgramOptions *ptr = ProgramOptions::GetInstance();
    ptr = ProgramOptions::GetInstance();
    ptr->SetOption("123", "HELLO", false);
    ptr->SetOption("123", "WORLD", true);
    std::string opt_val;
    ptr->GetOption("123", opt_val);
    std::cout << opt_val << std::endl;
    NST::program_options::CmdLineParser parser;
    parser.Parse(argc, argv);
    ptr->GetOption("p", opt_val);
    std::cout << opt_val << std::endl;
    std::cout << CmdLineParser::GetHelpMessage() << std::endl;
    return 0;
}
//------------------------------------------------------------------------------

