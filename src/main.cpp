//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Entry point of program.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#include <iostream>
#include <exception>

#include "controller/controller.h"
#include "controller/parameters.h"
//------------------------------------------------------------------------------
using namespace NST::controller;
//------------------------------------------------------------------------------
int main(int argc, char **argv) try
{
    Parameters params(argc, argv); // set and validate CLI options

    if(params.show_help() || params.show_list())
    {
        return 0; // -h or -L was passed
    }

    Controller controller(params);

    return controller.run();
}
catch(const std::exception& e)
{
    std::cerr << argv[0] << ": " << e.what() << std::endl;
    return -1;
}
catch(...)
{
    std::cerr << "Unknown error" << std::endl;
    return -1;
}
//------------------------------------------------------------------------------

