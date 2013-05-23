//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control of the aplication
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CONTROLLER_H
#define CONTROLLER_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class Controller
{
public:
    Controller();
    ~Controller();

    void parse_cmdline_args(int argc, char* argv[]);

};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //CONTROLLER_H
//------------------------------------------------------------------------------
