//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Dump filtered packets to .pcap file
// Copyright (c) 2014 EPAM Systems
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
#include <cerrno>
#include <exception>    // std::terminate()
#include <vector>

#include <unistd.h>

#include "filtration/dumping.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

Dumping::Dumping(pcap_t*const h, const Params& params)
    : handle  {h}
    , base    {params.output_file}
    , name    {params.output_file}
    , command {params.command}
    , limit   {params.size_limit}
    , part    {0}
    , size    {0}
{
    open_dumping_file(name);
}
Dumping::~Dumping()
{
    close_dumping_file();
}

void Dumping::open_dumping_file(const std::string& file_path)
{
    const char* path = file_path.c_str();
    LOG("Dumping packets to file:%s", path);
    dumper.reset(new pcap::PacketDumper{handle, path});
}

void Dumping::close_dumping_file()
{
    dumper.reset(); // close current dumper
    exec_command();
}

void Dumping::exec_command() const
{
    if(command.empty()) return;

    NST::utils::Log::flush();   // flush buffer

    if(pid_t pid = fork()) // spawn child process
    {
        // parent process
        LOG("Try to execute(%s %s) in %u child process", command.c_str(), name.c_str(), pid);
        NST::utils::Log::flush();   // flush buffer
        return;
    }
    else
    {
        // child process
        std::istringstream ss(command);
        std::vector<std::string> tokens;
        std::vector<char*> args;

        // TODO: this parser doesn't work with dual quotes, like rm "a file.cpp"
        for(std::string arg; ss >> arg;)
        {
           tokens.emplace_back(arg);
           args  .emplace_back(const_cast<char*>(tokens.back().c_str()));
        }
        args.push_back(const_cast<char*>(name.c_str()));
        args.push_back(NULL);  // need termination null pointer

        if(execvp(args[0], &args[0]) == -1)
        {
            LOG("execvp(%s,%s %s) return: %s", args[0], command.c_str(), name.c_str(), strerror(errno));
        }

        LOG("child process %u will be terminated.", getpid());
        std::terminate();
    }
}

std::ostream& operator<<(std::ostream& out, const Dumping::Params& params)
{
    out << "Dump packets to file: " << params.output_file << '\n'
        << "  file rotation size: " << params.size_limit << " bytes\n"
        << "  file rotation command: [" << params.command << ']';
    return out;
}


} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
