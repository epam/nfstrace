//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Place for description of module. A template for source files.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <fstream>
#include <iostream>

#include "configparser.h"
#include "ProgramOptions.h"
#include "ProgramOptionsExceptions.h"
//------------------------------------------------------------------------------
using namespace NST::program_options;
//------------------------------------------------------------------------------
ConfigParser::ConfigParser(const std::string &path)
  : _path(path)
{
}

ConfigParser::~ConfigParser()
{
    
}

void ConfigParser::Parse()
{
    std::ifstream file(_path.c_str());
    if (!file) {
        throw std::ios::failure("Can't open configuration file.");
    }
    std::string s;
    ProgramOptions &optsContainer = *ProgramOptions::GetInstance();
    std::size_t lineCounter = 1;
    while (std::getline(file, s)) {
        try 
        {
            std::string::size_type n = s.find('#');
            if (n != std::string::npos) {
                s = s.substr(0, n);
            }
            s = Trim(s);

            if (!s.empty()) {
                std::string option;
                std::string value;
                SplitString(s, option, value, " ");
                // debug output
                //std::cout << option << std::endl;
                optsContainer.SetOption(option, value, false);
            }
        }
        catch (InvalidConfigFileParameter& e) {
            std::cout << "In line " << lineCounter << ": " << std::endl;
            std::cout << "Cannot parse parameter: " << e.what() << std::endl;
            // TODO: Handle exceptions
        }
        catch (std::ios::failure& e) {
            std::cout << "Input stream error: " << e.what() << std::endl;
            std::terminate();
        }
        ++lineCounter;
    }
}

void ConfigParser::SplitString(const std::string& s, std::string& opt, 
    std::string& val, const std::string& separators) 
{
    std::string::size_type n = s.find_first_of(separators);
    if (n == std::string::npos) {
        throw InvalidConfigFileParameter("Missing option value or separator");
    } else {
        opt = s.substr(0, n);
        std::string::size_type valBegin = s.find_first_not_of(" ", n + 1);
        std::string::size_type valEnd;
        if (valBegin == std::string::npos) {
            throw InvalidConfigFileParameter("Invalid option name");
        } else if(s.at(valBegin) == '\"') {
            // Handle quoted values
            valEnd = s.find_first_of("\"", valBegin + 1);
            if (valEnd == std::string::npos) {
            throw InvalidConfigFileParameter("Cannot find closing quote");
            } else {
                val = s.substr(valBegin + 1, valEnd - valBegin - 1);
            }
        } else { // handle one-word values
                 // now store all words up to end of the line
            val = s.substr(valBegin, s.length() - valBegin);
            std::string::size_type n = s.find_last_not_of(" \t\r\n");
            if (n != std::string::npos) {
                val = val.substr(0, n);
            }
        }
    }
}

std::string ConfigParser::Trim(const std::string& s)
{
    std::string::size_type begin, end;
    begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return std::string();
    } else {
        end = s.find_last_not_of("#\t\r\n");
        return s.substr(begin, end - begin + 1);
    }
}
//------------------------------------------------------------------------------
