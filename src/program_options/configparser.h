//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Parser of configuration.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CONFIGPARSER_H
#define CONFIGPARSER_H
//------------------------------------------------------------------------------
#include <string>
//------------------------------------------------------------------------------
namespace NST
{
namespace program_options
{

class ConfigParser
{
public:
    explicit ConfigParser(const std::string &path);
    ~ConfigParser();

    void Parse();

private:
    std::string Trim(const std::string &s);
    void SplitString(const std::string& s, std::string& opt, 
        std::string& val,  const std::string& separators);

    std::string _path;

    /* making instances noncopyable */ 
    ConfigParser(const ConfigParser &parser);
    const ConfigParser& operator=(const ConfigParser &parser);

};

} // program_options
} // namespace NST
//------------------------------------------------------------------------------
#endif //CONFIGPARSER_H
//------------------------------------------------------------------------------
