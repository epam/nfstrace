//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Interface for passing info from file to filtration.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FILE_READER_H
#define FILE_READER_H
//------------------------------------------------------------------------------
#include <cstdio>
#include <string>

#include "base_reader.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

class FileReader : public BaseReader
{
public:
    FileReader(const std::string& file);
    ~FileReader();

    inline FILE* get_file() { return pcap_file(handle); }
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILE_READER_H
//------------------------------------------------------------------------------
