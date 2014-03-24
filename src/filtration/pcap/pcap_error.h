//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Special exception for libpcap errors.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PCAP_ERROR_H
#define PCAP_ERROR_H
//------------------------------------------------------------------------------
#include <stdexcept>
#include <string>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

class PcapError : public std::runtime_error
{
public:
    explicit PcapError(const char* func, const char* errbuf)
        : std::runtime_error{std::string{func}+"():"+std::string{errbuf}} { }
};

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//PCAP_ERROR_H
//------------------------------------------------------------------------------
