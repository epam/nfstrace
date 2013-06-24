//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Special exception for libpcap errors.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PCAP_ERROR_H
#define PCAP_ERROR_H
//------------------------------------------------------------------------------
#include <string>

#include <pcap.h>

#include "../../auxiliary/exception.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Exception;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

class PcapError : public Exception
{
public:
    explicit PcapError(const char* func, const char errbuf[PCAP_ERRBUF_SIZE])
        : Exception(std::string(func)+"():"+std::string(errbuf)) { }

    virtual const PcapError* dynamic_clone() const { return new PcapError(*this); }
    virtual void             dynamic_throw() const { throw *this; }
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//PCAP_ERROR_H
//------------------------------------------------------------------------------
