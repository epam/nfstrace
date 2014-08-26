//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Special exception for libpcap errors.
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
#ifndef PCAP_ERROR_H
#define PCAP_ERROR_H
//------------------------------------------------------------------------------
#include <stdexcept>
#include <string>
//------------------------------------------------------------------------------
#define NST_PUBLIC __attribute__ ((visibility("default")))
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

class NST_PUBLIC PcapError : public std::runtime_error
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
