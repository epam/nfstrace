//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Interface for passing data from file to filtration.
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
#include "filtration/pcap/file_reader.h"
#include "filtration/pcap/pcap_error.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

FileReader::FileReader(const std::string& file) : BaseReader{file}
{
    char errbuf[PCAP_ERRBUF_SIZE];

    // open pcap device for reading from file in file system
    handle = pcap_open_offline(file.c_str(), errbuf);
    if(!handle)
    {
        throw PcapError("pcap_open_offline", errbuf);
    }
}

FileReader::FileReader(FILE* rb_stream) : BaseReader()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    // open pcap device for reading from existing FILE*
    handle = pcap_fopen_offline(rb_stream, errbuf);
    if(!handle)
    {
        throw PcapError("pcap_fopen_offline", errbuf);
    }
}

FileReader::~FileReader()
{
}

std::ostream& operator<<(std::ostream& out, FileReader& f)
{
    out << "Read packets from: " << f.source << '\n';
    const int dlt = f.datalink();
    out << "  datalink: " << f.datalink_name(dlt) << " (" << f.datalink_description(dlt) << ")\n";
    out << "  version: " << f.major_version() << '.' << f.minor_version();
    if(f.is_swapped()) out << "\n  Note: file has data in swapped byte-order";
    return out;
}   


} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
