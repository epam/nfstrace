//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Interface for passing info from file to filtration.
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
#ifndef FILE_READER_H
#define FILE_READER_H
//------------------------------------------------------------------------------
#include <cstdio>

#include "filtration/pcap/base_reader.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{
class FileReader final : public BaseReader
{
public:
    explicit FileReader(const std::string& file);
    ~FileReader() override = default;

    inline FILE*         get_file() { return pcap_file(handle); }
    void                 print_statistic(std::ostream& /*out*/) const override {}
    inline int           major_version() { return pcap_major_version(handle); }
    inline int           minor_version() { return pcap_minor_version(handle); }
    inline bool          is_swapped() { return pcap_is_swapped(handle); }
    friend std::ostream& operator<<(std::ostream& out, FileReader& f);
};

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif // FILE_READER_H
//------------------------------------------------------------------------------
