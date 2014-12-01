//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Parser of filtrated CIFS Procedures.
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
#ifndef CIFS_PARSER_H
#define CIFS_PARSER_H
//------------------------------------------------------------------------------
#include "analysis/analyzers.h"
#include "protocols/cifs/cifs.h"
#include "protocols/cifs2/cifs2.h"
#include "utils/filtered_data.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

/*! \class It is class which can parse CIFS messages and it called by ParserThread
 */
class CIFSParser
{
    using FilteredDataQueue = NST::utils::FilteredDataQueue;//!< Packets queue
    Analyzers& analyzers;//!< Plugins manager

    /*! Parses SMBv1 packet
     * \param header - Message's header
     */
    inline void parse_packet(const protocols::CIFSv1::MessageHeader* header);

    /*! Parses SMBv2 packet
     * \param header - Message's header
     */
    inline void parse_packet(const protocols::CIFSv2::MessageHeader* header);
public:

    CIFSParser(Analyzers& a);
    CIFSParser(CIFSParser& c) : analyzers(c.analyzers) {}

    /*! Function which will be called by ParserThread class
     * \param data - CIFS header
     */
    void parse_data(FilteredDataQueue::Ptr&& data);
};

} // analysis
} // NST
//------------------------------------------------------------------------------
#endif // CIFS_PARSER_H
//------------------------------------------------------------------------------
