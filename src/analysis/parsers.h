//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Composite parser which parses both CIFS&NFS
// TODO: THIS CODE MUST BE TOTALLY REFACTORED!
// Copyright (c) 2015 EPAM Systems
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
#ifndef PARSERS_H
#define PARSERS_H
//------------------------------------------------------------------------------
#include "cifs_parser.h"
#include "nfs_parser.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{
/*!
 * Composite parser which parses both CIFS&NFS
 */
class Parsers final
{
    using FilteredDataQueue = NST::utils::FilteredDataQueue;
    CIFSParser parser_cifs; //!< CIFS parser
    NFSParser  parser_nfs;  //!< NFS parser
public:
    Parsers(Analyzers& a)
        : parser_cifs(a)
        , parser_nfs(a)
    {
    }

    Parsers(Parsers& c)
        : parser_cifs(c.parser_cifs)
        , parser_nfs(c.parser_nfs)
    {
    }

    /*! Function which will be called by ParserThread class
     * \param data - packet
     */
    inline void parse_data(FilteredDataQueue::Ptr& data)
    {
        if(!parser_nfs.parse_data(data))
        {
            if(!parser_cifs.parse_data(data))
            {
                LOG("Unknown packet to analysis");
            }
        }
    }
};

} // analysis
} // NST
//------------------------------------------------------------------------------
#endif // PARSERS_H
//------------------------------------------------------------------------------
