//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of filtrated NFSv3 Procedures.
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
#ifndef NFS_PARSER_H
#define NFS_PARSER_H
//------------------------------------------------------------------------------
#include "analysis/analyzers.h"
#include "analysis/rpc_sessions.h"
#include "utils/filtered_data.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{
/*! \class It is class which can parse NFS messages and it called by ParserThread
 */
class NFSParser {
    using FilteredDataQueue = NST::utils::FilteredDataQueue;

    Analyzers& analyzers;
    RPCSessions sessions;
public:

    NFSParser(Analyzers& a) : analyzers(a) {}
    NFSParser(NFSParser& c) : analyzers(c.analyzers) {}

    /*! Function which will be called by ParserThread class
     * \param data - RPC packet
     */
    void parse_data(FilteredDataQueue::Ptr&& data);
    void analyze_nfs_operation(FilteredDataQueue::Ptr&& call,
                               FilteredDataQueue::Ptr&& reply,
                               RPCSession* session);

};

}
}

#endif // NFS_PARSER_H
