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
#include "rpc_sessions.h"
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
    using FilteredDataQueue = NST::utils::FilteredDataQueue; //!< Packets queue

    Analyzers&        analyzers; //!< Plugins manager
    Sessions<Session> sessions;  //!< Sessions list

    /*! Parses SMBv1 packet
     * \param header - Message's header
     * \param ptr - raw packet
     */
    inline void parse_packet(const protocols::CIFSv1::MessageHeader* header, FilteredDataQueue::Ptr&& ptr);

    /*! analyses CIFS v1 operation: request and response
     * \param session - session
     * \param request - Call's header
     * \param response - Reply's header
     * \param requestData - Call's data
     * \param responseData - Reply's data
     */
    inline void analyse_operation(Session*                                session,
                                  const protocols::CIFSv1::MessageHeader* request,
                                  const protocols::CIFSv1::MessageHeader* response,
                                  FilteredDataQueue::Ptr&&                requestData,
                                  FilteredDataQueue::Ptr&&                responseData);

    /*! Parses SMB v2 packet
     * \param header - Message's header
     * \param ptr - raw packet
     */
    inline void parse_packet(const protocols::CIFSv2::MessageHeader* header, NST::utils::FilteredDataQueue::Ptr&& ptr);

    /*! analyses CIFS v2 operation: request and response
     * \param session - session
     * \param request - Call's header
     * \param response - Reply's header
     * \param requestData - Call's data
     * \param responseData - Reply's data
     */
    inline void analyse_operation(Session*                                session,
                                  const protocols::CIFSv2::MessageHeader* request,
                                  const protocols::CIFSv2::MessageHeader* response,
                                  FilteredDataQueue::Ptr&&                requestData,
                                  FilteredDataQueue::Ptr&&                responseData);

public:
    CIFSParser(Analyzers& a);
    CIFSParser(CIFSParser& c)
        : analyzers(c.analyzers)
    {
    }

    /*! Function which will be called by ParserThread class
     * \param data - raw packet
     * \return True, if it is CIFS packet and False in other case
     */
    bool parse_data(FilteredDataQueue::Ptr& data);
};

} // analysis
} // NST
//------------------------------------------------------------------------------
#endif //CIFS_PARSER_H
//------------------------------------------------------------------------------
