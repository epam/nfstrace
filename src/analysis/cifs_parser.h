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
    using FilteredDataQueue = NST::utils::FilteredDataQueue;//!< Packets queue

    /*! \class Represents CIFS session
     */
    class CIFSSession : public utils::ApplicationSession
    {
    public:
        CIFSSession(const utils::NetworkSession& s, utils::Session::Direction call_direction);
        ~CIFSSession() = default;
        CIFSSession(const CIFSSession&)            = delete;
        CIFSSession& operator=(const CIFSSession&) = delete;

        inline void save_call_data(const uint32_t CID, FilteredDataQueue::Ptr&& data);
        inline FilteredDataQueue::Ptr get_call_data(const uint32_t xid);

        inline const Session* get_session() const;
    private:
        // TODO: add custom allocator based on BlockAllocator
        // to decrease cost of expensive insert/erase operations
        std::unordered_map<uint32_t, FilteredDataQueue::Ptr> operations;
    };

    Analyzers& analyzers;//!< Plugins manager
    Sessions<CIFSSession> sessions;//!< Sessions list

    /*! Parses SMBv1 packet
     * \param header - Message's header
     * \param ptr - raw packet
     */
    inline void parse_packet(const protocols::CIFSv1::MessageHeader* header, FilteredDataQueue::Ptr&& ptr);

    /*! analyses CIFS v1 operation: request and response
     * \param request - Call's header
     * \param response - Reply's header
     * \param requestData - Call's data
     * \param responseData - Reply's data
     */
    inline void analyse_operation(const protocols::CIFSv1::MessageHeader* request,
                                  const protocols::CIFSv1::MessageHeader* response,
                                  FilteredDataQueue::Ptr&& requestData,
                                  FilteredDataQueue::Ptr&& responseData);

    /*! Parses SMB v2 packet
     * \param header - Message's header
     * \param ptr - raw packet
     */
    inline void parse_packet(const protocols::CIFSv2::MessageHeader* header, NST::utils::FilteredDataQueue::Ptr&& ptr);

    /*! analyses CIFS v2 operation: request and response
     * \param request - Call's header
     * \param response - Reply's header
     * \param requestData - Call's data
     * \param responseData - Reply's data
     */
    inline void analyse_operation(const protocols::CIFSv2::MessageHeader* request,
                                  const protocols::CIFSv2::MessageHeader* response,
                                  FilteredDataQueue::Ptr&& requestData,
                                  FilteredDataQueue::Ptr&& responseData);
public:

    CIFSParser(Analyzers& a);
    CIFSParser(CIFSParser& c) : analyzers(c.analyzers) {}

    /*! Function which will be called by ParserThread class
     * \param data - raw packet
     */
    void parse_data(FilteredDataQueue::Ptr&& data);
};

} // analysis
} // NST
//------------------------------------------------------------------------------
#endif // CIFS_PARSER_H
//------------------------------------------------------------------------------
