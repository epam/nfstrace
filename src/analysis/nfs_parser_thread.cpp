//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of filtrated NFSv3 Procedures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "analysis/nfs_parser_thread.h"
#include "protocols/nfs3/nfs_procedure.h"
#include "protocols/nfs3/nfs_structs.h"
#include "protocols/rpc/rpc_header.h"
#include "utils/logger.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::NFS3;
using namespace NST::protocols::xdr;
using namespace NST::protocols::rpc;
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

NFSParserThread::NFSParserThread(FilteredDataQueue& q, Analyzers& a, RunningStatus& s)
: status   (s)
, analysiss(a)
, queue    (q)
, runing   {}
{
}
NFSParserThread::~NFSParserThread()
{
    if (parsing.joinable()) stop();
}

void NFSParserThread::start()
{
    if(runing.test_and_set()) return;
    parsing = std::thread(&NFSParserThread::thread, this);
}

void NFSParserThread::stop()
{
    runing.clear();
    parsing.join();
}

inline void NFSParserThread::thread()
{
    try
    {
        while(runing.test_and_set())
        {
            // process all available items from queue
            process_queue();

            // then sleep this thread
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        process_queue(); // flush data from queue
    }
    catch(...)
    {
        status.push_current_exception();
    }
}

inline void NFSParserThread::process_queue()
{
    while(true)
    {
        // take all items from the queue
        FilteredDataQueue::List list{queue};
        if(list)    // list isn't empty
        {
            do
            {
                parse_data(list.get_current());
            }
            while(list);
        }
        else
        {
            break; // list is empty, break infinity loop
        }
    }
}

void NFSParserThread::parse_data(FilteredDataQueue::Ptr&& ptr)
{
    // TODO: refactor and generalize this code
    if(ptr->dlen < sizeof(MessageHeader)) return;
    auto msg = reinterpret_cast<const MessageHeader*>(ptr->data);
    switch(msg->type())
    {
    case SUNRPC_CALL:
        {
            if(ptr->dlen < sizeof(CallHeader)) return;

            auto call = static_cast<const CallHeader*>(msg);
            if(RPCValidator::check(call) && Validator::check(call))
            {
                RPCSession* session = sessions.get_session(ptr->session, ptr->direction, RPCSessions::MsgType::SUNRPC_CALL);
                if(session)
                {
                    session->save_nfs_call_data(call->xid(), std::move(ptr));
                }
            }
        }
        break;
    case SUNRPC_REPLY:
        {
            if(ptr->dlen < sizeof(ReplyHeader)) return;

            RPCSession* session = sessions.get_session(ptr->session, ptr->direction, RPCSessions::MsgType::SUNRPC_REPLY);

            if(session == NULL) return;

            auto reply = static_cast<const ReplyHeader*>(msg);
            FilteredDataQueue::Ptr&& call_data = session->get_nfs_call_data(reply->xid());
            if(call_data)
            {
                if(reply->stat() == SUNRPC_MSG_ACCEPTED)
                {
                    // TODO: check msg-length before cast
                    auto areply = static_cast<const AcceptedReplyHeader*>(msg);
                    if(areply->astat() == SUNRPC_SUCCESS)
                    {
                        create_nfs_operation(std::move(call_data), std::move(ptr), session);
                    }
                }
            }
        }
    }
}

void NFSParserThread::create_nfs_operation( FilteredDataQueue::Ptr&& call,
                                            FilteredDataQueue::Ptr&& reply,
                                            RPCSession* session)
{
    auto header = reinterpret_cast<const CallHeader*>(call->data);
    const uint32_t procedure = header->proc();
    try
    {
        RPCReader c{std::move(call) };
        RPCReader r{std::move(reply)};
        const Session* s = session->get_session();

        switch(procedure)
        {
        case Proc::NFS_NULL:    return analysiss(&IAnalyzer::null,       NFSPROC3_NULL       {c, r, s});
        case Proc::GETATTR:     return analysiss(&IAnalyzer::getattr3,   NFSPROC3_GETATTR    {c, r, s});
        case Proc::SETATTR:     return analysiss(&IAnalyzer::setattr3,   NFSPROC3_SETATTR    {c, r, s});
        case Proc::LOOKUP:      return analysiss(&IAnalyzer::lookup3,    NFSPROC3_LOOKUP     {c, r, s});
        case Proc::ACCESS:      return analysiss(&IAnalyzer::access3,    NFSPROC3_ACCESS     {c, r, s});
        case Proc::READLINK:    return analysiss(&IAnalyzer::readlink3,  NFSPROC3_READLINK   {c, r, s});
        case Proc::READ:        return analysiss(&IAnalyzer::read3,      NFSPROC3_READ       {c, r, s});
        case Proc::WRITE:       return analysiss(&IAnalyzer::write3,     NFSPROC3_WRITE      {c, r, s});
        case Proc::CREATE:      return analysiss(&IAnalyzer::create3,    NFSPROC3_CREATE     {c, r, s});
        case Proc::MKDIR:       return analysiss(&IAnalyzer::mkdir3,     NFSPROC3_MKDIR      {c, r, s});
        case Proc::SYMLINK:     return analysiss(&IAnalyzer::symlink3,   NFSPROC3_SYMLINK    {c, r, s});
        case Proc::MKNOD:       return analysiss(&IAnalyzer::mknod3,     NFSPROC3_MKNOD      {c, r, s});
        case Proc::REMOVE:      return analysiss(&IAnalyzer::remove3,    NFSPROC3_REMOVE     {c, r, s});
        case Proc::RMDIR:       return analysiss(&IAnalyzer::rmdir3,     NFSPROC3_RMDIR      {c, r, s});
        case Proc::RENAME:      return analysiss(&IAnalyzer::rename3,    NFSPROC3_RENAME     {c, r, s});
        case Proc::LINK:        return analysiss(&IAnalyzer::link3,      NFSPROC3_LINK       {c, r, s});
        case Proc::READDIR:     return analysiss(&IAnalyzer::readdir3,   NFSPROC3_READDIR    {c, r, s});
        case Proc::READDIRPLUS: return analysiss(&IAnalyzer::readdirplus3, NFSPROC3_READDIRPLUS{c, r, s});
        case Proc::FSSTAT:      return analysiss(&IAnalyzer::fsstat3,    NFSPROC3_FSSTAT     {c, r, s});
        case Proc::FSINFO:      return analysiss(&IAnalyzer::fsinfo3,    NFSPROC3_FSINFO     {c, r, s});
        case Proc::PATHCONF:    return analysiss(&IAnalyzer::pathconf3,  NFSPROC3_PATHCONF   {c, r, s});
        case Proc::COMMIT:      return analysiss(&IAnalyzer::commit3,    NFSPROC3_COMMIT     {c, r, s});
        case Proc::num:;
        }
    }
    catch(XDRError& exception)
    {
        LOG("The data of NFS operation %s %s(%u) is too short for parsing", session->str().c_str(), Proc::Titles[procedure], procedure);
    }
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
