//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base structure for nfs-info.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "../../auxiliary/print/indent.h"
#include "nfs_procedures.h"
#include "nfs_operation.h"
#include "nfs_structs.h"
//------------------------------------------------------------------------------
using NST::analyzer::NFS3::Proc;
using NST::auxiliary::print::Indent;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace NFS3
{

NFSOperation::~NFSOperation()
{
    delete call;
    delete reply;
}

timeval NFSOperation::latency() const
{
    timeval diff;
    timerclear(&diff);
    if(call && reply)
    {
        timersub(&reply->get_time(), &call->get_time(), &diff);
    }
    return diff;
}

std::ostream& operator<<(std::ostream& out, const NFSOperation& obj)
{
    if(obj.session && obj.call)
    {
        out << "Session:" << std::endl << *obj.session << std::endl;
        out << *obj.call << std::endl;

        out << "Arguments:" << std::endl;
        Indent indentation(out, 4);
        switch(obj.call->get_proc())
        {
            case Proc::NFS_NULL :
                {
                }
                break;
            case Proc::GETATTR :
                {
                }
                break;
            case Proc::SETATTR :
                {
                    out << static_cast<const SetAttrArgs&>(*obj.get_call());
                }
                break;
            case Proc::LOOKUP :
                {
                }
                break;
            case Proc::ACCESS :
                {
                }
                break;
            case Proc::READLINK :
                {
                }
                break;
            case Proc::READ :
                {
                }
                break;
            case Proc::WRITE :
                {
                }
                break;
            case Proc::CREATE :
                {
                    out << static_cast<const CreateArgs&>(*obj.get_call());
                }
                break;
            case Proc::MKDIR :
                {
                    out << static_cast<const MkDirArgs&>(*obj.get_call());
                }
                break;
            case Proc::SYMLINK :
                {
                    out << static_cast<const SymLinkArgs&>(*obj.get_call());
                }
                break;
            case Proc::MKNOD :
                {
                    out << static_cast<const MkNodArgs&>(*obj.get_call());
                }
                break;
            case Proc::REMOVE :
                {
                }
                break;
            case Proc::RMDIR :
                {
                }
                break;
            case Proc::RENAME :
                {
                }
                break;
            case Proc::LINK :
                {
                }
                break;
            case Proc::READDIR :
                {
                }
                break;
            case Proc::READDIRPLUS :
                {
                }
                break;
            case Proc::FSSTAT :
                {
                }
                break;
            case Proc::FSINFO :
                {
                }
                break;
            case Proc::PATHCONF :
                {
                }
                break;
            case Proc::COMMIT :
                {
                }
                break;
        }
    }
    if(obj.reply)
    {
        out << std::endl;
        out << "Response:" << std::endl;
        Indent indentation(out, 4);
        out << "FUNCTIONALITY HAVE NOT BEEN IMPLEMENTED YET";
    }
    return out;
}

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
