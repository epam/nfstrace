//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Helpers for parsing CIFS structures.
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
#include <cassert>

#include "api/plugin_api.h" // for NST_PUBLIC
#include "protocols/cifs/cifs.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::CIFSv1;
using namespace NST::API;
union SMBCode {
    uint8_t  codes[4];
    uint32_t code;
};

static inline uint32_t get_code()
{
    SMBCode code;

    code.codes[0] = static_cast<uint8_t>(ProtocolCodes::SMB1);
    code.codes[1] = 'S';
    code.codes[2] = 'M';
    code.codes[3] = 'B';

    return code.code;
}

const NST::protocols::CIFSv1::MessageHeader* NST::protocols::CIFSv1::get_header(const uint8_t* data)
{
    static uint32_t code = get_code();

    const MessageHeader* header(reinterpret_cast<const MessageHeader*>(data));
    if(header->head_code == code)
    {
        return header;
    }
    return nullptr;
}

bool MessageHeader::isFlag(const Flags flag) const
{
    return static_cast<uint8_t>(flag) & static_cast<uint8_t>(flags);
}

extern "C" NST_PUBLIC const char* print_cifs1_procedures(SMBv1Commands cmd_code)
{
    assert(cmd_code < SMBv1Commands::CMD_COUNT);

    // clang-format off
    static const char* const commandNames[] =
    {
        "CREATE_DIRECTORY",       "DELETE_DIRECTORY",         "OPEN",                     "CREATE",
        "CLOSE",                  "FLUSH",                    "DELETE",                   "RENAME",
        "QUERY_INFORMATION",      "SET_INFORMATION",          "READ",                     "WRITE",
        "LOCK_BYTE_RANGE",        "UNLOCK_BYTE_RANGE",        "CREATE_TEMPORARY",         "CREATE_NEW",
        "CHECK_DIRECTORY",        "PROCESS_EXIT",             "SEEK",                     "LOCK_AND_READ",
        "WRITE_AND_UNLOCK",       "READ_RAW",                 "READ_MPX",                 "READ_MPX_SECONDARY",
        "WRITE_RAW",              "WRITE_MPX",                "WRITE_MPX_SECONDARY",      "WRITE_COMPLETE",
        "QUERY_SERVER",           "SET_INFORMATION2",         "QUERY_INFORMATION2",       "LOCKING_ANDX",
        "TRANSACTION",            "TRANSACTION_SECONDARY",    "IOCTL",                    "IOCTL_SECONDARY",
        "COPY",                   "MOVE",                     "ECHO",                     "WRITE_AND_CLOSE",
        "OPEN_ANDX",              "READ_ANDX",                "WRITE_ANDX",               "NEW_FILE_SIZE",
        "CLOSE_AND_TREE_DISC",    "TRANSACTION2",             "TRANSACTION2_SECONDARY",   "FIND_CLOSE2",
        "FIND_NOTIFY_CLOSE",      "TREE_CONNECT",             "TREE_DISCONNECT",          "NEGOTIATE",
        "SESSION_SETUP_ANDX",     "LOGOFF_ANDX",              "TREE_CONNECT_ANDX",        "SECURITY_PACKAGE_ANDX",
        "QUERY_INFORMATION_DISK", "SEARCH",                   "FIND",                     "FIND_UNIQUE",
        "FIND_CLOSE",             "NT_TRANSACT",              "NT_TRANSACT_SECONDARY",    "NT_CREATE_ANDX",
        "NT_CANCEL",              "NT_RENAME",                "OPEN_PRINT_FILE",          "WRITE_PRINT_FILE",
        "CLOSE_PRINT_FILE",       "GET_PRINT_QUEUE",          "READ_BULK",                "WRITE_BULK",
        "WRITE_BULK_DATA",        "INVALID",                  "NO_ANDX_COMMAND"
    };
    // clang-format on

    return commandNames[static_cast<int>(cmd_code)];
}
