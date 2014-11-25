///------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Operation CIFS analyzer. Identify clients that are busier than others.
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
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <list>
#include <map>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <sys/time.h>

#include <api/plugin_api.h>
//------------------------------------------------------------------------------
template <typename T>
T to_sec(const timeval& val)
{
    return (((T)val.tv_sec) + ((T)val.tv_usec) / 1000000.0);
}

template <typename T>
class TwoPassVariance
{
    using ConstIterator = std::list<timeval>::const_iterator;

public:
    TwoPassVariance() : count{0} {}
    ~TwoPassVariance() {}

    void add(const timeval& t)
    {
        ++count;
        latencies.push_back(t);
    }

    uint32_t get_count() const { return count; }

    T get_avg() const
    {
        if(count == 0) return T();

        ConstIterator   i = latencies.begin();
        ConstIterator end = latencies.end();

        timeval res;
        timerclear(&res);
        for(; i != end; ++i)
        {
            timeradd(&res, &(*i), &res);
        }
        return to_sec<T>(res) / count;
    }

    T get_st_dev() const
    {
        if(count < 2) return T();

        const T avg = get_avg();
        T st_dev = T();

        ConstIterator   i = latencies.begin();
        ConstIterator end = latencies.end();
        for(T delta; i != end; ++i)
        {
            delta = to_sec<T>(*i) - avg;
            st_dev += pow(delta, 2.0);
        }
        st_dev /= (count - 1);
        return sqrt(st_dev);
    }

private:
    void operator=(const TwoPassVariance&)  = delete;

    uint32_t count;
    std::list<timeval> latencies;
};

template <typename T>
class OnlineVariance
{
public:
    OnlineVariance() : count{0},
                       st_dev{},
                          avg{},
                           m2{} {}
    ~OnlineVariance() {}

    void add(const timeval& t)
    {
        T x = to_sec<T>(t);
        T delta = x - avg;
        avg += delta / (++count);
        m2 += delta * (x - avg);
    }

    uint32_t get_count() const { return count; }

    T get_avg() const { return avg; }

    T get_st_dev() const
    {
        if(count < 2) return T();
        return sqrt(m2 / (count - 1));
    }

private:
    void operator=(const OnlineVariance&) = delete;

    uint32_t count;
    T st_dev;
    T avg;
    T m2;
};

/*! CIFS v1 commands list
 */
enum class SMBv1Commands {
    SMB_COM_CREATE_DIRECTORY,       //!< Create a new directory.
    SMB_COM_DELETE_DIRECTORY,       //!< Delete an empty directory.
    SMB_COM_OPEN,                   //!< Open a file.
    SMB_COM_CREATE,                 //!< Create or open a file.
    SMB_COM_CLOSE,                  //!< Close a file.
    SMB_COM_FLUSH,                  //!< Flush data for a file
    SMB_COM_DELETE,                 //!< Delete a file.
    SMB_COM_RENAME,                 //!< Rename a file or set of files.
    SMB_COM_QUERY_INFORMATION,      //!< Get file attributes.
    SMB_COM_SET_INFORMATION,        //!< Set file attributes.
    SMB_COM_READ,                   //!< Read from a file.
    SMB_COM_WRITE,                  //!< Write to a file.
    SMB_COM_LOCK_BYTE_RANGE,        //!< Request a byte-range lock on a file.
    SMB_COM_UNLOCK_BYTE_RANGE,      //!< Release a byte-range lock on a file.
    SMB_COM_CREATE_TEMPORARY,       //!< Create a temporary file.
    SMB_COM_CREATE_NEW,             //!< Create and open a new file.
    SMB_COM_CHECK_DIRECTORY,        //!< Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation.
    SMB_COM_PROCESS_EXIT,           //!< Indicate process exit.
    SMB_COM_SEEK,                   //!< Set the current file pointer within a file.
    SMB_COM_LOCK_AND_READ,          //!< Lock and read a byte-range within a file.
    SMB_COM_WRITE_AND_UNLOCK,       //!< Write and unlock a byte-range within a file.
    SMB_COM_READ_RAW,               //!< Read a block in raw mode.
    SMB_COM_READ_MPX,               //!< Multiplexed block read. Listed as SMBreadmpx in some documentation.
    SMB_COM_READ_MPX_SECONDARY,     //!< Multiplexed block read
    SMB_COM_WRITE_RAW,              //!< Write a block in raw mode.
    SMB_COM_WRITE_MPX,              //!< Multiplexed block write.
    SMB_COM_WRITE_MPX_SECONDARY,    //!< Multiplexed block write
    SMB_COM_WRITE_COMPLETE,         //!< Raw block write
    SMB_COM_QUERY_SERVER,           //!< Reserved
    SMB_COM_SET_INFORMATION2,       //!< Set an extended set of file attributes.
    SMB_COM_QUERY_INFORMATION2,     //!< Get an extended set of file attributes.
    SMB_COM_LOCKING_ANDX,           //!< Lock multiple byte ranges; AndX chaining.
    SMB_COM_TRANSACTION,            //!< Transaction.
    SMB_COM_TRANSACTION_SECONDARY,  //!< Transaction secondary request.
    SMB_COM_IOCTL,                  //!< Pass an I/O Control function request to the server.
    SMB_COM_IOCTL_SECONDARY,        //!< IOCTL secondary request.
    SMB_COM_COPY,                   //!< Copy a file or directory.
    SMB_COM_MOVE,                   //!< Move a file or directory.
    SMB_COM_ECHO,                   //!< Echo request (ping).
    SMB_COM_WRITE_AND_CLOSE,        //!< Write to and close a file.
    SMB_COM_OPEN_ANDX,              //!< Extended file open with AndX chaining.
    SMB_COM_READ_ANDX,              //!< Extended file read with AndX chaining.
    SMB_COM_WRITE_ANDX,             //!< Extended file write with AndX chaining.
    SMB_COM_NEW_FILE_SIZE,          //!< Reserved
    SMB_COM_CLOSE_AND_TREE_DISC,    //!< Close an open file and tree disconnect.
    SMB_COM_TRANSACTION2,           //!< Transaction 2 format request/response.
    SMB_COM_TRANSACTION2_SECONDARY, //!< Transaction 2 secondary request.
    SMB_COM_FIND_CLOSE2,            //!< Close an active search.
    SMB_COM_FIND_NOTIFY_CLOSE,      //!< Notification of the closure of an active search.
    SMB_COM_TREE_CONNECT,           //!< Tree connect.
    SMB_COM_TREE_DISCONNECT,        //!< Tree disconnect.
    SMB_COM_NEGOTIATE,              //!< Negotiate protocol dialect.
    SMB_COM_SESSION_SETUP_ANDX,     //!< Session Setup with AndX chaining.
    SMB_COM_LOGOFF_ANDX,            //!< User logoff with AndX chaining.
    SMB_COM_TREE_CONNECT_ANDX,      //!< Tree connect with AndX chaining.
    SMB_COM_SECURITY_PACKAGE_ANDX,  //!< Negotiate security packages with AndX chaining.
    SMB_COM_QUERY_INFORMATION_DISK, //!< Retrieve file system information from the server.
    SMB_COM_SEARCH,                 //!< Directory wildcard search.
    SMB_COM_FIND,                   //!< Start or continue an extended wildcard directory search.
    SMB_COM_FIND_UNIQUE,            //!< Perform a one-time extended wildcard directory search.
    SMB_COM_FIND_CLOSE,             //!< End an extended wildcard directory search.
    SMB_COM_NT_TRANSACT,            //!< NT format transaction request/response.
    SMB_COM_NT_TRANSACT_SECONDARY,  //!< NT format transaction secondary request.
    SMB_COM_NT_CREATE_ANDX,         //!< Create or open a file or a directory.
    SMB_COM_NT_CANCEL,              //!< Cancel a request currently pending at the server.
    SMB_COM_NT_RENAME,              //!< File rename with extended semantics.
    SMB_COM_OPEN_PRINT_FILE,        //!< Create a print queue spool file.
    SMB_COM_WRITE_PRINT_FILE,       //!< Write to a print queue spool file.
    SMB_COM_CLOSE_PRINT_FILE,       //!< Close a print queue spool file.
    SMB_COM_GET_PRINT_QUEUE,        //!< Request print queue information.
    SMB_COM_READ_BULK,              //!< Reserved
    SMB_COM_WRITE_BULK,             //!< Reserved
    SMB_COM_WRITE_BULK_DATA,        //!< Reserved
    SMB_COM_INVALID,                //!< As the name suggests
    SMB_COM_NO_ANDX_COMMAND,        //!<  Also known as the NIL command. It identifies the end of an AndX Chain
    COUNT
};

/*! CIFS v2 commands list
 */
enum class SMBv2Commands {
    NEGOTIATE,
    SESSION_SETUP,
    LOGOFF,
    TREE_CONNECT,
    TREE_DISCONNECT,
    CREATE,
    CLOSE,
    FLUSH,
    READ,
    WRITE,
    LOCK,
    IOCTL,
    CANCEL,
    ECHO,
    QUERY_DIRECTORY,
    CHANGE_NOTIFY,
    QUERY_INFO,
    SET_INFO,
    OPLOCK_BREAK,
    COUNT
};

static const std::string commandDescription(SMBv2Commands cmd_code)
{
    static std::map<SMBv2Commands, std::string> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[SMBv2Commands::NEGOTIATE]         = "SMB v2 NEGOTIATE";
        cmdNames[SMBv2Commands::SESSION_SETUP]     = "SMB v2 SESSION_SETUP";
        cmdNames[SMBv2Commands::LOGOFF]            = "SMB v2 LOGOFF";
        cmdNames[SMBv2Commands::TREE_CONNECT]      = "SMB v2 TREE_CONNECT";
        cmdNames[SMBv2Commands::TREE_DISCONNECT]   = "SMB v2 TREE_DISCONNECT";
        cmdNames[SMBv2Commands::CREATE]            = "SMB v2 CREATE";
        cmdNames[SMBv2Commands::CLOSE]             = "SMB v2 CLOSE";
        cmdNames[SMBv2Commands::FLUSH]             = "SMB v2 FLUSH";
        cmdNames[SMBv2Commands::READ]              = "SMB v2 READ";
        cmdNames[SMBv2Commands::WRITE]             = "SMB v2 WRITE";
        cmdNames[SMBv2Commands::LOCK]              = "SMB v2 LOCK";
        cmdNames[SMBv2Commands::IOCTL]             = "SMB v2 IOCTL";
        cmdNames[SMBv2Commands::CANCEL]            = "SMB v2 CANCEL";
        cmdNames[SMBv2Commands::ECHO]              = "SMB v2 ECHO";
        cmdNames[SMBv2Commands::QUERY_DIRECTORY]   = "SMB v2 QUERY_DIRECTORY";
        cmdNames[SMBv2Commands::CHANGE_NOTIFY]     = "SMB v2 CHANGE_NOTIFY";
        cmdNames[SMBv2Commands::QUERY_INFO]        = "SMB v2 QUERY_INFO";
        cmdNames[SMBv2Commands::SET_INFO]          = "SMB v2 SET_INFO";
        cmdNames[SMBv2Commands::OPLOCK_BREAK]      = "SMB v2 OPLOCK_BREAK";
    }
    return cmdNames[cmd_code];
}

static const std::string commandName(SMBv2Commands cmd_code)
{
    static std::map<SMBv2Commands, std::string> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[SMBv2Commands::NEGOTIATE]         = "NEGOTIATE";
        cmdNames[SMBv2Commands::SESSION_SETUP]     = "SESSION SETUP";
        cmdNames[SMBv2Commands::LOGOFF]            = "LOGOFF";
        cmdNames[SMBv2Commands::TREE_CONNECT]      = "TREE CONNECT";
        cmdNames[SMBv2Commands::TREE_DISCONNECT]   = "TREE DISCONNECT";
        cmdNames[SMBv2Commands::CREATE]            = "CREATE";
        cmdNames[SMBv2Commands::CLOSE]             = "CLOSE";
        cmdNames[SMBv2Commands::FLUSH]             = "FLUSH";
        cmdNames[SMBv2Commands::READ]              = "READ";
        cmdNames[SMBv2Commands::WRITE]             = "WRITE";
        cmdNames[SMBv2Commands::LOCK]              = "LOCK";
        cmdNames[SMBv2Commands::IOCTL]             = "IOCTL";
        cmdNames[SMBv2Commands::CANCEL]            = "CANCEL";
        cmdNames[SMBv2Commands::ECHO]              = "ECHO";
        cmdNames[SMBv2Commands::QUERY_DIRECTORY]   = "QUERY DIRECTORY";
        cmdNames[SMBv2Commands::CHANGE_NOTIFY]     = "CHANGE NOTIFY";
        cmdNames[SMBv2Commands::QUERY_INFO]        = "QUERY INFO";
        cmdNames[SMBv2Commands::SET_INFO]          = "SET INFO";
        cmdNames[SMBv2Commands::OPLOCK_BREAK]      = "OPLOCK BREAK";
    }
    return cmdNames[cmd_code];
}

static const std::string commandDescription(SMBv1Commands cmd_code)
{
    static std::map<SMBv1Commands, const char *> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[SMBv1Commands::SMB_COM_CREATE_DIRECTORY]       = "SMB_COM_CREATE_DIRECTORY: Create a new directory.";
        cmdNames[SMBv1Commands::SMB_COM_DELETE_DIRECTORY]       = "SMB_COM_DELETE_DIRECTORY: Delete an empty directory.";
        cmdNames[SMBv1Commands::SMB_COM_OPEN]                   = "SMB_COM_OPEN: Open a file.";
        cmdNames[SMBv1Commands::SMB_COM_CREATE]                 = "SMB_COM_CREATE: Create or open a file.";
        cmdNames[SMBv1Commands::SMB_COM_CLOSE]                  = "SMB_COM_CLOSE: Close a file.";
        cmdNames[SMBv1Commands::SMB_COM_FLUSH]                  = "SMB_COM_FLUSH: Flush data for a file";
        cmdNames[SMBv1Commands::SMB_COM_DELETE]                 = "SMB_COM_DELETE: Delete a file.";
        cmdNames[SMBv1Commands::SMB_COM_RENAME]                 = "SMB_COM_RENAME: Rename a file or set of files.";
        cmdNames[SMBv1Commands::SMB_COM_QUERY_INFORMATION]      = "SMB_COM_QUERY_INFORMATION: Get file attributes.";
        cmdNames[SMBv1Commands::SMB_COM_SET_INFORMATION]        = "SMB_COM_SET_INFORMATION: Set file attributes.";
        cmdNames[SMBv1Commands::SMB_COM_READ]                   = "SMB_COM_READ: Read from a file.";
        cmdNames[SMBv1Commands::SMB_COM_WRITE]                  = "SMB_COM_WRITE: Write to a file.";
        cmdNames[SMBv1Commands::SMB_COM_LOCK_BYTE_RANGE]        = "SMB_COM_LOCK_BYTE_RANGE: Request a byte-range lock on a file.";
        cmdNames[SMBv1Commands::SMB_COM_UNLOCK_BYTE_RANGE]      = "SMB_COM_UNLOCK_BYTE_RANGE: Release a byte-range lock on a file.";
        cmdNames[SMBv1Commands::SMB_COM_CREATE_TEMPORARY]       = "SMB_COM_CREATE_TEMPORARY: Create a temporary file.";
        cmdNames[SMBv1Commands::SMB_COM_CREATE_NEW]             = "SMB_COM_CREATE_NEW: Create and open a new file.";
        cmdNames[SMBv1Commands::SMB_COM_CHECK_DIRECTORY]        = "SMB_COM_CHECK_DIRECTORY: Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation.";
        cmdNames[SMBv1Commands::SMB_COM_PROCESS_EXIT]           = "SMB_COM_PROCESS_EXIT: Indicate process exit.";
        cmdNames[SMBv1Commands::SMB_COM_SEEK]                   = "SMB_COM_SEEK: Set the current file pointer within a file.";
        cmdNames[SMBv1Commands::SMB_COM_LOCK_AND_READ]          = "SMB_COM_LOCK_AND_READ: Lock and read a byte-range within a file.";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_AND_UNLOCK]       = "SMB_COM_WRITE_AND_UNLOCK: Write and unlock a byte-range within a file.";
        cmdNames[SMBv1Commands::SMB_COM_READ_RAW]               = "SMB_COM_READ_RAW: Read a block in raw mode.";
        cmdNames[SMBv1Commands::SMB_COM_READ_MPX]               = "SMB_COM_READ_MPX: Multiplexed block read. Listed as SMBreadmpx in some documentation.";
        cmdNames[SMBv1Commands::SMB_COM_READ_MPX_SECONDARY]     = "SMB_COM_READ_MPX_SECONDARY: Multiplexed block read";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_RAW]              = "SMB_COM_WRITE_RAW: Write a block in raw mode.";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_MPX]              = "SMB_COM_WRITE_MPX: Multiplexed block write.";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_MPX_SECONDARY]    = "SMB_COM_WRITE_MPX_SECONDARY: Multiplexed block write";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_COMPLETE]         = "SMB_COM_WRITE_COMPLETE: Raw block write";
        cmdNames[SMBv1Commands::SMB_COM_QUERY_SERVER]           = "SMB_COM_QUERY_SERVER: Reserved";
        cmdNames[SMBv1Commands::SMB_COM_SET_INFORMATION2]       = "SMB_COM_SET_INFORMATION2: Set an extended set of file attributes.";
        cmdNames[SMBv1Commands::SMB_COM_QUERY_INFORMATION2]     = "SMB_COM_QUERY_INFORMATION2: Get an extended set of file attributes.";
        cmdNames[SMBv1Commands::SMB_COM_LOCKING_ANDX]           = "SMB_COM_LOCKING_ANDX: Lock multiple byte ranges; AndX chaining.";
        cmdNames[SMBv1Commands::SMB_COM_TRANSACTION]            = "SMB_COM_TRANSACTION: Transaction.";
        cmdNames[SMBv1Commands::SMB_COM_TRANSACTION_SECONDARY]  = "SMB_COM_TRANSACTION_SECONDARY: Transaction secondary request.";
        cmdNames[SMBv1Commands::SMB_COM_IOCTL]                  = "SMB_COM_IOCTL: Pass an I/O Control function request to the server.";
        cmdNames[SMBv1Commands::SMB_COM_IOCTL_SECONDARY]        = "SMB_COM_IOCTL_SECONDARY: IOCTL secondary request.";
        cmdNames[SMBv1Commands::SMB_COM_COPY]                   = "SMB_COM_COPY: Copy a file or directory.";
        cmdNames[SMBv1Commands::SMB_COM_MOVE]                   = "SMB_COM_MOVE: Move a file or directory.";
        cmdNames[SMBv1Commands::SMB_COM_ECHO]                   = "SMB_COM_ECHO: Echo request (ping).";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_AND_CLOSE]        = "SMB_COM_WRITE_AND_CLOSE: Write to and close a file.";
        cmdNames[SMBv1Commands::SMB_COM_OPEN_ANDX]              = "SMB_COM_OPEN_ANDX: Extended file open with AndX chaining.";
        cmdNames[SMBv1Commands::SMB_COM_READ_ANDX]              = "SMB_COM_READ_ANDX: Extended file read with AndX chaining.";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_ANDX]             = "SMB_COM_WRITE_ANDX: Extended file write with AndX chaining.";
        cmdNames[SMBv1Commands::SMB_COM_NEW_FILE_SIZE]          = "SMB_COM_NEW_FILE_SIZE: Reserved";
        cmdNames[SMBv1Commands::SMB_COM_CLOSE_AND_TREE_DISC]    = "SMB_COM_CLOSE_AND_TREE_DISC: Close an open file and tree disconnect.";
        cmdNames[SMBv1Commands::SMB_COM_TRANSACTION2]           = "SMB_COM_TRANSACTION2: Transaction 2 format request/response.";
        cmdNames[SMBv1Commands::SMB_COM_TRANSACTION2_SECONDARY] = "SMB_COM_TRANSACTION2_SECONDARY: Transaction 2 secondary request.";
        cmdNames[SMBv1Commands::SMB_COM_FIND_CLOSE2]            = "SMB_COM_FIND_CLOSE2: Close an active search.";
        cmdNames[SMBv1Commands::SMB_COM_FIND_NOTIFY_CLOSE]      = "SMB_COM_FIND_NOTIFY_CLOSE: Notification of the closure of an active search.";
        cmdNames[SMBv1Commands::SMB_COM_TREE_CONNECT]           = "SMB_COM_TREE_CONNECT: Tree connect.";
        cmdNames[SMBv1Commands::SMB_COM_TREE_DISCONNECT]        = "SMB_COM_TREE_DISCONNECT: Tree disconnect.";
        cmdNames[SMBv1Commands::SMB_COM_NEGOTIATE]              = "SMB_COM_NEGOTIATE: Negotiate protocol dialect.";
        cmdNames[SMBv1Commands::SMB_COM_SESSION_SETUP_ANDX]     = "SMB_COM_SESSION_SETUP_ANDX: Session Setup with AndX chaining.";
        cmdNames[SMBv1Commands::SMB_COM_LOGOFF_ANDX]            = "SMB_COM_LOGOFF_ANDX: User logoff with AndX chaining.";
        cmdNames[SMBv1Commands::SMB_COM_TREE_CONNECT_ANDX]      = "SMB_COM_TREE_CONNECT_ANDX: Tree connect with AndX chaining.";
        cmdNames[SMBv1Commands::SMB_COM_SECURITY_PACKAGE_ANDX]  = "SMB_COM_SECURITY_PACKAGE_ANDX: Negotiate security packages with AndX chaining.";
        cmdNames[SMBv1Commands::SMB_COM_QUERY_INFORMATION_DISK] = "SMB_COM_QUERY_INFORMATION_DISK: Retrieve file system information from the server.";
        cmdNames[SMBv1Commands::SMB_COM_SEARCH]                 = "SMB_COM_SEARCH: Directory wildcard search.";
        cmdNames[SMBv1Commands::SMB_COM_FIND]                   = "SMB_COM_FIND: Start or continue an extended wildcard directory search.";
        cmdNames[SMBv1Commands::SMB_COM_FIND_UNIQUE]            = "SMB_COM_FIND_UNIQUE: Perform a one-time extended wildcard directory search.";
        cmdNames[SMBv1Commands::SMB_COM_FIND_CLOSE]             = "SMB_COM_FIND_CLOSE: End an extended wildcard directory search.";
        cmdNames[SMBv1Commands::SMB_COM_NT_TRANSACT]            = "SMB_COM_NT_TRANSACT: NT format transaction request/response.";
        cmdNames[SMBv1Commands::SMB_COM_NT_TRANSACT_SECONDARY]  = "SMB_COM_NT_TRANSACT_SECONDARY: NT format transaction secondary request.";
        cmdNames[SMBv1Commands::SMB_COM_NT_CREATE_ANDX]         = "SMB_COM_NT_CREATE_ANDX: Create or open a file or a directory.";
        cmdNames[SMBv1Commands::SMB_COM_NT_CANCEL]              = "SMB_COM_NT_CANCEL: Cancel a request currently pending at the server.";
        cmdNames[SMBv1Commands::SMB_COM_NT_RENAME]              = "SMB_COM_NT_RENAME: File rename with extended semantics.";
        cmdNames[SMBv1Commands::SMB_COM_OPEN_PRINT_FILE]        = "SMB_COM_OPEN_PRINT_FILE: Create a print queue spool file.";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_PRINT_FILE]       = "SMB_COM_WRITE_PRINT_FILE: Write to a print queue spool file.";
        cmdNames[SMBv1Commands::SMB_COM_CLOSE_PRINT_FILE]       = "SMB_COM_CLOSE_PRINT_FILE: Close a print queue spool file.";
        cmdNames[SMBv1Commands::SMB_COM_GET_PRINT_QUEUE]        = "SMB_COM_GET_PRINT_QUEUE: Request print queue information.";
        cmdNames[SMBv1Commands::SMB_COM_READ_BULK]              = "SMB_COM_READ_BULK: Reserved";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_BULK]             = "SMB_COM_WRITE_BULK: Reserved";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_BULK_DATA]        = "SMB_COM_WRITE_BULK_DATA: Reserved";
        cmdNames[SMBv1Commands::SMB_COM_INVALID]                = "SMB_COM_INVALID: As the name suggests";
        cmdNames[SMBv1Commands::SMB_COM_NO_ANDX_COMMAND]        = "SMB_COM_NO_ANDX_COMMAND: Also known as the NIL command. It identifies the end of an AndX Chain";
    }
    return cmdNames[cmd_code];
}

static const std::string commandName(SMBv1Commands cmd_code)
{
    static std::map<SMBv1Commands, const char *> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[SMBv1Commands::SMB_COM_CREATE_DIRECTORY]       = "CREATE_DIRECTORY";
        cmdNames[SMBv1Commands::SMB_COM_DELETE_DIRECTORY]       = "DELETE_DIRECTORY";
        cmdNames[SMBv1Commands::SMB_COM_OPEN]                   = "OPEN";
        cmdNames[SMBv1Commands::SMB_COM_CREATE]                 = "CREATE";
        cmdNames[SMBv1Commands::SMB_COM_CLOSE]                  = "CLOSE";
        cmdNames[SMBv1Commands::SMB_COM_FLUSH]                  = "FLUSH";
        cmdNames[SMBv1Commands::SMB_COM_DELETE]                 = "DELETE";
        cmdNames[SMBv1Commands::SMB_COM_RENAME]                 = "RENAME";
        cmdNames[SMBv1Commands::SMB_COM_QUERY_INFORMATION]      = "QUERY_INFORMATION";
        cmdNames[SMBv1Commands::SMB_COM_SET_INFORMATION]        = "SET_INFORMATION";
        cmdNames[SMBv1Commands::SMB_COM_READ]                   = "READ";
        cmdNames[SMBv1Commands::SMB_COM_WRITE]                  = "WRITE";
        cmdNames[SMBv1Commands::SMB_COM_LOCK_BYTE_RANGE]        = "LOCK_BYTE_RANGE";
        cmdNames[SMBv1Commands::SMB_COM_UNLOCK_BYTE_RANGE]      = "UNLOCK_BYTE_RANGE";
        cmdNames[SMBv1Commands::SMB_COM_CREATE_TEMPORARY]       = "CREATE_TEMPORARY";
        cmdNames[SMBv1Commands::SMB_COM_CREATE_NEW]             = "CREATE_NEW";
        cmdNames[SMBv1Commands::SMB_COM_CHECK_DIRECTORY]        = "CHECK_DIRECTORY";
        cmdNames[SMBv1Commands::SMB_COM_PROCESS_EXIT]           = "PROCESS_EXIT";
        cmdNames[SMBv1Commands::SMB_COM_SEEK]                   = "SEEK";
        cmdNames[SMBv1Commands::SMB_COM_LOCK_AND_READ]          = "LOCK_AND_READ";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_AND_UNLOCK]       = "WRITE_AND_UNLOCK";
        cmdNames[SMBv1Commands::SMB_COM_READ_RAW]               = "READ_RAW";
        cmdNames[SMBv1Commands::SMB_COM_READ_MPX]               = "READ_MPX";
        cmdNames[SMBv1Commands::SMB_COM_READ_MPX_SECONDARY]     = "READ_MPX_SECONDARY";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_RAW]              = "WRITE_RAW";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_MPX]              = "WRITE_MPX";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_MPX_SECONDARY]    = "WRITE_MPX_SECONDARY";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_COMPLETE]         = "WRITE_COMPLETE";
        cmdNames[SMBv1Commands::SMB_COM_QUERY_SERVER]           = "QUERY_SERVER";
        cmdNames[SMBv1Commands::SMB_COM_SET_INFORMATION2]       = "SET_INFORMATION2";
        cmdNames[SMBv1Commands::SMB_COM_QUERY_INFORMATION2]     = "QUERY_INFORMATION2";
        cmdNames[SMBv1Commands::SMB_COM_LOCKING_ANDX]           = "LOCKING_ANDX";
        cmdNames[SMBv1Commands::SMB_COM_TRANSACTION]            = "TRANSACTION";
        cmdNames[SMBv1Commands::SMB_COM_TRANSACTION_SECONDARY]  = "TRANSACTION_SECONDARY";
        cmdNames[SMBv1Commands::SMB_COM_IOCTL]                  = "IOCTL";
        cmdNames[SMBv1Commands::SMB_COM_IOCTL_SECONDARY]        = "IOCTL_SECONDARY";
        cmdNames[SMBv1Commands::SMB_COM_COPY]                   = "COPY";
        cmdNames[SMBv1Commands::SMB_COM_MOVE]                   = "MOVE";
        cmdNames[SMBv1Commands::SMB_COM_ECHO]                   = "ECHO";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_AND_CLOSE]        = "WRITE_AND_CLOSE";
        cmdNames[SMBv1Commands::SMB_COM_OPEN_ANDX]              = "OPEN_ANDX";
        cmdNames[SMBv1Commands::SMB_COM_READ_ANDX]              = "READ_ANDX";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_ANDX]             = "WRITE_ANDX";
        cmdNames[SMBv1Commands::SMB_COM_NEW_FILE_SIZE]          = "NEW_FILE_SIZE";
        cmdNames[SMBv1Commands::SMB_COM_CLOSE_AND_TREE_DISC]    = "CLOSE_AND_TREE_DISC";
        cmdNames[SMBv1Commands::SMB_COM_TRANSACTION2]           = "TRANSACTION2";
        cmdNames[SMBv1Commands::SMB_COM_TRANSACTION2_SECONDARY] = "TRANSACTION2_SECONDARY";
        cmdNames[SMBv1Commands::SMB_COM_FIND_CLOSE2]            = "FIND_CLOSE2";
        cmdNames[SMBv1Commands::SMB_COM_FIND_NOTIFY_CLOSE]      = "FIND_NOTIFY_CLOSE";
        cmdNames[SMBv1Commands::SMB_COM_TREE_CONNECT]           = "TREE_CONNECT";
        cmdNames[SMBv1Commands::SMB_COM_TREE_DISCONNECT]        = "TREE_DISCONNECT";
        cmdNames[SMBv1Commands::SMB_COM_NEGOTIATE]              = "NEGOTIATE";
        cmdNames[SMBv1Commands::SMB_COM_SESSION_SETUP_ANDX]     = "SESSION_SETUP_ANDX";
        cmdNames[SMBv1Commands::SMB_COM_LOGOFF_ANDX]            = "LOGOFF_ANDX";
        cmdNames[SMBv1Commands::SMB_COM_TREE_CONNECT_ANDX]      = "TREE_CONNECT_ANDX";
        cmdNames[SMBv1Commands::SMB_COM_SECURITY_PACKAGE_ANDX]  = "SECURITY_PACKAGE_ANDX";
        cmdNames[SMBv1Commands::SMB_COM_QUERY_INFORMATION_DISK] = "QUERY_INFORMATION_DISK";
        cmdNames[SMBv1Commands::SMB_COM_SEARCH]                 = "SEARCH";
        cmdNames[SMBv1Commands::SMB_COM_FIND]                   = "FIND";
        cmdNames[SMBv1Commands::SMB_COM_FIND_UNIQUE]            = "FIND_UNIQUE";
        cmdNames[SMBv1Commands::SMB_COM_FIND_CLOSE]             = "FIND_CLOSE";
        cmdNames[SMBv1Commands::SMB_COM_NT_TRANSACT]            = "NT_TRANSACT";
        cmdNames[SMBv1Commands::SMB_COM_NT_TRANSACT_SECONDARY]  = "NT_TRANSACT_SECONDARY";
        cmdNames[SMBv1Commands::SMB_COM_NT_CREATE_ANDX]         = "NT_CREATE_ANDX";
        cmdNames[SMBv1Commands::SMB_COM_NT_CANCEL]              = "NT_CANCEL";
        cmdNames[SMBv1Commands::SMB_COM_NT_RENAME]              = "NT_RENAME";
        cmdNames[SMBv1Commands::SMB_COM_OPEN_PRINT_FILE]        = "OPEN_PRINT_FILE";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_PRINT_FILE]       = "WRITE_PRINT_FILE";
        cmdNames[SMBv1Commands::SMB_COM_CLOSE_PRINT_FILE]       = "CLOSE_PRINT_FILE";
        cmdNames[SMBv1Commands::SMB_COM_GET_PRINT_QUEUE]        = "GET_PRINT_QUEUE";
        cmdNames[SMBv1Commands::SMB_COM_READ_BULK]              = "READ_BULK";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_BULK]             = "WRITE_BULK";
        cmdNames[SMBv1Commands::SMB_COM_WRITE_BULK_DATA]        = "WRITE_BULK_DATA";
        cmdNames[SMBv1Commands::SMB_COM_INVALID]                = "INVALID";
        cmdNames[SMBv1Commands::SMB_COM_NO_ANDX_COMMAND]        = "NO_ANDX_COMMAND";
    }
    return cmdNames[cmd_code];
}

template
<
typename T, // Data type defines evaluation precision
template <typename> class Algorithm // Evaluation algorithm
>
class Latencies
{
public:
    Latencies()
    {
        timerclear(&min);
        timerclear(&max);
    }

    void add(const timeval& t)        { algorithm.add(t); set_range(t); }
    uint64_t       get_count()  const { return algorithm.get_count();   }
    long double    get_avg()    const { return algorithm.get_avg();     }
    long double    get_st_dev() const { return algorithm.get_st_dev();  }
    const timeval& get_min()    const { return min; }
    const timeval& get_max()    const { return max; }

private:
    void operator=(const Latencies&) = delete;

    void set_range(const timeval& t)
    {
        if(timercmp(&t, &min, <))
            min = t;
        if(min.tv_sec == 0 && min.tv_usec == 0)
            min = t;
        if(timercmp(&t, &max, >))
            max = t;
    }

    Algorithm<T> algorithm;
    timeval min;
    timeval max;
};

template
<
    typename T,
    template <class> class Algorithm
>
class BreakdownCounter
{
public:
     BreakdownCounter() {}
    ~BreakdownCounter() {}
    const Latencies<T, Algorithm>& operator[](int index) const
    {
        return latencies[index];
    }
    Latencies<T, Algorithm>& operator[](int index)
    {
        return latencies[index];
    }

    uint64_t getTotalCount () const
    {
        return std::accumulate(std::begin(latencies), std::end(latencies), 0, [](int sum, const Latencies<T, Algorithm>& latency)
        {
            return sum + latency.get_count();
        });
    }

private:
    void operator=  (const BreakdownCounter&) = delete;

    Latencies<T, Algorithm> latencies[static_cast<int>(SMBv1Commands::COUNT)];//FIXME: wrong size
};

/*! \class Represents statistic
 */
template
<
    typename Statistic,
    typename SMBCommands
>
class Representer
{
    std::ostream& out;
public:
    Representer(std::ostream& o = std::cout)
                : out(o)
    {
    }

    virtual void flush_statistics(const Statistic &statistic)
    {
         out << "###  Breakdown analyzer  ###"
             << std::endl
             << "CIFS total procedures: "
             << statistic.procedures_total_count
             << ". Per procedure:"
             << std::endl;

         for (const auto& procedure: statistic.procedures_count)
         {
             //FIXME: Sync primitives to be used
             out.width(12);
             out << std::left
                 << commandDescription(procedure.first);
             out.width(5);
             out << std::right
                 << procedure.second;
             out.width(7);
             out.setf(std::ios::fixed, std::ios::floatfield);
             out.precision(2);
             out << (statistic.procedures_total_count ? ((1.0 * procedure.second / statistic.procedures_total_count) * 100.0) : 0);
             out.setf(std::ios::fixed | std::ios::scientific , std::ios::floatfield);
             out << '%' << std::endl;
         };

         if (statistic.per_procedure_statistic.size())  // is not empty?
         {
            out << "Per connection info: " << std::endl;

            std::stringstream session;

             for(auto& it : statistic.per_procedure_statistic)
             {
                 const typename Statistic::Breakdown& current = it.second;
                 uint64_t s_total_proc = current.getTotalCount();

                 session.str("");
                 //print_session(session, it.first);//FIXME: print session
                 print_per_session<static_cast<int>(SMBCommands::COUNT)>(current, session.str(), s_total_proc);
                 std::ofstream file(("breakdown_" + session.str() + ".dat").c_str(), std::ios::out | std::ios::trunc);
                 store_per_session<static_cast<int>(SMBCommands::COUNT)>(file, current, session.str(), s_total_proc);
             }
         }
    }


    template<int op_count>
    void store_per_session(std::ostream& file,
                           const typename Statistic::Breakdown& breakdown,
                           const std::string& session,
                           uint64_t s_total_proc) const
    {
        file << "Session: " << session << std::endl;

        for(unsigned i = 0; i < op_count; ++i)
        {
            file << commandName(static_cast<SMBCommands>(i));
            file << ' ' << breakdown[i].get_count() << ' ';
            file << (s_total_proc ? (((long double)(breakdown[i].get_count()) / s_total_proc) * 100) : 0);
            file << ' ' << to_sec<long double>(breakdown[i].get_min())
                 << ' ' << to_sec<long double>(breakdown[i].get_max())
                 << ' ' << breakdown[i].get_avg()
                 << ' ' << breakdown[i].get_st_dev()
                 << std::endl;
        }
    }

    template<int op_count>
    void print_per_session(const typename Statistic::Breakdown& breakdown,
                           const std::string& session,
                           uint64_t s_total_proc) const
    {
        out << "Session: " << session << std::endl;

        out << "Total procedures: " << s_total_proc
            << ". Per procedure:"   << std::endl;
        for(unsigned i = 0; i < op_count; ++i)
        {
            out.width(22);
                out << std::left
                    << commandName(static_cast<SMBCommands>(i));
            out.width(6);
            out << " Count:";
            out.width(5);
            out << std::right
                << breakdown[i].get_count()
                << ' ';
            out.precision(2);
            out << '(';
            out.width(6);
            out << std::fixed
                << (s_total_proc ? (((long double)(breakdown[i].get_count()) / s_total_proc) * 100) : 0);
            out << "%) Min: ";
            out.precision(3);
            out << std::fixed
                << to_sec<long double>(breakdown[i].get_min())
                << " Max: "
                << std::fixed
                << to_sec<long double>(breakdown[i].get_max())
                << " Avg: "
                << std::fixed
                << breakdown[i].get_avg();
            out.precision(8);
            out << " StDev: "
                << std::fixed
                << breakdown[i].get_st_dev()
                << std::endl;
        }
    }
};


/*! \class Analyzer for CIFS v1
 */
template
<
    template <class> class Algorithm
>
class CIFSBreakdownAnalyzer : public IAnalyzer
{
    /*! \class All statistic data
     */
    struct Statistic {
        using Breakdown = BreakdownCounter<long double, Algorithm>;
        using PerOpStat = std::map<SMBv1::Session, Breakdown>;
        using Pair = typename PerOpStat::value_type;
        using ProceduresCount = std::map<SMBv1Commands, int>;

        uint64_t procedures_total_count;//!< Total amount of procedures
        ProceduresCount procedures_count;//!< Count of each procedure
        PerOpStat per_procedure_statistic;//!< Statistic for each procedure

        Statistic() : procedures_total_count{0} {}
    };

    Statistic smbv1;//!< Statistic
    Representer<Statistic, SMBv1Commands> representer;//!< Class for statistic representation
public:
    CIFSBreakdownAnalyzer(std::ostream& o = std::cout)
                          : representer(o)
    {
    }

    void echoRequest(const SMBv1::EchoRequestCommand* cmd, const SMBv1::EchoRequestArgumentType&, const SMBv1::EchoRequestResultType&) override final
    {
        account(cmd, SMBv1Commands::SMB_COM_ECHO, smbv1);
    }

    void closeFile(const SMBv1::CloseFileCommand *cmd, const SMBv1::CloseFileArgumentType &, const SMBv1::CloseFileResultType &) override final
    {
        account(cmd, SMBv1Commands::SMB_COM_CLOSE, smbv1);
    }

    virtual void flush_statistics()
    {
        representer.flush_statistics(smbv1);
    }

protected:
    template<typename Cmd, typename Code, typename Stats>
    void account(const Cmd* proc, Code cmd_code, Stats &stats)
    {
        typename Statistic::PerOpStat::iterator i;
        timeval latency{0,0};

        // diff between 'reply' and 'call' timestamps
        //timersub(0, 0, &latency);//FIXME: Latency?

        ++stats.procedures_total_count;
        ++stats.procedures_count[cmd_code];

        i = stats.per_procedure_statistic.find(proc->session);
        if(i == stats.per_procedure_statistic.end())
        {
            auto session_res = stats.per_procedure_statistic.emplace(proc->session, typename Statistic::Breakdown{});
            if(session_res.second == false) return;
            i = session_res.first;
        }

        (i->second)[static_cast<int>(cmd_code)].add(latency);
    }
};

/*! \class Analyzer for CIFS v2
 */
template
<
        template <class> class Algorithm
>
class CIFSv2BreakdownAnalyzer : public CIFSBreakdownAnalyzer<Algorithm>
{
    /*! \class All statistic data
     */
    struct Statistic {
        using Breakdown = BreakdownCounter<long double, Algorithm>;
        using PerOpStat = std::map<SMBv1::Session, Breakdown>;
        using Pair = typename PerOpStat::value_type;
        using ProceduresCount = std::map<SMBv2Commands, int>;

        uint64_t procedures_total_count;//!< Total amount of procedures
        ProceduresCount procedures_count;//!< Count of each procedure
        PerOpStat per_procedure_statistic;//!< Statistic for each procedure

        Statistic() : procedures_total_count{0} {}
    };

    Statistic smbv2;//!< Statistic
    Representer<Statistic, SMBv2Commands> representer;//!< Class for statistic representation
public:
    CIFSv2BreakdownAnalyzer(std::ostream& o = std::cout)
                            : CIFSBreakdownAnalyzer<Algorithm>(o)
                            , representer(o)
    {
    }

    void closeFileSMBv2(const SMBv2::CloseFileCommand *cmd, const SMBv2::CloseFileArgumentType &, const SMBv2::CloseFileResultType &) override final
    {
        CIFSBreakdownAnalyzer<Algorithm>::account(cmd, SMBv2Commands::CLOSE, smbv2);
    }

    virtual void flush_statistics()
    {
         CIFSBreakdownAnalyzer<Algorithm>::flush_statistics();//FIXME: use observer
         representer.flush_statistics(smbv2);
    }

};

extern "C"
{

const char* usage()
{
    return "ACC - for accurate evaluation(default), MEM - for memory efficient evaluation. Options cannot be combined";
}

IAnalyzer* create(const char* optarg)
{
    enum
    {
        ACC = 0,
        MEM
    };
    const char* token[] = {
        "ACC",
        "MEM",
         NULL
    };

    char* value = NULL;
    if(*optarg == '\0')
        return new CIFSv2BreakdownAnalyzer<OnlineVariance>();
    else
        do
        {
            switch(getsubopt((char**)&optarg, (char**)token, &value))
            {
                case ACC:
                    return new CIFSv2BreakdownAnalyzer<TwoPassVariance>();
                    break;

                case MEM:
                    return new CIFSv2BreakdownAnalyzer<OnlineVariance>();
                    break;

                default:
                    return nullptr;
            }
        } while (*optarg != '\0');
    return nullptr;
}

void destroy(IAnalyzer* instance)
{
    delete instance;
}

NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

}//extern "C"
//------------------------------------------------------------------------------
