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

/*! CIFS commands
 */
enum class Commands : uint8_t {
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
    SBM_COM_COUNT
};

static const std::string commandDescription(Commands cmd_code)
{
    static std::map<Commands, const char *> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[Commands::SMB_COM_CREATE_DIRECTORY]       = "SMB_COM_CREATE_DIRECTORY: Create a new directory.";
        cmdNames[Commands::SMB_COM_DELETE_DIRECTORY]       = "SMB_COM_DELETE_DIRECTORY: Delete an empty directory.";
        cmdNames[Commands::SMB_COM_OPEN]                   = "SMB_COM_OPEN: Open a file.";
        cmdNames[Commands::SMB_COM_CREATE]                 = "SMB_COM_CREATE: Create or open a file.";
        cmdNames[Commands::SMB_COM_CLOSE]                  = "SMB_COM_CLOSE: Close a file.";
        cmdNames[Commands::SMB_COM_FLUSH]                  = "SMB_COM_FLUSH: Flush data for a file";
        cmdNames[Commands::SMB_COM_DELETE]                 = "SMB_COM_DELETE: Delete a file.";
        cmdNames[Commands::SMB_COM_RENAME]                 = "SMB_COM_RENAME: Rename a file or set of files.";
        cmdNames[Commands::SMB_COM_QUERY_INFORMATION]      = "SMB_COM_QUERY_INFORMATION: Get file attributes.";
        cmdNames[Commands::SMB_COM_SET_INFORMATION]        = "SMB_COM_SET_INFORMATION: Set file attributes.";
        cmdNames[Commands::SMB_COM_READ]                   = "SMB_COM_READ: Read from a file.";
        cmdNames[Commands::SMB_COM_WRITE]                  = "SMB_COM_WRITE: Write to a file.";
        cmdNames[Commands::SMB_COM_LOCK_BYTE_RANGE]        = "SMB_COM_LOCK_BYTE_RANGE: Request a byte-range lock on a file.";
        cmdNames[Commands::SMB_COM_UNLOCK_BYTE_RANGE]      = "SMB_COM_UNLOCK_BYTE_RANGE: Release a byte-range lock on a file.";
        cmdNames[Commands::SMB_COM_CREATE_TEMPORARY]       = "SMB_COM_CREATE_TEMPORARY: Create a temporary file.";
        cmdNames[Commands::SMB_COM_CREATE_NEW]             = "SMB_COM_CREATE_NEW: Create and open a new file.";
        cmdNames[Commands::SMB_COM_CHECK_DIRECTORY]        = "SMB_COM_CHECK_DIRECTORY: Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation.";
        cmdNames[Commands::SMB_COM_PROCESS_EXIT]           = "SMB_COM_PROCESS_EXIT: Indicate process exit.";
        cmdNames[Commands::SMB_COM_SEEK]                   = "SMB_COM_SEEK: Set the current file pointer within a file.";
        cmdNames[Commands::SMB_COM_LOCK_AND_READ]          = "SMB_COM_LOCK_AND_READ: Lock and read a byte-range within a file.";
        cmdNames[Commands::SMB_COM_WRITE_AND_UNLOCK]       = "SMB_COM_WRITE_AND_UNLOCK: Write and unlock a byte-range within a file.";
        cmdNames[Commands::SMB_COM_READ_RAW]               = "SMB_COM_READ_RAW: Read a block in raw mode.";
        cmdNames[Commands::SMB_COM_READ_MPX]               = "SMB_COM_READ_MPX: Multiplexed block read. Listed as SMBreadmpx in some documentation.";
        cmdNames[Commands::SMB_COM_READ_MPX_SECONDARY]     = "SMB_COM_READ_MPX_SECONDARY: Multiplexed block read";
        cmdNames[Commands::SMB_COM_WRITE_RAW]              = "SMB_COM_WRITE_RAW: Write a block in raw mode.";
        cmdNames[Commands::SMB_COM_WRITE_MPX]              = "SMB_COM_WRITE_MPX: Multiplexed block write.";
        cmdNames[Commands::SMB_COM_WRITE_MPX_SECONDARY]    = "SMB_COM_WRITE_MPX_SECONDARY: Multiplexed block write";
        cmdNames[Commands::SMB_COM_WRITE_COMPLETE]         = "SMB_COM_WRITE_COMPLETE: Raw block write";
        cmdNames[Commands::SMB_COM_QUERY_SERVER]           = "SMB_COM_QUERY_SERVER: Reserved";
        cmdNames[Commands::SMB_COM_SET_INFORMATION2]       = "SMB_COM_SET_INFORMATION2: Set an extended set of file attributes.";
        cmdNames[Commands::SMB_COM_QUERY_INFORMATION2]     = "SMB_COM_QUERY_INFORMATION2: Get an extended set of file attributes.";
        cmdNames[Commands::SMB_COM_LOCKING_ANDX]           = "SMB_COM_LOCKING_ANDX: Lock multiple byte ranges; AndX chaining.";
        cmdNames[Commands::SMB_COM_TRANSACTION]            = "SMB_COM_TRANSACTION: Transaction.";
        cmdNames[Commands::SMB_COM_TRANSACTION_SECONDARY]  = "SMB_COM_TRANSACTION_SECONDARY: Transaction secondary request.";
        cmdNames[Commands::SMB_COM_IOCTL]                  = "SMB_COM_IOCTL: Pass an I/O Control function request to the server.";
        cmdNames[Commands::SMB_COM_IOCTL_SECONDARY]        = "SMB_COM_IOCTL_SECONDARY: IOCTL secondary request.";
        cmdNames[Commands::SMB_COM_COPY]                   = "SMB_COM_COPY: Copy a file or directory.";
        cmdNames[Commands::SMB_COM_MOVE]                   = "SMB_COM_MOVE: Move a file or directory.";
        cmdNames[Commands::SMB_COM_ECHO]                   = "SMB_COM_ECHO: Echo request (ping).";
        cmdNames[Commands::SMB_COM_WRITE_AND_CLOSE]        = "SMB_COM_WRITE_AND_CLOSE: Write to and close a file.";
        cmdNames[Commands::SMB_COM_OPEN_ANDX]              = "SMB_COM_OPEN_ANDX: Extended file open with AndX chaining.";
        cmdNames[Commands::SMB_COM_READ_ANDX]              = "SMB_COM_READ_ANDX: Extended file read with AndX chaining.";
        cmdNames[Commands::SMB_COM_WRITE_ANDX]             = "SMB_COM_WRITE_ANDX: Extended file write with AndX chaining.";
        cmdNames[Commands::SMB_COM_NEW_FILE_SIZE]          = "SMB_COM_NEW_FILE_SIZE: Reserved";
        cmdNames[Commands::SMB_COM_CLOSE_AND_TREE_DISC]    = "SMB_COM_CLOSE_AND_TREE_DISC: Close an open file and tree disconnect.";
        cmdNames[Commands::SMB_COM_TRANSACTION2]           = "SMB_COM_TRANSACTION2: Transaction 2 format request/response.";
        cmdNames[Commands::SMB_COM_TRANSACTION2_SECONDARY] = "SMB_COM_TRANSACTION2_SECONDARY: Transaction 2 secondary request.";
        cmdNames[Commands::SMB_COM_FIND_CLOSE2]            = "SMB_COM_FIND_CLOSE2: Close an active search.";
        cmdNames[Commands::SMB_COM_FIND_NOTIFY_CLOSE]      = "SMB_COM_FIND_NOTIFY_CLOSE: Notification of the closure of an active search.";
        cmdNames[Commands::SMB_COM_TREE_CONNECT]           = "SMB_COM_TREE_CONNECT: Tree connect.";
        cmdNames[Commands::SMB_COM_TREE_DISCONNECT]        = "SMB_COM_TREE_DISCONNECT: Tree disconnect.";
        cmdNames[Commands::SMB_COM_NEGOTIATE]              = "SMB_COM_NEGOTIATE: Negotiate protocol dialect.";
        cmdNames[Commands::SMB_COM_SESSION_SETUP_ANDX]     = "SMB_COM_SESSION_SETUP_ANDX: Session Setup with AndX chaining.";
        cmdNames[Commands::SMB_COM_LOGOFF_ANDX]            = "SMB_COM_LOGOFF_ANDX: User logoff with AndX chaining.";
        cmdNames[Commands::SMB_COM_TREE_CONNECT_ANDX]      = "SMB_COM_TREE_CONNECT_ANDX: Tree connect with AndX chaining.";
        cmdNames[Commands::SMB_COM_SECURITY_PACKAGE_ANDX]  = "SMB_COM_SECURITY_PACKAGE_ANDX: Negotiate security packages with AndX chaining.";
        cmdNames[Commands::SMB_COM_QUERY_INFORMATION_DISK] = "SMB_COM_QUERY_INFORMATION_DISK: Retrieve file system information from the server.";
        cmdNames[Commands::SMB_COM_SEARCH]                 = "SMB_COM_SEARCH: Directory wildcard search.";
        cmdNames[Commands::SMB_COM_FIND]                   = "SMB_COM_FIND: Start or continue an extended wildcard directory search.";
        cmdNames[Commands::SMB_COM_FIND_UNIQUE]            = "SMB_COM_FIND_UNIQUE: Perform a one-time extended wildcard directory search.";
        cmdNames[Commands::SMB_COM_FIND_CLOSE]             = "SMB_COM_FIND_CLOSE: End an extended wildcard directory search.";
        cmdNames[Commands::SMB_COM_NT_TRANSACT]            = "SMB_COM_NT_TRANSACT: NT format transaction request/response.";
        cmdNames[Commands::SMB_COM_NT_TRANSACT_SECONDARY]  = "SMB_COM_NT_TRANSACT_SECONDARY: NT format transaction secondary request.";
        cmdNames[Commands::SMB_COM_NT_CREATE_ANDX]         = "SMB_COM_NT_CREATE_ANDX: Create or open a file or a directory.";
        cmdNames[Commands::SMB_COM_NT_CANCEL]              = "SMB_COM_NT_CANCEL: Cancel a request currently pending at the server.";
        cmdNames[Commands::SMB_COM_NT_RENAME]              = "SMB_COM_NT_RENAME: File rename with extended semantics.";
        cmdNames[Commands::SMB_COM_OPEN_PRINT_FILE]        = "SMB_COM_OPEN_PRINT_FILE: Create a print queue spool file.";
        cmdNames[Commands::SMB_COM_WRITE_PRINT_FILE]       = "SMB_COM_WRITE_PRINT_FILE: Write to a print queue spool file.";
        cmdNames[Commands::SMB_COM_CLOSE_PRINT_FILE]       = "SMB_COM_CLOSE_PRINT_FILE: Close a print queue spool file.";
        cmdNames[Commands::SMB_COM_GET_PRINT_QUEUE]        = "SMB_COM_GET_PRINT_QUEUE: Request print queue information.";
        cmdNames[Commands::SMB_COM_READ_BULK]              = "SMB_COM_READ_BULK: Reserved";
        cmdNames[Commands::SMB_COM_WRITE_BULK]             = "SMB_COM_WRITE_BULK: Reserved";
        cmdNames[Commands::SMB_COM_WRITE_BULK_DATA]        = "SMB_COM_WRITE_BULK_DATA: Reserved";
        cmdNames[Commands::SMB_COM_INVALID]                = "SMB_COM_INVALID: As the name suggests";
        cmdNames[Commands::SMB_COM_NO_ANDX_COMMAND]        = "SMB_COM_NO_ANDX_COMMAND: Also known as the NIL command. It identifies the end of an AndX Chain";
    }
    return cmdNames[cmd_code];
}

static inline const std::string commandDescription(int cmd_code)
{
    return commandDescription(static_cast<Commands>(cmd_code));
}

static const std::string commandName(Commands cmd_code)
{
    static std::map<Commands, const char *> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[Commands::SMB_COM_CREATE_DIRECTORY]       = "CREATE_DIRECTORY";
        cmdNames[Commands::SMB_COM_DELETE_DIRECTORY]       = "DELETE_DIRECTORY";
        cmdNames[Commands::SMB_COM_OPEN]                   = "OPEN";
        cmdNames[Commands::SMB_COM_CREATE]                 = "CREATE";
        cmdNames[Commands::SMB_COM_CLOSE]                  = "CLOSE";
        cmdNames[Commands::SMB_COM_FLUSH]                  = "FLUSH";
        cmdNames[Commands::SMB_COM_DELETE]                 = "DELETE";
        cmdNames[Commands::SMB_COM_RENAME]                 = "RENAME";
        cmdNames[Commands::SMB_COM_QUERY_INFORMATION]      = "QUERY_INFORMATION";
        cmdNames[Commands::SMB_COM_SET_INFORMATION]        = "SET_INFORMATION";
        cmdNames[Commands::SMB_COM_READ]                   = "READ";
        cmdNames[Commands::SMB_COM_WRITE]                  = "WRITE";
        cmdNames[Commands::SMB_COM_LOCK_BYTE_RANGE]        = "LOCK_BYTE_RANGE";
        cmdNames[Commands::SMB_COM_UNLOCK_BYTE_RANGE]      = "UNLOCK_BYTE_RANGE";
        cmdNames[Commands::SMB_COM_CREATE_TEMPORARY]       = "CREATE_TEMPORARY";
        cmdNames[Commands::SMB_COM_CREATE_NEW]             = "CREATE_NEW";
        cmdNames[Commands::SMB_COM_CHECK_DIRECTORY]        = "CHECK_DIRECTORY";
        cmdNames[Commands::SMB_COM_PROCESS_EXIT]           = "PROCESS_EXIT";
        cmdNames[Commands::SMB_COM_SEEK]                   = "SEEK";
        cmdNames[Commands::SMB_COM_LOCK_AND_READ]          = "LOCK_AND_READ";
        cmdNames[Commands::SMB_COM_WRITE_AND_UNLOCK]       = "WRITE_AND_UNLOCK";
        cmdNames[Commands::SMB_COM_READ_RAW]               = "READ_RAW";
        cmdNames[Commands::SMB_COM_READ_MPX]               = "READ_MPX";
        cmdNames[Commands::SMB_COM_READ_MPX_SECONDARY]     = "READ_MPX_SECONDARY";
        cmdNames[Commands::SMB_COM_WRITE_RAW]              = "WRITE_RAW";
        cmdNames[Commands::SMB_COM_WRITE_MPX]              = "WRITE_MPX";
        cmdNames[Commands::SMB_COM_WRITE_MPX_SECONDARY]    = "WRITE_MPX_SECONDARY";
        cmdNames[Commands::SMB_COM_WRITE_COMPLETE]         = "WRITE_COMPLETE";
        cmdNames[Commands::SMB_COM_QUERY_SERVER]           = "QUERY_SERVER";
        cmdNames[Commands::SMB_COM_SET_INFORMATION2]       = "SET_INFORMATION2";
        cmdNames[Commands::SMB_COM_QUERY_INFORMATION2]     = "QUERY_INFORMATION2";
        cmdNames[Commands::SMB_COM_LOCKING_ANDX]           = "LOCKING_ANDX";
        cmdNames[Commands::SMB_COM_TRANSACTION]            = "TRANSACTION";
        cmdNames[Commands::SMB_COM_TRANSACTION_SECONDARY]  = "TRANSACTION_SECONDARY";
        cmdNames[Commands::SMB_COM_IOCTL]                  = "IOCTL";
        cmdNames[Commands::SMB_COM_IOCTL_SECONDARY]        = "IOCTL_SECONDARY";
        cmdNames[Commands::SMB_COM_COPY]                   = "COPY";
        cmdNames[Commands::SMB_COM_MOVE]                   = "MOVE";
        cmdNames[Commands::SMB_COM_ECHO]                   = "ECHO";
        cmdNames[Commands::SMB_COM_WRITE_AND_CLOSE]        = "WRITE_AND_CLOSE";
        cmdNames[Commands::SMB_COM_OPEN_ANDX]              = "OPEN_ANDX";
        cmdNames[Commands::SMB_COM_READ_ANDX]              = "READ_ANDX";
        cmdNames[Commands::SMB_COM_WRITE_ANDX]             = "WRITE_ANDX";
        cmdNames[Commands::SMB_COM_NEW_FILE_SIZE]          = "NEW_FILE_SIZE";
        cmdNames[Commands::SMB_COM_CLOSE_AND_TREE_DISC]    = "CLOSE_AND_TREE_DISC";
        cmdNames[Commands::SMB_COM_TRANSACTION2]           = "TRANSACTION2";
        cmdNames[Commands::SMB_COM_TRANSACTION2_SECONDARY] = "TRANSACTION2_SECONDARY";
        cmdNames[Commands::SMB_COM_FIND_CLOSE2]            = "FIND_CLOSE2";
        cmdNames[Commands::SMB_COM_FIND_NOTIFY_CLOSE]      = "FIND_NOTIFY_CLOSE";
        cmdNames[Commands::SMB_COM_TREE_CONNECT]           = "TREE_CONNECT";
        cmdNames[Commands::SMB_COM_TREE_DISCONNECT]        = "TREE_DISCONNECT";
        cmdNames[Commands::SMB_COM_NEGOTIATE]              = "NEGOTIATE";
        cmdNames[Commands::SMB_COM_SESSION_SETUP_ANDX]     = "SESSION_SETUP_ANDX";
        cmdNames[Commands::SMB_COM_LOGOFF_ANDX]            = "LOGOFF_ANDX";
        cmdNames[Commands::SMB_COM_TREE_CONNECT_ANDX]      = "TREE_CONNECT_ANDX";
        cmdNames[Commands::SMB_COM_SECURITY_PACKAGE_ANDX]  = "SECURITY_PACKAGE_ANDX";
        cmdNames[Commands::SMB_COM_QUERY_INFORMATION_DISK] = "QUERY_INFORMATION_DISK";
        cmdNames[Commands::SMB_COM_SEARCH]                 = "SEARCH";
        cmdNames[Commands::SMB_COM_FIND]                   = "FIND";
        cmdNames[Commands::SMB_COM_FIND_UNIQUE]            = "FIND_UNIQUE";
        cmdNames[Commands::SMB_COM_FIND_CLOSE]             = "FIND_CLOSE";
        cmdNames[Commands::SMB_COM_NT_TRANSACT]            = "NT_TRANSACT";
        cmdNames[Commands::SMB_COM_NT_TRANSACT_SECONDARY]  = "NT_TRANSACT_SECONDARY";
        cmdNames[Commands::SMB_COM_NT_CREATE_ANDX]         = "NT_CREATE_ANDX";
        cmdNames[Commands::SMB_COM_NT_CANCEL]              = "NT_CANCEL";
        cmdNames[Commands::SMB_COM_NT_RENAME]              = "NT_RENAME";
        cmdNames[Commands::SMB_COM_OPEN_PRINT_FILE]        = "OPEN_PRINT_FILE";
        cmdNames[Commands::SMB_COM_WRITE_PRINT_FILE]       = "WRITE_PRINT_FILE";
        cmdNames[Commands::SMB_COM_CLOSE_PRINT_FILE]       = "CLOSE_PRINT_FILE";
        cmdNames[Commands::SMB_COM_GET_PRINT_QUEUE]        = "GET_PRINT_QUEUE";
        cmdNames[Commands::SMB_COM_READ_BULK]              = "READ_BULK";
        cmdNames[Commands::SMB_COM_WRITE_BULK]             = "WRITE_BULK";
        cmdNames[Commands::SMB_COM_WRITE_BULK_DATA]        = "WRITE_BULK_DATA";
        cmdNames[Commands::SMB_COM_INVALID]                = "INVALID";
        cmdNames[Commands::SMB_COM_NO_ANDX_COMMAND]        = "NO_ANDX_COMMAND";
    }
    return cmdNames[cmd_code];
}

static inline const std::string commandName(int cmd_code)
{
    return commandName(static_cast<Commands>(cmd_code));
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

    Latencies<T, Algorithm> latencies[static_cast<int>(Commands::SBM_COM_COUNT)];
};

template
<
    typename T,
    template <class> class Algorithm
>
class CIFSBreakdownAnalyzer : public IAnalyzer
{
    using Breakdown = BreakdownCounter<T, Algorithm>;
    using PerOpStat = std::map<SMBv1::Session, Breakdown>;
    using Pair = typename PerOpStat::value_type;
    using ProceduresCount = std::map<Commands, int>;
public:
    CIFSBreakdownAnalyzer(std::ostream& o = std::cout)
                          : procedures_total_count{0}
                          , out(o)
    {
    }

    virtual ~CIFSBreakdownAnalyzer() { }

    void echoRequest(const SMBv1::EchoRequestCommand* cmd, const SMBv1::EchoRequestArgumentType&, const SMBv1::EchoRequestResultType&) override final
    {
        account(cmd, Commands::SMB_COM_ECHO);
    }

    void closeFile(const SMBv1::CloseFileCommand *cmd, const SMBv1::CloseFileArgumentType &, const SMBv1::CloseFileResultType &) override final
    {
        account(cmd, Commands::SMB_COM_CLOSE);
    }

    virtual void flush_statistics()
    {
         out << "###  Breakdown analyzer  ###"
             << std::endl
             << "CIFS total procedures: "
             << procedures_total_count
             << ". Per procedure:"
             << std::endl;

         for (const auto& procedure: procedures_count)
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
             out << (procedures_total_count ? ((1.0 * procedure.second / procedures_total_count) * 100.0) : 0);
             out.setf(std::ios::fixed | std::ios::scientific , std::ios::floatfield);
             out << '%' << std::endl;
         };

         if (per_procedure_statistic.size())  // is not empty?
         {
            out << "Per connection info: " << std::endl;

            std::stringstream session;

             for(auto& it : per_procedure_statistic)
             {
                 const Breakdown& current = it.second;
                 uint64_t s_total_proc = current.getTotalCount();

                 session.str("");
                 //print_session(session, it.first);//FIXME: print session
                 print_per_session(current, session.str(), s_total_proc);
                 std::ofstream file(("breakdown_" + session.str() + ".dat").c_str(), std::ios::out | std::ios::trunc);
                 store_per_session(file, current, session.str(), s_total_proc);
             }
         }
    }

    void store_per_session(std::ostream& file,
                           const Breakdown& breakdown,
                           const std::string& session,
                           uint64_t s_total_proc) const
    {
        file << "Session: " << session << std::endl;

        unsigned int op_count  = static_cast<unsigned int>(Commands::SBM_COM_COUNT);

        for(unsigned i = 0; i < op_count; ++i)
        {
            file << commandName(i);
            file << ' ' << breakdown[i].get_count() << ' ';
            file << (s_total_proc ? (((T)(breakdown[i].get_count()) / s_total_proc) * 100) : 0);
            file << ' ' << to_sec<T>(breakdown[i].get_min())
                 << ' ' << to_sec<T>(breakdown[i].get_max())
                 << ' ' << breakdown[i].get_avg()
                 << ' ' << breakdown[i].get_st_dev()
                 << std::endl;
        }
    }

    void print_per_session(const Breakdown& breakdown,
                           const std::string& session,
                           uint64_t s_total_proc) const
    {
        out << "Session: " << session << std::endl;

        unsigned int op_count  = static_cast<unsigned int>(Commands::SBM_COM_COUNT);

        out << "Total procedures: " << s_total_proc
            << ". Per procedure:"   << std::endl;
        for(unsigned i = 0; i < op_count; ++i)
        {
            out.width(22);
                out << std::left
                    << commandName(i);
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
                << (s_total_proc ? (((T)(breakdown[i].get_count()) / s_total_proc) * 100) : 0);
            out << "%) Min: ";
            out.precision(3);
            out << std::fixed
                << to_sec<T>(breakdown[i].get_min())
                << " Max: "
                << std::fixed
                << to_sec<T>(breakdown[i].get_max())
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

private:
    void account(const SMBv1::EchoRequestCommand* proc, Commands cmd_code)
    {
        typename PerOpStat::iterator i;
        timeval latency{0,0};

        // diff between 'reply' and 'call' timestamps
        //timersub(0, 0, &latency);//FIXME: Latency?

        ++procedures_total_count;
        ++procedures_count[cmd_code];

        i = per_procedure_statistic.find(proc->session());
        if(i == per_procedure_statistic.end())
        {
            auto session_res = per_procedure_statistic.emplace(proc->session(), Breakdown{});
            if(session_res.second == false) return;
            i = session_res.first;
        }

        (i->second)[static_cast<int>(cmd_code)].add(latency);

    }
    uint64_t procedures_total_count;
    ProceduresCount procedures_count;
    PerOpStat per_procedure_statistic;

    std::ostream& out;
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
        return new CIFSBreakdownAnalyzer<long double, OnlineVariance>();
    else
        do
        {
            switch(getsubopt((char**)&optarg, (char**)token, &value))
            {
                case ACC:
                    return new CIFSBreakdownAnalyzer<long double, TwoPassVariance>();
                    break;

                case MEM:
                    return new CIFSBreakdownAnalyzer<long double, OnlineVariance>();
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
