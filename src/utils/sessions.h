//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structs for sessions.
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
#ifndef SESSIONS_H
#define SESSIONS_H
//------------------------------------------------------------------------------
#include <cstddef>
#include <cstdint>
#include <ostream>

#include "api/session.h"
//------------------------------------------------------------------------------
#define NST_PUBLIC __attribute__ ((visibility("default")))
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

using Session = NST::API::Session;

// Network layer session
struct NetworkSession : public Session
{
public:
    NetworkSession()
    : application {nullptr}
    , direction   {Direction::Unknown}
    {
    }

    void*     application;  // pointer to application protocol implementation
    Direction direction;
};


// Application layer session
struct ApplicationSession : public Session
{
public:
    ApplicationSession(const NetworkSession& s, Direction from_client);

    const std::string& str() const { return session_str; }
private:
    std::string session_str;
};

extern "C"
NST_PUBLIC
void print_session(std::ostream& out, const Session& session);

std::ostream& operator<<(std::ostream& out, const Session& session);

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//SESSIONS_H
//------------------------------------------------------------------------------
