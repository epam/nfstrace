//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structs for sessions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SESSIONS_H
#define SESSIONS_H
//------------------------------------------------------------------------------
#include <cstddef>
#include <cstdint>
#include <ostream>

#include "api/session.h"
//------------------------------------------------------------------------------
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
struct ApplicationsSession : public Session
{
public:
    ApplicationsSession(const NetworkSession& s, Direction from_client);

    const std::string& str() const { return session_str; }
private:
    std::string session_str;
};

std::ostream& operator<<(std::ostream& out, const Session& session);

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//SESSIONS_H
//------------------------------------------------------------------------------
