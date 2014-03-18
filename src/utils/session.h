//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structs represents session.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SESSION_H
#define SESSION_H
//------------------------------------------------------------------------------
#include <cstddef>
#include <cstdint>
#include <ostream>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

#include "api/session_type.h"   // definition of utils::Session

// Network layer session
struct NetworkSession : public utils::Session
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


// Application layer session representation
struct ApplicationsSession : public utils::Session
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
#endif//SESSION_H
//------------------------------------------------------------------------------
