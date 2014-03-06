//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Struct represents network session.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SESSION_H
#define SESSION_H
//------------------------------------------------------------------------------
#include <ostream>

#include <stddef.h>
#include <stdint.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

#include "api/session_type.h"   // definition of utils::Session

// application layer session
struct AppSession : public utils::Session
{
public:
    AppSession()
    : impl      {nullptr}
    , direction {Direction::Uninialized}
    {
    }

    void*     impl;  // pointer to application protocol implementation
    Direction direction;
};

std::ostream& operator<<(std::ostream& out, const Session& session);

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif //SESSION_H
//------------------------------------------------------------------------------
