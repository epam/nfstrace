//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Struct represents application layer session.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef APPLICATION_SESSION_H
#define APPLICATION_SESSION_H
//------------------------------------------------------------------------------
#include "utils/session.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

struct ApplicationSession : public utils::Session
{
public:
    ApplicationSession()
    : application {nullptr}
    {
    }

    void* application; // pointer to implementation
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif //APPLICATION_SESSION_H
//------------------------------------------------------------------------------
