//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Struct represented tcp session.
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

#include "api/session_type.h"

std::ostream& operator<<(std::ostream& out, const Session& session);

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif //SESSION_H
//------------------------------------------------------------------------------
