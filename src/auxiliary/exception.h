//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Base exception for NST
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef EXCEPTION_H
#define EXCEPTION_H
//------------------------------------------------------------------------------
#include <stdexcept>
#include <string>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class Exception : public std::exception
{
public:
    Exception(const std::string& msg)  : message(msg)      { }
    Exception(const std::exception& e) : message(e.what()) { }
    Exception(const Exception& e)      : message(e.what()) { }

    virtual ~Exception() throw() { }

    virtual const char*               what() const throw() { return message.c_str(); }
    virtual const Exception* dynamic_clone() const { return new Exception(*this); }
    virtual void             dynamic_throw() const { throw *this; }

private:
    std::string message;
};

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//EXCEPTION_H
//------------------------------------------------------------------------------
