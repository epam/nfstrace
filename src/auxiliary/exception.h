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
    explicit Exception(const std::string& what_arg)
        : message(what_arg) { }

    virtual ~Exception() throw() { }

    virtual const char* what() const throw()
    {
        return message.c_str();
    }

private:
    std::string message;
};

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//EXCEPTION_H
//------------------------------------------------------------------------------
