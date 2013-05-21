//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: A template for headers.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef TEMPLATE_H
#define TEMPLATE_H
//------------------------------------------------------------------------------
#include <string>
//------------------------------------------------------------------------------
#define MY_MIN(a,b) (((a) < (b)) ? (a) : (b))
//------------------------------------------------------------------------------
namespace hello
{

class SayHello
{
public:
    SayHello();
    ~SayHello();

    SayHello(const SayHello&);              // undefined
    SayHello& operator=(const SayHello&);   // undefined

    // small functions may be implemented in-place
    inline const std::string& say()const { return text; }

    unsigned int get()const;
    void set(unsigned int v);

private:
    std::string text;
    unsigned int value; // just a value for get/set methods

    static const unsigned int BAD_COFFEE;
};

} // namespace hello
//------------------------------------------------------------------------------
#endif//TEMPLATE_H
//------------------------------------------------------------------------------
