//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Indent output of std::ostream. Work on each character, it is slow operation.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef INDENT_H
#define INDENT_H
//------------------------------------------------------------------------------
#include <iostream>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{
namespace print
{

class Indent : public std::streambuf
{
public:
    explicit Indent(std::ostream& destination, int indent = 4)
        : owner(&destination)
        , dst(destination.rdbuf())
        , at_start(true)
        , indent(indent, ' ')
    {
        owner->rdbuf(this);
    }
    virtual ~Indent()
    {
        owner->rdbuf( dst );
    }

protected:
    virtual int overflow(int ch)
    {
        if( at_start && ch != '\n' )
        {
            dst->sputn(indent.data(), indent.size());
        }
        at_start = (ch == '\n');
        return dst->sputc(ch);
    }

private:
    Indent(const Indent&);            // undefined
    Indent& operator=(const Indent&); // undefined

    std::ostream*       owner;
    std::streambuf*     dst;
    bool                at_start;
    std::string         indent;
};

} // namespace print
} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//INDENT_H
//------------------------------------------------------------------------------
