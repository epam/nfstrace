//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Must be replaced with std::unique_ptr after switch to C++11
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef UNIQUE_PTR_H
#define UNIQUE_PTR_H
//------------------------------------------------------------------------------
#include <cstddef> // NULL
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

template <typename T> class DefaultDelete;

template
<
    typename T,                     // type of the managed object
    typename D = DefaultDelete<T>   // type of the callable object used for deleting instance of T
>
class UniquePtr : private D // inheritance for object size optimization in case of D is DefaultDelete<T>
{
public:
    inline UniquePtr() : D(), pointer(NULL)
    {
    }
    inline explicit UniquePtr(T* p) : D(), pointer(p)
    {
    }
    inline explicit UniquePtr(T*const p, const D& deleter) : D(deleter), pointer(p)
    {
    }
    inline UniquePtr(const UniquePtr& that) // move
    {
        static_cast<D&>(*this) = static_cast<const D&>(that); // use slicing for copying deleter
        pointer = that.pointer;
        that.pointer = NULL;    // reset mutable that.pointer
    }
    inline void operator=(const UniquePtr& that) // move
    {
        if(this != &that) // check self assignment
        {
            D::operator()(pointer);                               // delete current managed object
            static_cast<D&>(*this) = static_cast<const D&>(that); // use slicing for copying deleter
            pointer = that.pointer;
            that.pointer = NULL;    // reset mutable that.pointer
        }
    }
    inline ~UniquePtr()
    {
        D::operator()(pointer);
    }

    inline void reset(T*const p, const D& deleter=D())
    {
        static_cast<D&>(*this) = deleter; // use slicing for copying deleter
        pointer = p;
    }

    inline  operator bool() const { return  pointer; } // is empty?
    inline T&  operator *() const { return *pointer; }
    inline T* operator ->() const { return  pointer; }
    inline T*         get() const { return  pointer; }

private:
    // mutable is required for move-assignment while pushing const UniquePtr& to std::vector via push_back() method
    mutable T* pointer;
};

template<typename T, typename D>
class UniquePtr<T[], D>
{
    // specialization for array objects with a compile time length isn't supported in this implementation
};

template <typename T> class DefaultDelete
{
    friend class UniquePtr<T>;

    inline void operator()(T* const pointer) const
    {
        if(pointer) // it is an optimization, believe me
        {
            delete pointer;
        }
    }
};

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//UNIQUE_PTR_H
//------------------------------------------------------------------------------
