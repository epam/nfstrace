//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: This test created as example of the use thread safe queue.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include <unistd.h>

#include "auxiliary/fifo.h"
#include "auxiliary/spinlock.h"
#include "../src/auxiliary/thread_std.h"

using NST::auxiliary::FIFO;
using NST::auxiliary::ThreadStd;
using NST::auxiliary::Spinlock;

FIFO<int> g_fifo;
Spinlock print_lock;

void print(int thread, const char* action, int value)
{
    Spinlock::Lock lock(print_lock);
    std::cout << thread << " " << action << " " << value << std::endl;
}

class Writer
{
public:
    Writer(int _id, int _repeat) : repeat(_repeat), id(_id) {}
    ~Writer() {}
    Writer(const Writer&);
    Writer& operator=(const Writer&);
    static void* run(void *data)
    {
        Writer& writer = *(Writer*)data;
        for(int i = 0; i < writer.repeat; ++i)
        {
            g_fifo.push(i);
            print(writer.id, "write", i);
        }
        return NULL;
    }
    void* get_runarg() const
    {
        return (void*)this;
    }
private:
    int id;
    int repeat;
};

class Reader
{
public:
    Reader(int _id, int _repeat) : repeat(_repeat), id(_id) 
    {
    }
    ~Reader() {}
    Reader(const Reader&);
    Reader& operator=(const Reader&);
    static void* run(void *data)
    {
        Reader& reader = *(Reader*)data;
        int value = 0;
        for(int i = 0; i < reader.repeat; ++i)
        {                             
            while(g_fifo.pop(value) == FIFO<int>::EAGAIN); // Stupid behaviour, just for test purpose
            print(reader.id, "read", value);
        }
        return NULL;
    }
    void* get_runarg() const
    {
        return (void*)this;
    }
private:
    int id;
    int repeat;
};

int main(int argc, char** argv)
{
    /*
    Writer writer1(1,1);
    Writer writer2(2,2);
    Writer writer3(3,1);
    Writer writer4(4,2);
    Writer writer5(5,1);
    
    ThreadStd<Writer> thread1(writer1); 
    ThreadStd<Writer> thread2(writer2); 
    ThreadStd<Writer> thread3(writer3); 

    Reader reader0(0,10);
    ThreadStd<Reader> thread0(reader0); 
    
    ThreadStd<Writer> thread4(writer4); 
    ThreadStd<Writer> thread5(writer5);
    */ 

    Reader reader0(0,10);
    ThreadStd<Reader> thread0(reader0); 

    Writer writer1(1,1);
    ThreadStd<Writer> thread1(writer1); 
    return 0;
}
