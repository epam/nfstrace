//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Test for NST:auxiliary::Queue<T>
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include "../../src/auxiliary/queue.h"
//------------------------------------------------------------------------------
struct Data
{
    int value;
};

typedef NST::auxiliary::Queue<Data> Queue;
//------------------------------------------------------------------------------
int main(int argc, char **argv)
{
    Queue queue(10, 2); // two blocks of 10 elements

    // FILL QUEUE BY ELEMENTS
    std::cout << "fill elements:   ";
    for(unsigned int i=0; i<42; i++)    // try to push 42 elements
    {
        Data* data = queue.allocate();  // allocate element of data
        if(data == NULL)
        {
            std::cout << "\nqueue is reached the limit of elements";
            break;
        }
        data->value = i;    // fill data
        std::cout << data->value << " ";
        queue.push(data);   // push element to queue
    }

    // READ ELEMENTS
    std::cout << "\nqueued elements: ";
    Queue::List list = queue.pop_list(); // take out list of all queued elements
    while(list) // loop over all elements
    {
        Data* i = list.get();           // get first element
        std::cout << i->value << " ";
        queue.deallocate(i);            // free unused element
    }
    std::cout << std::endl;

    return 0;
}
//------------------------------------------------------------------------------
