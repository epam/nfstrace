//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Test for NST:auxiliary::Queue<T>
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <cassert>
#include <iostream>

#include "../../src/auxiliary/queue.h"
//------------------------------------------------------------------------------
struct Data
{
    int value;
};

typedef NST::auxiliary::Queue<Data> Queue;
//------------------------------------------------------------------------------
void push(Queue& queue, unsigned int n)
{
    std::cout << "fill elements:   ";
    for(unsigned int i=0; i<n; i++)    // try to push 42 elements
    {
        Data* data = queue.allocate();  // allocate element of data
        if(data == NULL)
        {
            std::cout << "\nqueue has reached the limit of elements";
            break;
        }
        data->value = i;    // fill data
        std::cout << data->value << " ";
        queue.push(data);   // push element to queue
    }
    std::cout << std::endl;
}

void pop_print(Queue& queue)
{
    Queue::List list(queue); // take out list of all queued elements
    assert(queue.pop_list() == false); // empty queue
    std::cout << "queued elements: ";
    while(list) // loop over all taken elements
    {
        const Data& i = list.data();   // get first element
        std::cout << i.value << " ";
        list.free_current();    // free unused element
    }
    std::cout << std::endl;
}

int main(int argc, char **argv)
{
    Queue queue(10, 2); // two blocks of 10 elements

    assert(queue.pop_list() == false); // empty queue

    push(queue, 40);
    {
        Queue::List list(queue);
        assert(queue.pop_list() == false); // empty queue
    }

    push(queue, 40);

    pop_print(queue);
    assert(queue.pop_list() == false); // empty queue

    return 0;
}
//------------------------------------------------------------------------------
