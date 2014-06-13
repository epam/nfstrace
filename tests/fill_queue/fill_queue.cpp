//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Test for NST:utils::Queue<T>
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#include <cassert>
#include <iostream>

#include "utils/queue.h"
//------------------------------------------------------------------------------
struct Data
{
    int value;
};

typedef NST::utils::Queue<Data> Queue;
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

int main()
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
