//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Container for storing threads' exceptions.
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
#ifndef RUNNING_STATUS_H
#define RUNNING_STATUS_H
//------------------------------------------------------------------------------
#include <exception>
#include <iostream>
#include <list>
#include <mutex>
#include <condition_variable>
#include <stdexcept>
#include <type_traits>

#include "utils/noncopyable.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{
class ProcessingDone final : public std::runtime_error
{
public:
    explicit ProcessingDone(const std::string& in)
        : std::runtime_error{in}
    {
    }
};

class RunningStatus final : utils::noncopyable
{
public:
    RunningStatus() = default;

    template <typename ExceptionType>
    inline void push(const ExceptionType& e)
    {
        static_assert(std::is_base_of<std::exception, ExceptionType>::value,
                      "The ExceptionType should be inherited from std::exception");
        push(std::make_exception_ptr(e));
    }

    inline void push_current_exception()
    {
        push(std::current_exception());
    }

    std::exception_ptr wait_exception()
    {
        std::unique_lock<std::mutex> lock(mutex);
        while(fifo.empty())
        {
            condition.wait(lock);
        }
        std::exception_ptr e = fifo.front();
        fifo.pop_front();
        return e;
    }

    void wait_and_rethrow_exception()
    {
        auto e = wait_exception();
        std::rethrow_exception(e);
    }

    void print(std::ostream& out)
    {
        std::unique_lock<std::mutex> lock(mutex);
        if(!fifo.empty())
        {
            out << "list of unhandled exceptions:" << std::endl;
            for(auto& e : fifo)
            {
                try
                {
                    std::rethrow_exception(e);
                }
                catch(const std::exception& e)
                {
                    out << '\t' << e.what() << std::endl;
                }
                catch(...)
                {
                    out << '\t' << "Unknown exception" << std::endl;
                }
            }
        }
    }

private:
    inline void push(std::exception_ptr e)
    {
        if(e == nullptr) return;
        std::unique_lock<std::mutex> lock(mutex);
        fifo.emplace_front(e);
        condition.notify_one();
    }

    std::list<std::exception_ptr> fifo;
    std::mutex                    mutex;
    std::condition_variable       condition;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif // RUNNING_STATUS_H
//------------------------------------------------------------------------------
