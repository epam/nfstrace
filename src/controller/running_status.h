//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Container for storing threads' exceptions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RUNNING_STATUS_H
#define RUNNING_STATUS_H
//------------------------------------------------------------------------------
#include <condition_variable>
#include <exception>
#include <iostream>
#include <list>
#include <mutex>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class RunningStatus
{
public:
    RunningStatus() = default;
    RunningStatus(const RunningStatus&)            = delete;
    RunningStatus& operator=(const RunningStatus&) = delete;

    template <typename ExceptionType>
    inline void push(const ExceptionType& e)
    {
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
        if(e != nullptr)
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
                    catch (const std::exception& e)
                    {
                        out << '\t' << e.what() << std::endl;
                    }
                }
            }
    }

private:
    inline void push(std::exception_ptr e)
    {
        std::unique_lock<std::mutex> lock(mutex);
            fifo.emplace_front(e);
            condition.notify_one();
    }

    std::list<std::exception_ptr> fifo;
    std::mutex mutex;
    std::condition_variable condition;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //RUNNING_STATUS_H
//------------------------------------------------------------------------------
