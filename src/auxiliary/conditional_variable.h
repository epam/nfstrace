//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Wrapper arround conditional variable.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CONDITIONAL_VARIABLE_H
#define CONDITIONAL_VARIABLE_H
//------------------------------------------------------------------------------
#include <pthread.h>

#include "exception.h"
#include "mutex.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class ConditionalVariable
{
public:
    inline ConditionalVariable()
    {
        pthread_cond_init(&cond, NULL);
    }
    inline ~ConditionalVariable()
    {
        pthread_cond_destroy(&cond);
    }

    inline void wait(Mutex& mutex)
    {
        pthread_cond_wait(&cond, &mutex.mutex);
    }

    inline void signal()
    {
        pthread_cond_signal(&cond);
    }
private:
    pthread_cond_t cond;
};

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//CONDITIONAL_VARIABLE_H
//------------------------------------------------------------------------------
