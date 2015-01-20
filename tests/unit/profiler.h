#ifndef PROFILER_H
#define PROFILER_H

#include <vector>
#include <algorithm>
#include <iostream>

#include <sys/time.h>

class Profiler {
    const char* name = "";
    struct timespec tm1;
public:

    class Local
    {
        const char* name = "";
    public:
        std::vector<int> values;
        Local(const char* name)
            : name(name)
        {
            values.reserve(50 * 1000 * 1000);
        }

        ~Local()
        {
            int sum = std::accumulate(values.begin(), values.end(), 0, std::plus<int>());
            std::cout << name << ": sum=" << sum << ", count=" << values.size() << ", avg=" << sum/values.size() << " nanosecs" << std::endl;
        }
    };

    Profiler(const char* name)
        : name(name)
    {
        clock_gettime(CLOCK_REALTIME, &tm1);
    }

    ~Profiler()
    {
        static Local local(name);
        struct timespec tm2;
        clock_gettime(CLOCK_REALTIME, &tm2);
        local.values.push_back(tm2.tv_nsec - tm1.tv_nsec);
    }
};

#endif // PROFILER_H

