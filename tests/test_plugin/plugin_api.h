//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin-API describe interface expected by nfstrace.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_API_H
#define PLUGIN_API_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

class BaseAnalyzer
{
    public:
        BaseAnalyzer() {}
        virtual ~BaseAnalyzer() {}

        virtual void analyse(int) = 0;          // Data processing
        virtual const char* name() const = 0;   // Return analyzer name
        virtual void stage() = 0;               // Signal about new processing stage
        virtual void terminate(int msec) = 0;   // Signal about program completion in [msec] milliseconds

    private:
        BaseAnalyzer(const BaseAnalyzer&);
        void operator=(const BaseAnalyzer&);
};

BaseAnalyzer* create(const char* args);
void destroy(BaseAnalyzer* handle);

}

//------------------------------------------------------------------------------
#endif//PLUGIN_API_H
//------------------------------------------------------------------------------
