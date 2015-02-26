
#ifndef PROTOCOLS_H
#define PROTOCOLS_H
#include <cstdlib>
#include <string>


#include <api/plugin_api.h> // include plugin development definitions

class AbstractProtocol
{
public:
    AbstractProtocol() = delete;
    AbstractProtocol(const char*, std::size_t);
    ~AbstractProtocol();
    virtual const char* printProcedure(std::size_t);
    unsigned int getAmount();
    std::string getProtocolName();
private:
    std::string name;
    std::size_t amount;
};

class NFSv3Protocol : public AbstractProtocol
{
public:
    NFSv3Protocol();
    ~NFSv3Protocol();
    virtual const char* printProcedure(std::size_t);
};

class NFSv4Protocol : public AbstractProtocol
{
public:
    NFSv4Protocol();
    ~NFSv4Protocol();
    virtual const char* printProcedure(std::size_t);
};

class NFSv41Protocol : public AbstractProtocol
{
public:
    NFSv41Protocol();
    ~NFSv41Protocol();
    virtual const char* printProcedure(std::size_t);
};

class CIFSv1Protocol : public AbstractProtocol
{
public:
    CIFSv1Protocol();
    ~CIFSv1Protocol();
    virtual const char* printProcedure(std::size_t);
};

class CIFSv2Protocol : public AbstractProtocol
{
public:
    CIFSv2Protocol();
    ~CIFSv2Protocol();
    virtual const char* printProcedure(std::size_t);
};
#endif // PROTOCOLS_H
