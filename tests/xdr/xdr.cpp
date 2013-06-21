#include <iostream>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "../../src/filter/nfs/nfs_struct.h"
#include "../../src/filter/xdr/xdr_reader.h"

using namespace NST::filter::NFS3;
using namespace NST::filter::XDR;

void check_int()
{
    uint32_t val;
    uchar_t data[4] = {0, 128, 0, 0}; // 0x8000 (32768)
    XDRReader reader(data, sizeof(data));
    reader >> val;
    assert(val == 0x800000); // wrong uint32_t convertion
}

void check_OpaqueDyn()
{
    uchar_t data[12] = {0, 0, 0, 6, 0, 0, 0, 0, 1, 2, 1, 2}; // 0x6 0x102 0x102
    XDRReader reader(data, sizeof(data));
    OpaqueDyn opaque;
    reader >> opaque;
    assert(opaque.data.size() == 6);
    assert(opaque.data[4] == 1 && opaque.data[5] == 2);
}

void check_long_long()
{
    uint64_t val;
    const uint64_t TEST = 0xBADC00FE00000000;
    uchar_t *data =(uchar_t*)&TEST; // 0x08000000000000
    XDRReader reader(data, 8);
    reader >> val;
    assert(val == 0xFE00DCBA); // wrong uint64_t convertion
}

void check_OpaqueStat()
{
    uchar_t data[9U] = {0, 0, 0, 0, 1, 2, 1, 2, 0}; // 0x6 0x102 0x102
    XDRReader reader(data, sizeof(data));
    OpaqueStat<6> opaque;
    reader >> opaque;
    assert(opaque.data[4] == 1 && opaque.data[5] == 2);
}

void check_ReadArgs()
{
    uchar_t data[24] = {0, 0, 0, 6,             // file handler size == 
                    0, 0, 0, 0, 1, 2, 0, 0,  // file handler value (last 2 bytes for align) == 0x01 02
                    0, 0, 0, 0, 0, 0, 0, 0,  // offset == 9
                    0, 0, 1, 0};             // count == 256
    XDRReader reader(data, sizeof(data));
    ReadArgs read_args;
    reader >> read_args;
    assert(read_args.file.data.size() == 6);
    assert(read_args.file.data[4] == 1 && read_args.file.data[5] == 2);
    assert(read_args.offset == 0);
    assert(read_args.count == 256);
}

void check_WriteArgs()
{
    uchar_t data[36] = {0, 0, 0, 6,             // file handler size == 
                    0, 0, 0, 0, 1, 2, 0, 0,  // file handler value (last 2 bytes for align) == 0x01 02
                    0, 0, 0, 0, 0, 0, 0, 0,  // offset == 9
                    0, 0, 1, 0,              // count == 256
                    0, 0, 0, 0,              // enum stable == UNSTABLE == 0
                    0, 0, 0, 4,              // data size = 8
                    0x10, 0x12, 0xFF, 0x01}; // data value = 0x10 12 FF 01
    XDRReader reader(data, sizeof(data));
    WriteArgs write_args;
    reader >> write_args;
    assert(write_args.file.data.size() == 6);
    assert(write_args.file.data[4] == 1 && write_args.file.data[5] == 2);
    assert(write_args.offset == 0);
    assert(write_args.count == 256);
    assert(write_args.stable == 0);
    assert(write_args.data.data.size() == 4);
    assert(write_args.data.data[0] == 0x10 && write_args.data.data[1] == 0x12 && write_args.data.data[2] == 0xFF && write_args.data.data[3] == 0x01);
}

int main(int argc, char** argv)
{
    check_int();
    check_OpaqueDyn();
    check_OpaqueStat();
    check_long_long();
    check_ReadArgs();
    check_WriteArgs();
    std::cout << "All tests passed" << std::endl;
    return 0;
}
