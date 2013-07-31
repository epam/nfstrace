#!/usr/bin/python

import sys
import os
import signal
import subprocess as subprc

def system(*popenargs, **kwargs):
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    process = subprc.Popen(stdout=subprc.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise RuntimeError(retcode, cmd)
    return output

def main (argv):
    # should be dir with access for user to changes
    try:
        for i in range(0, int(argv[1])):
            cd_op = "cd " + argv[3]
            system(cd_op + "&& rm -rf hello", shell=True)
            system(cd_op + "&& ls", shell=True)
            system(cd_op + "&& mkdir hello", shell=True)
            system(cd_op + "&& chmod 777 hello", shell=True)
            cd_op += "/hello &&"
            system(cd_op + "dd if=/dev/zero of=temp.file bs=1M count=" + argv[2], shell=True)
            system(cd_op + "cd .. && rm -rf hello", shell=True)
    except:
        os.killpg(0, signal.SIGKILL)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print sys.argv[0] + " [number of iterations] [size in Mb] [path to directory]"
        sys.exit(2)
    main(sys.argv)
