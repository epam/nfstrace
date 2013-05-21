#!/usr/bin/python

import sys
import subprocess as subprc

# Python 2.6 hasn't check_output method
if "check_output" not in dir( subprc ): # duck punch it in!
    def f(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be overridden.')
        process = subprc.Popen(stdout=subprc.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise CalledProcessError(retcode, cmd)
        return output
    subprc.check_output = f

def main (argv):
    if len(argv) != 2:
        print "load_tests [numb_of_oper] [mnt_dir]"
        sys.exit(2)
    try:
        # should be dir with access for user to changes
        noop = int(argv[0])
        subprc.check_output("cat /etc/services", shell=True)
        # mnt_dir is argv[1]
        for i in range(0, noop):
            cd_op = "cd " + argv[1]
            subprc.check_output(cd_op + "&& ls", shell=True)
            subprc.check_output(cd_op + "&& mkdir hello", shell=True)
            cd_op += "/hello &&"
            subprc.check_output(cd_op + "touch temp.file && echo \
                    'hello there' > temp.file", shell=True)
            subprc.check_output(cd_op + "touch temp2.file && ln -s\
                    ./temp2.file hello", shell=True)
            subprc.check_output(cd_op + "rm temp2.file && rm hello", shell=True)
            subprc.check_output(cd_op + "cat temp.file && mv -i\
                    temp.file temp", shell=True)
            subprc.check_output(cd_op + "cd .. && rm -rf hello", shell=True)
    except ValueError:
        print "data error - load_tests [numb_of_oper] [mnt_dir]"

if __name__ == "__main__":
    main(sys.argv[1:])
