#!/usr/bin/env bash
#------------------------------------------------------------------------------
#    Copyright (c) 2013 EPAM Systems
#------------------------------------------------------------------------------
#
#    This file is part of Nfstrace.
#
#    Nfstrace is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 2 of the License.
#
#    Nfstrace is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
#------------------------------------------------------------------------------

usage()
{
cat << EOF
Graph images by data provided by analyzers.
usage: analyzers/nst.sh -a analyzers/breakdown.plt -d . -p "breakdown*.dat"

OPTIONS:
   -h      Show this message.
   -a      Set path to the analyzer.
   -d      Directory contained i_files-files. Pattern: <analyzer>(.)*.dat
   -f      Use specific file as i_files-file.
   -p      Pattern used for file search.
   -r      Recursive search.
   -v      Verbose.

Known issues:
    Supported just one analyzer ('-a' option) at a time.
EOF
}

o_ext=.png

analyzer=
directories=
i_files=

while getopts “ha:d:f:p:rv” OPTION
do
    case $OPTION in
        h)
            usage
            exit
            ;;
        a)
            if [[ ! -z "$analyzer" ]] ; then
                usage
                exit 1
            fi

            analyzer="$OPTARG"
            ;;
        d)
            directories+="$OPTARG"
            ;;
        f)
            i_files+="$OPTARG"$'\n'
            ;;
        p)
            pattern+="$OPTARG"
            ;;
        r)
            recursive=1
            ;;
        v)
            verbose=1
            ;;
        ?)
            usage
            exit
            ;;
    esac
done

for directory in "$directories" ; do
    i_files+=$(ls "$directory/$pattern")
done

if [[ -z "$analyzer" ]] || [[ -z "$i_files" ]] ; then
    usage
    exit 1
fi

OIFS="${IFS}"
IFS=$'\n'
for i_file in "$i_files" ; do
    o_file="${i_file/%$i_ext/$o_ext}"
    gnuplot -e "i_file='$i_file';o_file='$o_file'" "$analyzer$e_ext" &>/dev/null
    result=$?
    if [[ ! -z "$verbose" ]] ; then
        echo "gnuplot -e \"i_file='$i_file';o_file='$o_file'\" $analyzer$e_ext"
        if [[ ! $result == 0 ]] ; then
            echo "fail during $i_file processing (return: $result)" 1>&2
            exit 1
        fi
    fi
done
IFS="${OIFS}"
