#!/bin/bash -e

if test $# -eq 0
then
	echo usage: $0 shellname '[shellname ...]' 1>&2
	exit 1
fi

file=/etc/shells
# I want this to be GUARANTEED to be on the same filesystem as $file
tmpfile=${file}.tmp
otmpfile=${file}.tmp2

set -o noclobber

trap "rm -f $tmpfile $otmpfile" EXIT
        
if ! cat $file > $tmpfile
then
        cat 1>&2 <<EOF
Either another instance of $0 is running, or it was previously interrupted.
Please examine ${tmpfile} to see if it should be moved onto ${file}.
EOF
        exit 1
fi

# this is supposed to be reliable, not pretty
for i
do
	grep -v "^${i}$" $tmpfile > $otmpfile || true
	mv $otmpfile $tmpfile
done

chmod --reference=$file $tmpfile
chown --reference=$file $tmpfile

mv $tmpfile $file

trap "" EXIT
exit 0
