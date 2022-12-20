#!/bin/bash
#
# reset-trace - reset state of tracing, disabling all tracing.
#               Written for Linux.
#
# If a bcc tool crashed and you suspect tracing is partially enabled, you
# can use this tool to reset the state of tracing, disabling anything still
# enabled. Only use this tool in the case of error, and, consider filing a
# bcc ticket so we can fix the error.
#
# bcc-used tracing facilities are reset. Other tracing facilities (ftrace) are
# checked, and if not in an expected state, a note is printed. All tracing
# files can be reset with -F for force, but this will interfere with any other
# running tracing sessions (eg, ftrace).
#
# USAGE: ./reset-trace [-Fhqv]
#
# REQUIREMENTS: debugfs mounted on /sys/kernel/debug
#
# COPYRIGHT: Copyright (c) 2016 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Jul-2014	Brendan Gregg	Created this.
# 18-Oct-2016      "      "     Updated for bcc use.

tracing=/sys/kernel/debug/tracing
opt_force=0; opt_verbose=0; opt_quiet=0

function usage {
	cat <<-END >&2
	USAGE: reset-trace [-Fhqv]
	                 -F             # force: reset all tracing files
	                 -v             # verbose: print details while working
	                 -h             # this usage message
	                 -q             # quiet: no output
	  eg,
	       reset-trace              # disable semi-enabled tracing
END
	exit
}

function die {
	echo >&2 "$@"
	exit 1
}

function vecho {
	(( ! opt_verbose )) && return
	echo "$@"
}

function writefile {
	file=$1
	write=$2
	if [[ ! -w $file ]]; then
		echo >&2 "WARNING: file $file not writable/exists. Skipping."
		return
	fi

	vecho "Checking $PWD/$file"
        contents=$(grep -v '^#' $file)
	if [[ "$contents" != "$expected" ]]; then
		(( ! opt_quiet )) && echo "Needed to reset $PWD/$file"
		vecho "$file, before (line enumerated):"
		(( opt_verbose )) && cat -nv $file
		cmd="echo $write > $file"
		if ! eval "$cmd"; then
			echo >&2 "WARNING: command failed \"$cmd\"." \
			    "bcc still running? Continuing."
		fi
		vecho "$file, after (line enumerated):"
		(( opt_verbose )) && cat -nv $file
		vecho
	fi
}

# only write when force is used