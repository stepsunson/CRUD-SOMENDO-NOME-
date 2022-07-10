#!/bin/bash
# Copyright (c) GitHub, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

set -xe
cd "src/lua"

function fail {
    echo "test failed: $1" >&2
    exit 1
}

if [[ ! -x bcc-lua ]]; then
    echo "bcc-lua not built --- skipping"
    exit 0
fi

LIBRARY=$(ldd bcc-lua | grep luajit)
if [ $? -ne 0 -o -z "$LIBRARY" ] ; then
    fail "bcc-lua depends on libluajit"
fi

rm -f probe.lua
echo "return function(BPF) print(\"Hello world\") end" > probe.lua

PROBE="../.