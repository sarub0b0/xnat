#!/bin/bash

if [ -z "$1" ]; then
    echo "Set obj filename."
    exit 1
fi

llvm-objdump -S --no-show-raw-insn $1
