#!/bin/bash
gcc -o initContext.o initContext.c -lcrypto -lpolypasswordhasher
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

