#!/bin/sh
gcc -g -Wall -o creole *.h *.c -Iinclude -L. -l:libxed.a
