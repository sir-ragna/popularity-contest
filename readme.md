
![Valgrind memcheck](https://github.com/sir-ragna/popularity-contest/actions/workflows/makefile.yml/badge.svg)

# What CPU instructions are the most popular?

That is the question that I wanted to answer.

You can run it on an x64 ELF file and it will read out the .text section
if it can find it, disassemble and count the instructions and output
the results as CSV.

## Why?

There exist about 1500+ instructions in x86-64.
If one wanted to learn x86-64, maybe it is reasonable to look into 
which instructions are the most used.

Which lead me to the question, which instructions are the most popular?

## Build upon other works

This project wouldn't have been possible without 
https://github.com/Nomade040/nmd

## Build it yourself

Activate the git submodule to satisfy the dependencies.

```
git submodule update --init --recursive
```

Then you can compile it with your compiler of choice.

```
gcc -Wall -O2 -o main main.c
```

## Valgrind

I used valgrind to check for memory leaks.
I suggest compiling with debug symbols first `-g`.

```sh
gcc -g -o main main.c
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --log-file=valgrind-out.txt ./main /bin/a* 2>/dev/null >/dev/null
```

## Profiling

First compile with profiling active. (`-pg`)

    gcc -pg -g -o main main.c

Run the software. (On itself for example)

    ./main main

This will create a file `gmon.out`. You can feed this file to the 
program gprof together with the original executable to get a performance
report.

    gprof main gmon.out

## Advanced profiling

To create a flame graph of the execution you can use the flamegraph
scripts from https://github.com/brendangregg/FlameGraph

    perf record -g ./main /bin/*
    perf script | ../FlameGraph/stackcollapse-perf.pl | ../FlameGraph/flamegraph.pl > perf.data.svg
