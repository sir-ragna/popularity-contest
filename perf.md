
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
