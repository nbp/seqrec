Sequence Recognition (seqrec) is a tools for debugging crash-dumps by finding
the code which is responsible for generating a sequence of data.

This tool works in 2 phases. A learning phase, which requires a tiny
instrumentation in your code, and an analysis phase which does not require any
instrumentation.

During the learning phase, your program is supposed to write to a Fifo, the data
which is being written followed by the backtrace which wrote it.

During the analysis phase, you provide a sequence of bytes, and the program
attempt to find the code path corresponding to the data you are seeing.

# How to use.

## Recording

Recording happens by instrumenting a build of the program you are interested in.
The instrumentation should write to the Fifo, with the thread id, followed by
the number of bytes, the bytes which are recorded, the number of stack frames
and the stack frames.

```c++
void
recordBytes(unsigned char* value, size_t size)
{
    MOZ_ASSERT(size < 256);
    void* sptr[64];
    size_t depth = backtrace(sptr, sizeof(sptr));

    // The thread id is used to identify sequences when multiple helper thread
    // or multiple processes are generating stacks concurrently.
    pid_t tid = syscall(SYS_gettid);

    LockGuard<Mutex> guard(stackRecorderLock);
    Fprinter& f = getStackRecorder();                    // append to /tmp/seqrec.fifo
    f.put(reinterpret_cast<char*>(&tid), sizeof(pid_t)); // 4 bytes
    f.putChar(static_cast<unsigned char>(size));         // 1 byte
    f.put(reinterpret_cast<char*>(value), size);         // 0-255 bytes
    f.putChar(static_cast<unsigned char>(depth));        // 1 byte
    f.put(reinterpret_cast<char*>(sptr), depth * sizeof(void*)); // 0-64 * 4/8 bytes
    f.flush();
}
```

Before running the instrumented executable, you should start the `learn.py`
program, which is in charge of creating the Fifo, and waiting for results as
they are written.  Start the `learn.py` program with the following command:

```shell
$ ./learn.py --single \
             --fifo /tmp/seqrec.fifo \
             --binary /path/to/instrumented/bin \
             --out ./seqrec-out \
             --ptr-size 8
```

In the previous command:
  * `--single` is used to automatically terminate the program as soon as all
    writers have closed the Fifo. Dropping this flag implies that the program
    will stay alive until the following command is executed:
  
  ```shell
  $ printf '\x00\x00\x00\x00' > /tmp/seqrec.info
  ```

  * `--fifo` is used to specify the location of the Fifo. In this case it can be
    dropped because ``/tmp/seqrec.fifo`` is the default location.
    
  * `--binary` is used to give the name of the instrumented binary which would
    be sending data on the Fifo. The binary is used to resolve the names of
    symbols using `addr2line`.
  
  * `--out` provides the output file in which the summary would be written to.
    This summary will be used by the sequence recognizer JS script to identify
    what code help produced the sequence.
    
  * `--ptr-size` provides the size of the pointers which are sent over on the
    Fifo. This is used for properly decoding what is being written by the
    instrumented program.
    
## Recognize

The reverse engineering code is currently made in JavaScript for a potential
future integration in a crash-dump analizer tool. To execute this JavaScript
tool at the moment, you will need a recent version of `mozjs` shell.

```shell
$ js ./reverse.js
```

At the moment this is still an experiment, which is hard-coding a test sequence
of bytes.
