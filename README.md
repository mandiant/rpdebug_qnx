# rpdbg
`rpdbg.py` is designed to communicate with the QNX operating system's `pdebug` utility. The `pdebug` utility was written by QNX and appears to be designed to support `GDB` in a very lightweight capacity. The protocol is similar to GDB, but also appears to have been modified. QNX provides their version of `GDB` with their software development platform. The primary purpose of this script is to extract process-level memory from any process leveraging `pdebug`.

**This script will only work on Windows (for now).**

## pdebug
`pdebug` must be instantiated on the QNX machine for this script to connect to it. The following commands were used to instantiate `pdebug` in QNX. Note that the `-1` option specifies that `pdebug` is to terminate when the debug session ends- this is optional (as are the other options).

```
# export PDEBUG_DEBUG=1
# pdebug -1efv 8001
```

## Usage
1. Launch `pdebug` as described above.
```
# export PDEBUG_DEBUG=1
# pdebug -1efv 8001

This version of pdebug was built on May 20 2009.
ProtoVer 0.3
```
2. Run `rpdbg.py` using `Python3`
```
λ python3 rpdbg.py
QNX Process Memory Viewer & Dumper
pdbg>
```
3. `help` to view options, and `help <option>` for light description.
```
pdbg> help

Documented commands (type help <topic>):
========================================
attach   dump           dump_range  quit        verbose
connect  dump_complete  help        set_outdir

pdbg> help connect
Connect to QNX target via IPv4.
* Usage: connect <qnx_ip> <qnx_port>

pdbg>
```

4. There are three ways to dump memory (`dump`, `dump_range`, `dump_complete`).
  * `dump` - Dump up to 0x400 (1024) bytes from a known address. Bytes will be dumped to console and optionally a file.
    * Usage: `dump <addr=0x...> <len (max 1024)> [outfile]`
  * `dump_range` - Dump an address range's worth of pages to a single file.
    * Usage: `dump_range <start_addr: 0x...> <end_addr: 0x...> <outfile>`
  * `dump_complete` - Dump entire address space of process into separate files based on accessible regions.
    * Usage: `dump_complete <outfile_prefix>`

## Example Usage
```
λ python3 rpdbg.py
QNX Process Memory Viewer & Dumper
pdbg> connect 192.168.126.139 8001
Connected
pdbg> attach 847910
Attached
pdbg> dump 0x8048000 256
7f454c460101010000000000000000000200030001000000a8970408340000000cc306000000000034002000060028001b00180006000000340000003480040834800408c0000000c0000000050000000400000003000000f4000000f4800408f4800408140000001400000004000000010000000100000000000000008004080080040862510600625106000500000000100000010000006451060064e10a0864e10a08bc690000dcc300000600000000100000020000007451060074e10a0874e10a08d0000000d000000006000000040000000400000020bb06000881040808810408180000000000000004000000010000002f7573722f6c69622f6c6471
pdbg> dump_range 0x8040000 0x8080000 dump_804_8080000.bin
pdbg> quit
```