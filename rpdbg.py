"""
# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.

Author: Omar Sardar <omar.sardar@fireeye.com>
Name: rpdbg.py

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import sys
import os
import logging
import cmd
import socket
import struct
import binascii
import time

class Pdebug():
    logger = None

    counter = 0x100
    rx_buf_len = 0x84C # Buffer from pdebug (verify)

    qnx_ip = None
    qnx_port = None
    qnx_sock = None

    cmd = { "TargetConnect": 0,
            "TargetDisconnect": 1,
            "TargetSelect": 2,
            "TargetMapinfo": 3,
            "TargetLoad": 4,
            "TargetAttach": 5,
            "TargetDetach": 6,
            "TargetKill": 7,
            "TargetStop": 8,
            "TargetMemrd": 9,
            "TargetMemwr": 10,
            "TargetRegrd": 11,
            "TargetRegwr": 12,
            "TargetRun": 13,
            "TargetBrk": 14,
            "TargetFileopen": 15,
            "TargetFilerd": 16,
            "TargetFilewr": 17,
            "TargetFileclose": 18,
            "TargetPidlist": 19,
            "TargetCwd": 20,
            "TargetEnv": 21,
            "TargetBase": 22,
            "TargetProtover": 23,
            "TargetHandlesig": 24,
            "TargetCPUInfo": 25,
            "TargetTIDNames": 26,
    }

    response = { "ResponseOk": 0x21,
                "ResponseErr": 0x20,
                "ResponseOkData": 0x23,
                "ResponseOkStatus": 0x22,
    }

    def __init__(self, qnx_ip, qnx_port, loglevel=logging.INFO):
        self.logger = logging.getLogger(__name__)
        self.qnx_sock = self.qnx_connect(qnx_ip, qnx_port)
        self.qnx_handshake()
        

    def dump_packet_info(self, buf, tag=""):
        self.logger.info("[{}] {}b -> {}".format(tag, len(buf), buf.hex()))

    def gen_checksum(self, user_buf):
        checksum = bytes([0xFF - (sum(list(user_buf)) % 0x100)])
        if ord("~") in checksum:
            checksum = bytes([0x7d, 0x5e])
        elif ord("}") in checksum:
            checksum = bytes([0x7d, 0x5d])
        return checksum

    def get_status(self, rx_buf):
        return rx_buf[1]

    def inc_counter(self):
        self.counter += 1
        self.counter = self.counter % 0x200
        if self.counter == 0:
            self.counter = 0x100 # Not sure if this matters
        counter_le = struct.pack("<H", self.counter)    

        # TODO the real fix is likely to replace 0x7d with (0x7d, 0x5d) and 0x7e with (0x7d, 0x5e)
        if b"\x7d" in counter_le:
            self.counter += 2 # Limited time, lazy skip past edge cases 0x7d and 0x7es
        return self.counter

    def cmd_TargetMemrd(self, addr, n_bytes):
        """
        Dump memory (8-byte)
        TX TargetMemrd cmd[1]; space[1]; counter[2]; unk[4]; addr_lower[4]; addr_upper[4]; size[2]; unk[6]; csum[1]
        RX TargetMemRd cmd[1]; status[1]; counter[2]; data[8]; csum[1]
        """
        self.logger.info("TargetMemRd: {} {}-bytes".format(hex(addr), n_bytes))

        addr_le = struct.pack("<Q", addr)
        n_bytes_le = struct.pack("<H", n_bytes)
        counter_le = struct.pack("<H", self.inc_counter())
        data = bytes([self.cmd["TargetMemrd"]]) + bytes(1) + counter_le + bytes(4) + addr_le + n_bytes_le + bytes(6)
        checksum = self.gen_checksum(data)

        # Regenerate packet with substitutions, must be appended with old checksum
        addr_le = addr_le.replace(b"\x7d", b"\x7d\x5d") # GDB protocol delimiter replacement, packet size increases
        addr_le = addr_le.replace(b"\x7e", b"\x7d\x5e") # GDB protocol delimiter replacement, packet size increases
        data = bytes([self.cmd["TargetMemrd"]]) + bytes(1) + counter_le + bytes(4) + addr_le + n_bytes_le + bytes(6)
        tx_buf = b"~" + data + checksum + b"~"
        self.qnx_sock.send(tx_buf)
        self.dump_packet_info(tx_buf, tag="tx")
        rx_buf = self.qnx_sock.recv(self.rx_buf_len)
        self.dump_packet_info(rx_buf, tag="rx")
        # RX TargetMemrd cmd[1]; status[1]; counter[2]; status[4]; csum[1]
        status = rx_buf[1]
        if status == 0x00:
            memrd_data = rx_buf[5:-2] # This case should cover all n_bytes values
        elif status == self.response['ResponseOkData']:
            memrd_data = rx_buf[5:-2]
            self.logger.info("Received ResponseOkData vs. 0x00")
        elif status == self.response['ResponseErr']:
            memrd_data = bytes(0)
            self.logger.info("Received ResponseErr")
        else:
            self.logger.info("Unknown status byte: {}".format(status))
            import pdb; pdb.set_trace()
            memrd_data = bytes(0)

        memrd_data = memrd_data.replace(b"\x7d\x5e", b"\x7e") #GDB protocol delimiter (~) replacement
        memrd_data = memrd_data.replace(b"\x7d\x5d", b"\x7d") #GDB protocol delimiter (}) replacement

        return memrd_data

    def cmd_TargetDetach(self, pid):
        self.logger.info("TargetDetach: {}".format(hex(pid)))
        
        pid_le = struct.pack("<I", pid)
        counter_le = struct.pack("<H", self.inc_counter())
        data =  bytes([self.cmd["TargetDetach"]]) + bytes(1) + counter_le + pid_le
        checksum = self.gen_checksum(data)
        tx_buf = b"~" + data + checksum + b"~"
        self.qnx_sock.send(tx_buf)
        self.dump_packet_info(tx_buf, tag="tx")
        rx_buf = self.qnx_sock.recv(self.rx_buf_len)
        self.dump_packet_info(rx_buf, tag="rx")
        return True

    def cmd_TargetAttach(self, pid):
        self.logger.info("TargetAttach: {}".format(hex(pid)))

        pid_le = struct.pack("<I", pid)
        counter_le = struct.pack("<H", self.inc_counter())
        data =  bytes([self.cmd["TargetAttach"]]) + bytes(1) + counter_le + pid_le
        checksum = self.gen_checksum(data)
        tx_buf = b"~" + data + checksum + b"~"
        self.qnx_sock.send(tx_buf)
        self.dump_packet_info(tx_buf, tag="tx")
        rx_buf = self.qnx_sock.recv(self.rx_buf_len)
        self.dump_packet_info(rx_buf, tag="rx")
        if rx_buf[1] == self.response["ResponseErr"]:
            self.logger.info("Could not attach to PID {}".format(hex(pid)))
            return False
        return True

    def mem_page_check(self, start, end, n_bytes=1):
        time_start = time.time()
        valid_pages = list()
        for addr in range(start, end, 0x1000):
            memrd_data = self.cmd_TargetMemrd(addr, 1)
            if memrd_data == "":
                continue
            else:
                valid_pages.append(addr)
                self.logger.info("{}: Data accessible".format(hex(addr)))
        time_delta = time.time() - time_start
        self.logger.info("Page check complete: {} valid pages found in {} ms".format(len(valid_pages), time_delta))
        return valid_pages

    def get_page_range(self, start, end):
        # Checks if complete page is retrieved
        for addr in range(start, end, 0x1000):
            page = self.get_page(addr)
            if len(page) != 0x1000:
                self.logger.info("Fail - {} of 0x1000 bytes extracted from {}".format(hex(len(page)), hex(addr)))
                continue
            else:
                yield page

    def get_page(self, addr):
        # Will NOT check if a page was retrieved
        self.logger.info("get_page: Reading {}".format(hex(addr)))
        page = bytes()
        for addr_chunk in range(addr, addr+0x1000, 0x400):
            page += self.cmd_TargetMemrd(addr_chunk, 0x400)
        if len(page) != 0x1000:
            self.logger.info("Complete page not retrieved @ {}".format(hex(addr)))
        return page

    def qnx_handshake(self):
        rx_buf = self.qnx_sock.recv(self.rx_buf_len)   # Receive 4 bytes back '7e00ff7e'
        self.dump_packet_info(rx_buf, tag="rx")
        tx_buf = rx_buf
        self.qnx_sock.send(tx_buf)   # Reply back w/ same buffer, appears to be the handshake
        self.dump_packet_info(tx_buf, tag="tx")
        tx_buf = binascii.unhexlify("7e0000000100070000f77e") # TargetConnect unk
        self.qnx_sock.send(tx_buf)
        self.dump_packet_info(tx_buf, tag="tx")
        rx_buf = self.qnx_sock.recv(self.rx_buf_len)   # Receive 4 bytes '7e01fe7e'
        self.dump_packet_info(rx_buf, tag="rx")
        rx_buf = self.qnx_sock.recv(self.rx_buf_len)   # Status 0x420 '7e2200|0001|20040000b87e' Counter begins here @ 0x100
        self.dump_packet_info(rx_buf, tag="rx")
        self.inc_counter()
        tx_buf = binascii.unhexlify("7e170001010007df7e") # Note counter increment to 0x101
        self.qnx_sock.send(tx_buf)
        self.dump_packet_info(tx_buf, tag="tx")
        rx_buf = self.qnx_sock.recv(self.rx_buf_len) # Status 7e2200010103000000d87e
        self.dump_packet_info(rx_buf, tag="rx")
        self.logger.info("Init complete")
        return True

    def qnx_connect(self, qnx_ip, qnx_port):
        qnx_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.info("Connecting to {0}:{1}...".format(qnx_ip, qnx_port))
        qnx_sock.connect((qnx_ip, qnx_port))
        self.logger.info("Connected")
        return qnx_sock

class PdebugShell(cmd.Cmd):
    intro = "QNX Process Memory Viewer & Dumper"
    prompt = "pdbg> "
    pid = None
    outdir = os.getcwd()
    logger = None
    pdbg = None
    active = False
    verbose = False
    dump_complete = False

    def do_connect(self, args):
        "Connect to QNX target via IPv4.\n* Usage: connect <qnx_ip> <qnx_port>"
        if len(args.split()) != 2:
            print("See 'help connect' for command usage information.")
            return

        qnx_ip, qnx_port = args.split()
        try:
            self.pdbg = Pdebug(qnx_ip, int(qnx_port))
        except ConnectionRefusedError:
            print("Could not connect to {}:{}.".format(qnx_ip, qnx_port))
            print("* Is 'pdebug {}' running on QNX target?".format(qnx_port))
            return
        self.active = True
        print("Connected")
        
    def do_attach(self, args):
        "Attach to process using PID. \n* Usage: attach <pid>"
        if self.pid:
            self.pdbg.cmd_TargetDetach(self.pid)
            self.pid = None
        pid = args
        try:
            if pid[0:2] == "0x":
                self.pid = int(pid, 16)
            else:
                self.pid = int(pid)
        except:
            print("See 'help attach' for command usage information.")
            return

        status = self.pdbg.cmd_TargetAttach(self.pid)
        if status:
            print("Attached")
        else:
            print("Could not attach to PID {}".format(hex(self.pid)))
            self.pid = None
        return

    def do_dump(self, args):
        "Dump memory from target process from a known address\n* Usage: dump <addr=0x...> <len (max 1024)> [outfile]"
        outfile = None

        if not self.pid:
            print("Not attached to any processes.")
            return

        n_args = len(args.split())
        if n_args == 2:
            addr, n_bytes = args.split()
        elif n_args == 3:
            addr, n_bytes, outfile = args.split()
        else:
            print("See 'help dump' for command usage information.")
            return

        try:
            addr = int(addr, 16)
            n_bytes = int(n_bytes)
        except:
            print("Invalid argument")
            return
        
        if n_bytes > 0x400:
            print("Max buffer length is 0x400 (1024).")
            return

        data = self.pdbg.cmd_TargetMemrd(addr, n_bytes)
        if data == '':
            print("{} is inaccessible.".format(n_bytes))
            return
        print(data.hex())

        if outfile:
            outfile_path = os.path.join(self.outdir, outfile)
            with open(outfile_path, "wb") as fd:
                fd.write(data)
            print("Data dumped to {}".format(outfile_path))

        return

    def do_dump_range(self, args):
        "Dump a range of memory (if accessible) in the target process\n* Usage: dump_range <start_addr: 0x...> <end_addr: 0x...> <outfile>"
        if not self.pid:
            print("Not attached to any processes.")
            return
            
        n_args = len(args.split())
        if n_args != 3:
            print("See 'help dump_range for command usage information.")
            return

        start, end, outfile = args.split()
        if not start.startswith("0x") or not end.startswith("0x"):
            print("Addresses must be in hex, prefix with '0x'. See 'help dump_range for command usage information.")
            return
        else:
            start = int(start, 16)
            end = int(end, 16)
            if end <= start:
                print("Invalid address range (end <= start).")
                return

        outfile_path = os.path.join(self.outdir, outfile)
        with open(outfile_path, "wb") as fd:
            for page in self.pdbg.get_page_range(start, end):
                if len(page) != 0x1000:
                    page = bytes(0x1000) # Fill with zero pages
                fd.write(page)

    def do_dump_complete(self, args):
        "Bruteforce & dump all memory sections in target process\n* Usage: dump_complete <outfile_prefix>"
        if not self.pid:
            print("Not attached to any processes.")
            return
            
        if self.dump_complete:
            print("dump_complete can only run once during a given session. Please restart.")
            return

        n_args = len(args.split())
        if n_args != 1:
            print("See 'help dump_complete' for command usage information.")
            return
        
        outfile_prefix = args
        outfile_ext = ".bin"
        record = False
        pages = b""
        start = 0x0
        end = 0xFFFFFFFF
        for addr in range(start, end, 0x1000):
            if addr % 0x100000 == 0:
                print("\rDumping {}...".format(hex(addr)), end='')

            page = self.pdbg.get_page(addr)
            if len(page) == 0x1000:
                if not record:
                    rec_start = hex(addr)
                    record = True
                pages += page
            else:
                if len(pages):
                    outfilename = "_".join([outfile_prefix, rec_start, hex(addr)]) + outfile_ext
                    outfilepath = os.path.join(self.outdir, outfilename)
                    print("\rDumping ({}:{}) to {}".format(rec_start, hex(addr), outfilename))
                    with open(outfilepath, "wb") as fd:
                        fd.write(pages)
                    record = False
                    pages = b""
        
        # Edge case: Last page in range is successfully retrieved
        if len(pages):
            outfilename = "_".join([outfile_prefix, rec_start, hex(end)]) + outfile_ext
            outfilepath = os.path.join(self.outdir, outfilename)
            print("\rDumping ({}:{}) to {}".format(rec_start, hex(addr), outfilename))
            with open(outfilepath, "wb") as fd:
                fd.write(pages)

        self.dump_complete = True
        print("Complete")
        return

    def do_set_outdir(self, args):
        "Set the folder location of memory dumps.\n*Usage: set_outdir [dir]"
        print("Current output directory: {}".format(self.outdir))
        if args != "":
            if os.path.exists(args):
                print("New output directory: {}".format(args))
                self.outdir = args
            else:
                print("Path not found.")
        return

    def do_verbose(self, args):
        "Display logging messages"
        logging.basicConfig(level=logging.INFO)

    def do_quit(self, args):
        "Exit shell\n* Usage: quit"
        if self.pid:
            self.pdbg.cmd_TargetDetach(self.pid)
            self.pid = None
        sys.exit(0)

if __name__ == "__main__":
    PdebugShell().cmdloop()
