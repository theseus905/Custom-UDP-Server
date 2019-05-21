# This is a UDP Server that parses and verifies packets to be correct and valid
# -- John Trujillo

import argparse
import ast
import codecs
import os
import socket
import struct
import threading as th
import time
import zlib

from Queue import PriorityQueue
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

import multiprocessing as mp

class UServer():

    def __init__(self, keys, bins, delay_time, port):
        self.keys = keys
        self.bins = bins
        self.delay_time = delay_time
        self.port = port

        # counter to wake up checksum thread
        self.i = 1

        # packet_info :: {packet_id:[key_str, bin_str, modulus, e, g_id]}
        self.pkt_info = dict()
        # packet_dic :: {packet_id: PriorityQueue()}
        self.pkt_dic = dict()
        # give each packet iteration a group ID to keep track of discint packets
        self.val_arr =  mp.Manager().dict()

        # queue to place args on, desirable FIFO scheme
        self.queue = mp.Queue()

        # lock for digital signature and checksum threads to write
        self.lock = th.Lock()
        self.lock_v = th.Lock()

    @staticmethod
    def pad_key(key):
        """
        int -> string

        pads a key to be byte aligned
        """
        # must pad key to fill up the 2 bytes.  Ex: 0x1ed -> 0x01ed
        hex_key = "%x"%(key)
        return int(hex_key.zfill(4)*2,16)

    @staticmethod
    def get_pub_key(key_string):
        """
        string -> (long, long)

        Convert the key string into modulus and exponent
        """
        # last three elements are always exponent
        n, e = key_string[:-3], key_string[-3:]
        # string and int parsing from bytes
        modulus = long(codecs.encode(n, 'hex'), 16)
        e = long(codecs.encode(e, 'hex'), 16)

        pub_key = RSA.construct((modulus,e))
        verifier = PKCS1_v1_5.new(pub_key)
        return (verifier, pub_key)

    def check_struct(self, p_id):
        """
        string -> (string,string)

        This function extracts the key and binary file associated with the
        packet id. If packet id was not given as an argument, code returns 0,0

        """

        key_file = self.keys[p_id]
        bin_file = self.bins[p_id]
        with open(bin_file, "r") as bf, open(key_file, "rb") as kf:
            ret = [line for line in bf]
            return (kf.read(), ret)

    def get_chksum(self, p_id, key, crc = 0):
        """
        string -> int -> string -> string -> string

        Calculates checksum for either a file or for a string

        """
        content = self.pkt_info[p_id][1]
        for line in content:
            crc = zlib.crc32(line, crc)
        return "%x"%(crc & 0xFFFFFFFF)

    def verify_sig(self, dig_sig, p_id, p_seq, content, veri, pub_key, g_id):
        """
        string -> string -> string -> string -> int -> int -> bool
        Assumptions:
            digital signature: length 64

        Checks to see if the digitial signature is valid.
        """
        with self.lock_v:
            h = SHA256.new(content)
            h_digest = h.hexdigest()
            # encrypt the signature with the public key
            sig_encrypted = pub_key.encrypt(dig_sig,0)[0]
            # get expected hash
            exp_hash = codecs.encode(sig_encrypted, 'hex')[-64:]

            if not veri.verify(h, dig_sig):
                self.val_arr[g_id].append(0)
                self.dig_sig_writer(p_id, str(p_seq), exp_hash, h_digest)
                return

            self.val_arr[g_id].append(1)
            # if both threads for the group id are ready, let us know
            if sum(self.val_arr[g_id]) is 2:
                self.add_to_pq(content + dig_sig, p_id, p_seq, g_id)
        return

    def verify_chksum(self, q):
        """
        a' queue -> ()

        PreCond: q : queue
        Verifies if the checksum for each element in a queue is valid
        """
        while not q.empty():
            p_id, p_seq, key, content, chk_num, g_id = q.get()
            # make crc value change respective to the current packet id
            group_num, f_chksum = self.pkt_info[p_id][4]
            for i in range(chk_num):
                # get file checksum
                f_chksum = self.get_chksum(p_id, key, int(f_chksum, 16))
                # xor it with the key
                f_chk_xor = int(f_chksum, 16) ^ UServer.pad_key(key)
                # get the unpacked chksum
                p_chk_val = struct.unpack("!L", content[:4])[0]
                if p_chk_val != f_chk_xor:
                    # increment g_id and update new value for crc
                    self.pkt_info[p_id][4] = [group_num + 1, f_chksum]
                    # inverse of XOR is identity
                    rec_crc = "%x"%(p_chk_val ^ UServer.pad_key(key))
                    seq_val = p_seq + i
                    self.checksum_writer(p_id, str(p_seq), str(seq_val),
                                         rec_crc, f_chksum)
                    break
                content=content[4:]
            else:
                # increment g_id since
                self.pkt_info[p_id][4] = [group_num + 1, f_chksum]
                self.val_arr[g_id].append(1)
                # check if g_id packet is done
                if len(self.val_arr[g_id]) == 2:
                    self.add_to_pq(content, p_id, p_seq, g_id)
        print "done1231"

    def add_to_pq(self, packet, p_id, packet_seq, g_id):
        "append to the PriorityQueue"
        valid_x, valid_y = self.val_arr[g_id]
        del self.val_arr[g_id] # g_id wont be used again in this run
        self.pkt_dic[p_id].put((packet_seq, packet))

    def p_id_mapping(self):
        """
        void

        PreCond: There is a binary file and key file

        PostCond: Populates the pkt_info (dict) with the given data from
        command line to avoid extra reads and have it all memoized

        """
        for id in self.keys:
            key_, binary_ = self.check_struct(id)
            veri, pub_key = self.get_pub_key(key_)
            self.pkt_dic[id] = PriorityQueue()
            # memoize pid with key and binary string mappings
            self.pkt_info[id] = [key_, binary_, veri, pub_key, [1,"0"]]

    def dig_sig_writer(self, p_id, p_seq, recv_hash, exp_hash):
        p_id  += "\n"
        p_seq += "\n"
        recv_hash += "\n"
        exp_hash += "\n\n"
        with open("verification_failures.log", "a+") as verif_file:
            time.sleep(self.delay_time)
            verif_file.write(p_id + p_seq + recv_hash + exp_hash)

    def checksum_writer(self, p_id, p_seq, iter, r_crc32, e_crc32):
        p_id  += "\n"
        p_seq += "\n"
        iter += "\n"
        r_crc32 += "\n"
        e_crc32 += "\n\n"
        with open("checksum_failures.log", "a+") as chksum_file:
            time.sleep(self.delay_time)
            chksum_file.write(p_id + p_seq + iter + r_crc32 + e_crc32)

    def auth(self, packet, p_seq, p_id, g_id):
        """
        string -> string -> int -> void

        main executing thread for a packet, appends to a dictionary or
        writes to a log file
        """
        with self.lock:
            # keep track of different packet ids
            content, dig_sig = packet[:-64], packet[-64:]
            key_str, bin_str, verifier, pub_key, _ = self.pkt_info[p_id]

            # declare verification thread
            thread_dig_sig = th.Thread(target = self.verify_sig,
                                       args = (dig_sig, p_id, p_seq, content,
                                               verifier, pub_key, g_id))
            thread_dig_sig.start()

    def get(self, pid):
        """
        string -> string

        get all the packet content of a given packet id in packet sequence
        order
        """
        pid = hex(pid)
        x = ''.join( str(self.pkt_dic[pid].get()[1])
                for _ in range(self.pkt_dic[pid].qsize()))

    def run(self):
        # create files
        fd1 = open("verification_failures.log","w+")
        fd1.close()

        fd2 = open("checksum_failures.log","w+")
        fd2.close()

        #init UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("",self.port))

        #  multicore checksum process
        p = mp.Process(target=self.verify_chksum, args = (self.queue,))

        self.p_id_mapping()

        while 1:
            packet, addr = sock.recvfrom(65565)
            self.val_arr[self.i] = []

            udp_header  = struct.unpack('!IIHH', packet[:12])
            packet_id, packet_seq, xor_key, chk_num = udp_header
            p_id = hex(packet_id)

            c_args = (p_id, packet_seq, xor_key, packet[12:-64], chk_num, self.i)

            if self.queue.empty():
                self.queue.put(c_args)
                p.start()

            else:
                self.queue.put(c_args)

            th_auth =  th.Thread(target = self.auth,
                                 args = (packet, packet_seq, p_id, self.i))
            self.i += 1
            th_auth.start()
        sock.close()

if __name__ == '__main__':

    key_string = ('Define a dictionary of {packet_id: key_file_path} mappings' +
                 '\n ex : --keys \'{"0x42": "key.bin"}\'')
    bin_string = ('Define a dictionary of {packet_id: bin_file_path} mappings' +
                 '\n ex : --binaries \'{"0x42": "cat.jpg"} \'')
    port_string = ('Define a delay (in seconds) for writing to log files' +
                  '\n ex: -d \'180\'')
    delay_string = ('Define a new port to receive packets on\nex: \-p \'1337\'')


    #parse flags
    parser = argparse.ArgumentParser(description='Process commands')

    parser.add_argument('--keys', action='store', default='{"0x42":"key.bin"}',
                        help = key_string)

    parser.add_argument('--binaries', action='store',
                        help = bin_string)

    parser.add_argument('-d', action ='store', default = '0',
                        help = delay_string)

    parser.add_argument('-p', action ='store', default = '80',
                        help = port_string)

    # get flag attributes
    ARGS = parser.parse_args()

    # key and binaries are dict
    KEYS = ast.literal_eval(ARGS.keys.replace("\\", ""))
    BINARIES = ast.literal_eval(ARGS.binaries.replace("\\", ""))
    DELAY_TIME = int(ARGS.d)
    PORT = int(ARGS.p)

    udp = UServer(KEYS, BINARIES, DELAY_TIME, PORT)
    udp.run()
    # udp.get(66)
