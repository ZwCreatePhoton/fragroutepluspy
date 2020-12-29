from copy import copy
import random, string
from random import getrandbits
from dpkt.ip import IP, IP_PROTO_TCP
from dpkt.ip6 import IP6
from dpkt.tcp import TCP, TH_ACK, TH_FIN

from .mod import Mod

import logging


class TcpSeg(Mod):
    name = "tcp_seg"
    usage = "tcp_seg <size> [old|new|windows_new [<size2>]|windows_new_old [<size2>]]"
    description = """Segment each TCP data segment  in  the  queue  into
              size-byte  TCP  segments.  Optional segment overlap
              may be specified as old or new, to favor  newer  or
              older data. Or windows_new to favor newer at the
              beginning and non-overlapping segmentation of
              size <size2> at the end. Or windows_new_old to favor
              newer at the beginning and favor older with segments
              of size <size2> at the end."""
    OLD = 1
    NEW = 2
    WINDOWS_NEW = 3
    WINDOWS_NEW_OLD = 4

    def parse_args(self, args):
        self.size = None
        self.size2 = 1
        self.overlap = None

        if len(args) < 1:
            raise Mod.ArgumentException(self, "need segment <size> in bytes")
        try:
            self.size = int(args[0])
            assert 0 < self.size
        except:
            raise Mod.ArgumentException(self, "invalid segment size {0}".format(args[0]))
        if len(args) >= 2:
            if args[1] in ("old", "win32"):
                self.overlap = TcpSeg.OLD
            elif args[1] in ("new", "unix"):
                self.overlap = TcpSeg.NEW
            elif args[1] in ("windows_new",):
                self.overlap = TcpSeg.WINDOWS_NEW
                if len(args) == 3:
                    try:
                        self.size2 = int(args[2])
                        assert 0 < self.size2
                    except:
                        raise Mod.ArgumentException(self, "invalid segment size {0}".format(args[2]))
            elif args[1] in ("windows_new_old",):
                self.overlap = TcpSeg.WINDOWS_NEW_OLD
                if len(args) == 3:
                    try:
                        self.size2 = int(args[2])
                        assert 0 < self.size2
                    except:
                        raise Mod.ArgumentException(self, "invalid segment size {0}".format(args[2]))
            else:
                raise self.ArgumentException(self)

    def apply(self, packets):
        pkts = []
        for packet in packets:
            if TcpSeg.should_segment(packet, self.size):
                if self.overlap == TcpSeg.WINDOWS_NEW:
                    pkts.extend(TcpSeg.segment_packet_windows_new(packet, self.size, self.size2))
                elif self.overlap == TcpSeg.WINDOWS_NEW_OLD:
                    pkts.extend(TcpSeg.segment_packet_windows_new(packet, self.size, self.size2, self.OLD))
                else:
                    pkts.extend(TcpSeg.segment_packet(packet, self.size, self.overlap))
            else:
                pkts.append(packet)
        del packets[:]
        packets.extend(pkts)

    @staticmethod
    def should_segment(packet, segsize):
        ip = packet
        tl = ip.data

        is_fragmented = False
        if ip.v == 4:
            is_fragmented = not ((packet.mf == 0) and (packet.offset == 0))
        else:
            is_fragmented = packet.extension_hdrs.get(44) is not None

        return  (not is_fragmented and # Don't segment IP fragments.
                ip.p == IP_PROTO_TCP and
                tl and isinstance(tl, TCP) and
                (tl.flags & TH_ACK) and  # requires ACK flag
                tl.data and len(tl.data) > segsize)

    @staticmethod
    def segment_packet_windows_new(packet, segsize, segsize2=1, overlap2=None):
        reassembly_queue_size = 48

        ip = packet
        tcp = ip.data
        payload = str(tcp.data)

        if overlap2:
            # for reassembly_queue_size total segments
            right_whole_size = 2 * segsize2 * ((reassembly_queue_size + 1) / 2 - 1) + 2 * segsize2
        else:
            right_whole_size = segsize2 * reassembly_queue_size
        left_whole_size = len(payload) - right_whole_size
        if left_whole_size < right_whole_size or len(payload) <= right_whole_size + 2*segsize:
            return [packet]

        left_packet, right_packet = TcpSeg.segment_packet(packet, left_whole_size)
        left_segments = TcpSeg.segment_packet(left_packet, segsize, TcpSeg.NEW)
        right_segments = TcpSeg.segment_packet(right_packet, segsize2, overlap2)

        # for reassembly_queue_size total segments
        if overlap2 and reassembly_queue_size % 2 == 0:
            last_segment = right_segments.pop()
            last_segments = TcpSeg.segment_packet(last_segment, segsize2)
            right_segments.extend(last_segments)

        return right_segments + left_segments

    # assumes the packet pkt has a TCP layer
    @staticmethod
    def segment_packet(packet, segsize, overlap=None):

        packets = []

        ip = packet
        tcp = ip.data
        seq = tcp.seq
        p = 0
        payload = str(tcp.data)
        packet_end = len(payload)
        while p < packet_end:
            pkt1 = copy(ip)

            p1 = p
            p2 = None
            length = min(packet_end - p, segsize)

            if overlap and (p + (length << 1) < packet_end):
                tmp_buf = ''.join(random.choice(string.lowercase) for _ in xrange(length))
                # tmp_buf = ''.join('\x00' for _ in xrange(length)) # easier to identify while debugging
                if overlap == TcpSeg.OLD:
                    p1 = p + length
                    p2 = tmp_buf
                elif overlap == TcpSeg.NEW:
                    p1 = tmp_buf
                    p2 = p + length
                length = segsize
                seq += segsize

            if isinstance(p1, int):
                pload1 = payload[p1:p1 + length]
            else:
                pload1 = p1 # pkt2 will be created this iteration.

            # tcp1 = TCP(str(tcp), seq=seq, sum=0) # Bug in dpkt (at least in 1.9.x). Need to set sum = 0 in outside of the constructor
            tcp1 = TCP(str(tcp))
            tcp1.sum = 0
            tcp1.seq = seq
            tcp1.flags &= ~TH_FIN # limit FIN flag to only the last segment
            tcp1.data = pload1
            if p + length == packet_end and (tcp.flags & TH_FIN): 
                tcp1.flags |= TH_FIN
            pkt1.data = tcp1
            pkt1.id = getrandbits(16)
            if pkt1.v == 4:
                pkt1.sum = 0
                pkt1.len = 0
            else:
                # length is recalculated for IP but not for IPv6
                pkt1.plen = len(pkt1.data)

            if pkt1.v == 4:
                pkt1 = IP(bytes(pkt1))
                # bytes(packet) calculates both IP & TCP chksum if both sums set to 0
            else:
                pkt1 = IP6(bytes(pkt1))
            pkt1.ts = ip.ts

            packets.append(pkt1)

            if p2 is not None:
                pkt2 = copy(pkt1)

                if isinstance(p2, int):
                    pload2 = payload[p2:p2 + length]
                else:
                    pload2 = p2

                # tcp2 = TCP(str(tcp1), seq=seq-length, sum=0)
                tcp2 = TCP(str(tcp1))
                tcp2.sum = 0
                tcp2.seq = seq - length
                tcp2.data = payload[p:p+length] + pload2
                pkt2.data = tcp2
                pkt2.id = getrandbits(16)
                if pkt2.v == 4:
                    pkt2.sum = 0
                    pkt2.len = 0
                else:
                    # length is recalculated for IP but not for IPv6
                    pkt2.plen = len(pkt2.data)
                if pkt2.v == 4:
                    pkt2 = IP(bytes(pkt2)) # recalculates checksums
                else:
                    pkt2 = IP6(bytes(pkt2))
                pkt2.ts = pkt1.ts + 0.000001

                packets.append(pkt2)
                p += length

            seq += length
            p += length

        return packets
