from dpkt.ip import IP, IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMP, IP_MF, IP_OFFMASK
from dpkt.tcp import TCP, TH_ACK, TH_FIN
from copy import copy
import random, string
from socket import htons


import logging

from .mod import Mod


# favor old IP fragment overlap no longer works for Windows > XP

class IpFrag(Mod):
    name = "ip_frag"
    usage = "ip_frag <size> [old|new]"
    description = """Fragment each packet in the queue into size-byte IP
              fragments, preserving the complete transport header
              in the first fragment.  Optional  fragment  overlap
              may  be  specified as old or new, to favor newer or
              older data."""
    OLD = 1
    NEW = 2

    def parse_args(self, args):
        self.size = None
        self.overlap = None

        if len(args) < 1:
            raise Mod.ArgumentException(self, "need segment <size> in bytes")
        try:
            self.size = int(args[0])
            assert (0 < self.size) and (self.size % 8 == 0)
        except:
            raise Mod.ArgumentException(self, "fragment size must be a multiple of 8")

        if len(args) == 2:
            if args[1] in ("old", "win32"):
                self.overlap = IpFrag.OLD
            elif args[1] in ("new", "unix"):
                self.overlap = IpFrag.NEW
            else:
                raise Mod.ArgumentException(self)

    def apply(self, packets):
        pkts = []
        for packet in packets:
            if IpFrag.should_fragment(packet, self.size):
                pkts.extend(IpFrag.fragment_packet(packet, self.size, self.overlap))
            else:
                pkts.append(packet)
        del packets[:]
        packets.extend(pkts)

    @staticmethod
    def should_fragment(packet, fragsize):
        return len(packet.data) > fragsize

    @staticmethod
    def fragment_packet(packet, fragsize, overlap=None, perserve_th=True, clear_df=True):
        packets = []

        # Move into should_fragment?
        if (perserve_th and packet.p == IP_PROTO_TCP and isinstance(packet.data, TCP)):
            tcp = packet.data
            fraglen = max(tcp.off << 2, fragsize)
            fraglen = ((fraglen + 7) // 8) * 8  # round up to a multiple of 8
            if len(bytes(tcp)) < fraglen: # can this occur when headers / etc are all correct on the original packet?
                packets.append(packet)
                return packets
        else:
            fraglen = fragsize

        if clear_df:
            packet.df = 0

        payload = str(packet.data)
        og_off = packet.offset
        p = 0
        pkt_end = len(payload)
        while p < pkt_end:

            new = IP(str(packet))

            p1 = p
            p2 = None

            # requires at least 2 more fraglens to fit before reaching the ip payload's end to overlap
            if (overlap and not perserve_th and (p + (fraglen * 2)) < pkt_end):
                logging.info("inside overlap conditional")
                tmp_buf = ''.join(random.choice(string.lowercase) for _ in xrange(fraglen))
                #tmp_buf = '\x00' * fraglen # easier to identify while debugging
                if overlap == IpFrag.OLD:
                    p1 = p + fraglen
                    p2 = tmp_buf
                elif overlap == IpFrag.NEW:
                    p1 = tmp_buf
                    p2 = p + fraglen
                new.mf = 1
                new.offset = og_off + p + fraglen
            else:
                new.offset = og_off + p

                if p + fraglen < pkt_end: # is not the last fragment
                    new.mf = 1

            if isinstance(p1, int):
                p1 = payload[p1:p1 + fraglen]

            new.len = 0
            new.sum = 0
            new.data = p1
            new = IP(str(new))
            new.ts = packet.ts

            packets.append(new)

            if p2 is not None:
                if isinstance(p2, int):
                    p2 = payload[p2:p2 + fraglen]

                new2 = IP(str(new))

                new2.mf = True
                new2.offset = og_off + p

                # these are double fraglen long packets with first portion good data the other trash data
                new2.len = 0
                new2.sum = 0
                new2.data = payload[p:p + fraglen] + p2
                new2 = IP(str(new2))
                new2.ts = new.ts
                packets.append(new2)
                p += (fraglen * 2)
            else: # p2 is None
                p += fraglen
                perserve_th = False

            fraglen = min(pkt_end - p, fragsize)

        return packets
