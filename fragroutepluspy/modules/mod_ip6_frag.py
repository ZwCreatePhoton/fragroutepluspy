from random import getrandbits

from dpkt.ip import IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMP, IP_MF, IP_OFFMASK, IP_PROTO_FRAGMENT
from dpkt.ip6 import IP6, IP6FragmentHeader
from dpkt.tcp import TCP, TH_ACK, TH_FIN

from .mod import Mod
from .mod_ip6_opt import Ip6Opt

class Ip6Frag(Mod):
    name = "ip6_frag"
    usage = "ip6_frag <size>"
    description = """Fragment each IPv6 packet in the queue into size-byte IP
              fragments, preserving the complete transport header
              in the first fragment."""

    def parse_args(self, args):
        self.size = None

        if len(args) < 1:
            raise Mod.ArgumentException(self, "need segment <size> in bytes")
        try:
            self.size = int(args[0])
            assert (0 < self.size) and (self.size % 8 == 0)
        except:
            raise Mod.ArgumentException(self, "fragment size must be a multiple of 8")

    def apply(self, packets):
        pkts = []
        for packet in packets:
            if Ip6Frag.should_fragment(packet, self.size):
                pkts.extend(Ip6Frag.fragment_packet(packet, self.size))
            else:
                pkts.append(packet)
        del packets[:]
        packets.extend(pkts)

    @staticmethod
    def should_fragment(packet, fragsize):
        # TODO: replace packet.data with packet.data(fragmentable portion)
        return len(packet.data) > fragsize

    @staticmethod
    def fragment_packet(packet, fragsize):

        overlap = 0
        perserve_th = True

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

        # ASSUMPTION: packet has 0 or more extension headers, packet is possibly fragmented. All extension headers are treated as unfragmentabled
        og_fragment = packet.extension_hdrs.get(IP_PROTO_FRAGMENT)

        if og_fragment:
            fragid = og_fragment.id
            og_off = og_fragment.frag_off
        else:
            fragid = getrandbits(16)
            og_off = 0

        payload = str(packet.data)

        p = 0
        pkt_end = len(payload)
        while p < pkt_end:

            new = IP6(str(packet))
            new.plen = fraglen + sum(len(h) for h in packet.all_extension_headers)

            p1 = p
            p2 = None

            # requires at least 2 more fraglens to fit before reaching the ip payload's end to overlap
            if (overlap and not perserve_th and (p + (fraglen * 2)) < pkt_end):
                pass
            else:
                if new.extension_hdrs.get(IP_PROTO_FRAGMENT) is not None:
                    new.extension_hdrs[IP_PROTO_FRAGMENT].frag_off += (p//8)
                else:
                    fh = IP6FragmentHeader(id=fragid)
                    fh.frag_off = og_off + (p // 8)
                    Ip6Opt.add_option(IP_PROTO_FRAGMENT, fh, new)

                if p + fraglen < pkt_end:  # is not the last fragment
                    new.extension_hdrs[IP_PROTO_FRAGMENT].m_flag = True

            if isinstance(p1, int):
                p1 = payload[p1:p1 + fraglen]

            new = IP6(str(new))
            new.data = p1
            new.ts = packet.ts

            packets.append(new)

            if p2 is not None:
                pass
            else:  # p2 is None
                p += fraglen
                perserve_th = False

            fraglen = min(pkt_end - p, fragsize)

        return packets
