import random
import string

from dpkt.ip import IP, IP_PROTO_TCP
from dpkt.ip6 import IP6
from dpkt.tcp import TCP, TH_SYN, TH_ACK, TH_FIN, TCP_OPT_TIMESTAMP, TH_RST

from .mod import Mod, recalculate_checksums, parse_conf_file


class TcpChaff(Mod):
    name = "tcp_chaff"
    usage = "tcp_chaff [cksum|null|paws|rexmit|seq|syn|<ttl>|opt|timestamp|conf [/path/to/conf|@conf_var]] [before|after|sandwich]"
    description = """Interleave TCP segments in the queue with duplicate
              TCP  segments containing different payloads, either
              bearing invalid TCP  checksums,  null  TCP  control
              flags,  older TCP timestamp options for PAWS elimi-
              nation,  faked  retransmits  scheduled  for   later
              delivery,  out-of-window sequence numbers, requests
              to re-synchronize sequence numbers  mid-stream,  or
              short time-to-live values. Insert the new chaffed
              packet before, after, or sandwich the original
              packet. (Default: before)"""
    CKSUM = 1
    NULL = 2
    PAWS = 3
    REXMIT = 4
    SEQ = 5
    SYN = 6
    TTL = 7
    OPT = 8  # IP
    TIMESTAMP = 10 # IP
    CONF = 0

    TOP = 1
    BOTTOM = 2
    OUTSIDE = 3

    def parse_args(self, args):
        self.type = None
        self.ttl = None
        self.rules = []
        self.position = TcpChaff.BOTTOM

        if len(args) == 0:
            raise Mod.ArgumentException(self)
        if args[0] == "cksum":
            self.type = TcpChaff.CKSUM
        elif args[0] == "null":
            self.type = TcpChaff.NULL
        elif args[0] == "paws":
            self.type = TcpChaff.PAWS
        elif args[0] == "rexmit":
            self.type = TcpChaff.REXMIT
        elif args[0] == "seq":
            self.type = TcpChaff.SEQ
        elif args[0] == "syn":
            self.type = TcpChaff.SYN
        elif args[0] == "opt":
            self.type = TcpChaff.OPT
        elif args[0] == "timestamp":
            self.type = TcpChaff.TIMESTAMP
        elif args[0] == "conf":
            self.type = TcpChaff.CONF
            conf_path = args[1]
            self.rules = parse_conf_file(conf_path)
        elif 0 < int(args[0]) < 256:
            self.type = TcpChaff.TTL
            self.ttl = int(args[0])
        else:
            raise Mod.ArgumentException(self)

        if len(args) > 1:
            if args[-1] == "top" or args[-1] == "before":
                self.position = TcpChaff.TOP
            elif args[-1] == "bottom" or args[-1] == "after":
                self.position = TcpChaff.BOTTOM
            elif args[-1] == "outside" or args[-1] == "sandwich":
                self.position = TcpChaff.OUTSIDE


    def apply(self, packets):
        pkts = []

        for packet in packets:
            if not TcpChaff.should_chaff(packet):
                pkts.append(packet)
                continue

            new_packets = TcpChaff.do_chaff(packet, self.type, ttl=self.ttl, rules=self.rules)

            if self.position == TcpChaff.TOP:
                pkts.extend(new_packets)
                pkts.append(packet)
            elif self.position == TcpChaff.BOTTOM:
                pkts.append(packet)
                pkts.extend(new_packets)
            else:  # chaff_position == TcpChaff.OUTSIDE
                pkts.extend(new_packets)
                pkts.append(packet)
                pkts.extend(new_packets)

        del packets[:]
        packets.extend(pkts)


    @staticmethod
    def do_chaff(packet, chaff_type, ttl=None, rules=None):
        # returns the list of chaffed packets that result from chaffing packet

        # zeros are eaiser to identify when debugging
        # dummy_payload = ''.join('\x00' for _ in xrange(len(packet.data.data)))
        dummy_payload = ''.join(random.choice(string.lowercase) for _ in xrange(len(packet.data.data)))

        if packet.v == 4:
            new_packet = IP(str(packet))
        else:
            new_packet = IP6(str(packet))
        new_packet.ts = packet.ts
        new_packet.data.data = dummy_payload
        new_packet.id = random.getrandbits(16)
        recalculate_checksums(new_packet)

        new_packets = [new_packet]

        if chaff_type == TcpChaff.CKSUM:
            TcpChaff.do_cksum(new_packet)
        elif chaff_type == TcpChaff.NULL:
            TcpChaff.do_null(new_packet)
        elif chaff_type == TcpChaff.PAWS:
            TcpChaff.do_paws(new_packet)
        elif chaff_type == TcpChaff.REXMIT:
            TcpChaff.do_rexmit(new_packet)
        elif chaff_type == TcpChaff.SEQ:
            TcpChaff.do_seq(new_packet)
        elif chaff_type == TcpChaff.SYN:
            TcpChaff.do_syn(new_packet)
        elif chaff_type == TcpChaff.TTL:
            assert ttl is not None
            TcpChaff.do_ttl(new_packet, ttl)
        elif chaff_type == TcpChaff.OPT:
            TcpChaff.do_ip_opt(new_packet)
        elif chaff_type == TcpChaff.TIMESTAMP:
            TcpChaff.do_ip_timestamp(new_packet)
        elif chaff_type == TcpChaff.DEV:
            TcpChaff.do_dev(new_packet)
        elif chaff_type == TcpChaff.CONF:
            assert rules is not None
            TcpChaff.do_conf(new_packets, rules)

        return new_packets

    @staticmethod
    def should_chaff(packet):
        ip = packet
        tl = ip.data

        is_fragmented = False
        if ip.v == 4:
            is_fragmented = not ((packet.mf == 0) and (packet.offset == 0))
        else:
            is_fragmented = packet.extension_hdrs.get(44) is not None

        return (not is_fragmented and # Don't chaff IP fragments.
                ip.p == IP_PROTO_TCP and
                tl and isinstance(tl, TCP) and
                not (tl.flags & TH_SYN) and
                not (tl.flags & TH_RST) and # Shouldn't chaff reset packets. Otherwise there will be an infinite loop of SYN & RST packets when using tcp_chaff syn
                not (tl.flags & TH_FIN) and
                not len(tl.data) == 0)

    @staticmethod
    def do_cksum(packet):
        packet.data.sum = random.getrandbits(16)

    @staticmethod
    def do_null(packet):
        packet.data.flags = 0
        recalculate_checksums(packet)

    @staticmethod
    def do_paws(packet):
        """ Assumes that every received TCP segment (including data and ACK segments) contains a timestamp SEG.TSval whose values are monotone non-decreasing in time.
            See: http://www.freesoft.org/CIE/RFC/1323/13.htm """
        packet.data.opts = b'\x01\x01\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x00'
        packet.data.off = 5 + 3
        recalculate_checksums(packet)

    @staticmethod
    def do_rexmit(packet):
        recalculate_checksums(packet)

    @staticmethod
    def do_seq(packet):
        packet.data.seq = 1337
        packet.data.ack = 1337
        recalculate_checksums(packet)

    @staticmethod
    def do_syn(packet):
        packet.data.flags = TH_SYN
        packet.data.seq = random.getrandbits(32)
        packet.data.ack = 0
        packet.data.data = ""
        recalculate_checksums(packet)

    @staticmethod
    def do_ttl(packet, ttl):
        if packet.v == 4:
            packet.ttl = ttl
            recalculate_checksums(packet)
        else:
            print("[!]\n\tCan't apply 'tcp_chaff ttl' to IPv6 packet; skipping")

    @staticmethod
    def do_ip_opt(packet):

        if packet.v == 4:
            # packet.opts = b'\x18\x04\xFF\xFF'  # Invalid for Windows, Valid for CentOS
            packet.opts = b'\xa1\xda\x8b\xa1' # Invalid length -> invalid for both
            # packet.opts = b'\xa1\x04\x8b\xa1' # reserved set to uncommon values: (1,3) # Valid for CentOS, Invalid for Windows

            packet.hl = 6
            recalculate_checksums(packet)
        else:
            print("[!]\n\tCan't apply 'tcp_chaff opt' to IPv6 packet; skipping")

    @staticmethod
    def do_ip_timestamp(packet):

        if packet.v == 4:
            # hex(68) # timestamp
            # CentOS drops: invalid bytes 3 (pointer), invalid bytes 2 (Length  )
            # Windows drops invalid bytes 4 (overflow+flags), invalid bytes 3 (pointer), invalid bytes 2 (Length)
            option = b'\x44\x08\xFF\x00' + '\x00\x00\x00\x00'
            # option = b'\x44\x08\x05\xFF' + '\x00\x00\x00\x00'
            # option = b'\x44\x04\x00\x00' + 4*'\x00'
            packet.opts += option
            packet.hl += len(option)//4
            recalculate_checksums(packet)
        else:
            print("[!]\n\tCan't apply 'tcp_chaff timestamp' to IPv6 packet; skipping")

    @staticmethod
    def do_conf(packets, rules):
        for rule in rules:
            print("Applying {0} to {1} packets.".format(rule.name, len(packets)))
            rule.apply(packets)
