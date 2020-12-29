from copy import copy
import random, string

from dpkt.ip6 import IP6

from .mod import Mod, parse_conf_file


def option_generator():
    for p in [0,1,2,3,4,5,6,255]:
        for o in [0, 1, 15]:
            for f in list(xrange(16)):
                of = (o << 4) | f
                for x in [0,1,128,255]:
                    for l in list(xrange(10)):
                        option_data = chr(p) + chr(of) + l*chr(x)
                        option = b'\x44' + chr(2 + len(option_data)) + option_data
                        yield option

le_gen = option_generator()

class Ip6Chaff(Mod):
    name = "ip6_chaff"
    usage = "ip6_chaff [dup|conf [/path/to/conf|@conf_var]] [before|after|sandwich]"
    description = """Interleave  IPv6  packets in the queue with duplicate
              IPv6 packets containing  different  payloads. Insert the new
              chaffed packet before, after or sandwich the original packet.
              (Default: before)."""
    DUP = 1
    CONF = 2

    TOP = 1
    BOTTOM = 2
    OUTSIDE = 3

    def parse_args(self, args):
        self.type = None
        self.position = Ip6Chaff.TOP

        if len(args) == 0:
            raise Mod.ArgumentException(self)
        if args[0] == "dup":
            self.type = Ip6Chaff.DUP
        elif args[0] == "conf":
            self.type = Ip6Chaff.CONF
            conf_path = args[1]
            self.rules = parse_conf_file(conf_path)
        else:
            raise Mod.ArgumentException(self)

        if len(args) > 1 or (self.type == Ip6Chaff.CONF and len(args) > 2):
            if args[-1] == "top" or args[-1] == "before":
                self.position = Ip6Chaff.TOP
            elif args[-1] == "bottom" or args[-1] == "after":
                self.position = Ip6Chaff.BOTTOM
            elif args[-1] == "outside" or args[-1] == "sandwich":
                self.position = Ip6Chaff.OUTSIDE
            else:
                raise Mod.ArgumentException(self)

    def apply(self, packets):
        pkts = []
        for packet in packets:
            if not Ip6Chaff.should_chaff(packet):
                pkts.append(packet)
                continue

            # zeros are eaiser to identify when debugging
            # dummy_payload = ''.join('\x00' for _ in xrange(len(packet.data)))
            dummy_payload = ''.join(random.choice(string.lowercase) for _ in xrange(len(packet.data)))

            new_packet = IP6(str(packet))
            new_packet.ts = packet.ts
            new_packet.data = dummy_payload

            new_packets = [new_packet]

            if self.type == Ip6Chaff.DUP:
                Ip6Chaff.do_dup(new_packet)
            elif self.type == Ip6Chaff.CONF:
                Ip6Chaff.do_conf(new_packets, self.rules)

            if self.position == Ip6Chaff.TOP:
                pkts.extend(new_packets)
                pkts.append(packet)
            elif self.position == Ip6Chaff.BOTTOM:
                pkts.append(packet)
                pkts.extend(new_packets)
            else: # self.position == IpChaff.OUTSIDE
                pkts.extend(new_packets)
                pkts.append(packet)
                pkts.extend(new_packets)

        del packets[:]
        packets.extend(pkts)

    @staticmethod
    def should_chaff(packet):
        ip = packet
        fh = packet.extension_hdrs.get(44)

        return (not (fh is not None and fh.m_flag and (fh.frag_off == 0)) and # Don't chaff first fragments.
            not (fh is not None and fh.m_flag == 0 and fh.frag_off != 0) and # Don't chaff last fragments (not inclusive of nonfragmented IP packets).
            not len(ip.data) == 0)

    @staticmethod
    def do_dup(packet):
        packet.ts += 0.000001

    @staticmethod
    def do_conf(packets, rules):
        for rule in rules:
            print("Applying {0} to {1} packets.".format(rule.name, len(packets)))
            rule.apply(packets)
