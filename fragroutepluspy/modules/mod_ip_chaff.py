from copy import copy
import random, string

from dpkt.ip import IP

from .mod import Mod, recalculate_checksums, parse_conf_file


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

class IpChaff(Mod):
    name = "ip_chaff"
    usage = "ip_chaff [dup|opt|<ttl>|cksum|conf [/path/to/conf|@conf_var]] [before|after|sandwich]"
    description = """Interleave  IP  packets in the queue with duplicate
              IP packets containing  different  payloads,  either
              scheduled  for  later delivery, carrying invalid IP
              options, or bearing short time-to-live values.
              Insert the new chaffed packet before, after, or
              sandwich the original packet. (Default: before)"""
    DUP = 1
    OPT = 2
    TTL = 3
    CKSUM = 4
    DEV = 0
    CONF = 5

    TOP = 1
    BOTTOM = 2
    OUTSIDE = 3

    def parse_args(self, args):
        self.type = None
        self.ttl = None
        self.position = IpChaff.TOP

        if len(args) == 0:
            raise Mod.ArgumentException(self)
        if args[0] == "dup":
            self.type = IpChaff.DUP
        elif args[0] == "opt":
            self.type = IpChaff.OPT
        elif args[0] == "cksum":
            self.type = IpChaff.CKSUM
        elif args[0] == "conf":
            self.type = IpChaff.CONF
            conf_path = args[1]
            self.rules = parse_conf_file(conf_path)
        elif 0 < int(args[0]) < 256:
            self.type = IpChaff.TTL
            self.ttl = int(args[0])
        else:
            raise Mod.ArgumentException(self)

        if len(args) > 1 or (self.type == IpChaff.CONF and len(args) > 2):
            if args[-1] == "top" or args[-1] == "before":
                self.position = IpChaff.TOP
            elif args[-1] == "bottom" or args[-1] == "after":
                self.position = IpChaff.BOTTOM
            elif args[-1] == "outside" or args[-1] == "sandwich":
                self.position = IpChaff.OUTSIDE
            else:
                raise Mod.ArgumentException(self)

    def apply(self, packets):
        pkts = []
        for packet in packets:
            if not IpChaff.should_chaff(packet):
                pkts.append(packet)
                continue

            # zeros are eaiser to identify when debugging
            # dummy_payload = ''.join('\x00' for _ in xrange(len(packet.data)))
            dummy_payload = ''.join(random.choice(string.lowercase) for _ in xrange(len(packet.data)))

            new_packet = IP(str(packet))
            new_packet.ts = packet.ts
            new_packet.data = dummy_payload

            new_packets = [new_packet]

            if self.type == IpChaff.DUP:
                IpChaff.do_dup(new_packet)
            elif self.type == IpChaff.OPT:
                IpChaff.do_opt(new_packet)
            elif self.type == IpChaff.CKSUM:
                IpChaff.do_cksum(new_packet)
            elif self.type == IpChaff.CONF:
                IpChaff.do_conf(new_packets, self.rules)
            elif self.type == IpChaff.TTL:
                IpChaff.do_ttl(new_packet, self.ttl)

            if self.position == IpChaff.TOP:
                pkts.extend(new_packets)
                pkts.append(packet)
            elif self.position == IpChaff.BOTTOM:
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

        return (not ((ip.mf == 1) and (ip.offset == 0)) and # Don't chaff first fragments.
            not (ip.mf == 0 and ip.offset != 0) and # Don't chaff last fragments (not inclusive of nonfragmented IP packets).
            not len(ip.data) == 0)

    @staticmethod
    def do_dup(packet):
        packet.ts += 0.000001

    @staticmethod
    def do_opt(packet):
        packet.opts = b'\xa1\xda\x8b\xa1'
        packet.hl = 6
        recalculate_checksums(packet, calc_tl_sum=False)

    @staticmethod
    def do_ttl(packet, ttl):
        packet.ttl = ttl
        recalculate_checksums(packet, calc_tl_sum=False)

    @staticmethod
    def do_cksum(packet):
        packet.sum = random.getrandbits(16)


    @staticmethod
    def do_conf(packets, rules):
        for rule in rules:
            print("Applying {0} to {1} packets.".format(rule.name, len(packets)))
            rule.apply(packets)
