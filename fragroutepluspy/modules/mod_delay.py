from random import getrandbits

from dpkt.ip import IP_PROTO_TCP
from dpkt.tcp import TCP, TH_FIN

from .mod import Mod


class Delay(Mod):
    name = "delay"
    usage = "delay first|last|random|<idx> <ms>"
    description = """Delay  the  delivery  of the first, last, or a ran-
              domly selected packet from the  queue  by  ms  mil-
              liseconds."""

    FIRST = 1
    LAST = 2
    RANDOM = 3
    INDEX = 4

    def parse_args(self, args):
        self.sec = None
        self.index = None

        if len(args) != 2:
            raise Mod.ArgumentException(self)

        if args[0] == "first":
            self.which = Delay.FIRST
        elif args[0] == "last":
            self.which = Delay.LAST
        elif args[0] == "random":
            self.which = Delay.RANDOM
        else:
            self.which = Delay.INDEX
            self.index = int(args[0])
        try:
            self.sec = float(args[1]) / 1000.0
            assert 0 < self.sec
        except:
            raise Mod.ArgumentException(self, "delay must be at least 0 milliseconds")

    def apply(self, packets):

        if self.which == Delay.FIRST:
            idx = 0
        elif self.which == Delay.LAST:
            idx = len(packets) - 1
        elif self.which == Delay.RANDOM:
            idx = getrandbits(32) % len(packets)
        else:
            idx = self.index

        if len(packets) > idx >= -len(packets):
            Delay.delay_packet(packets[idx], self.sec)

    @staticmethod
    def delay_packet(pkt, sec):
        pkt.ts += sec
