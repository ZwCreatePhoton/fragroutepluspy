from random import getrandbits

from .mod import Mod

class Drop(Mod):
    name = "drop"
    usage = "drop first|last|random|<idx> <prob-%>"
    description = """Drop the first, last, or a randomly selected packet
              from the queue with a probability  of  prob-%  per-
              cent."""

    FIRST = 1
    LAST = 2
    RANDOM = 3
    INDEX = 4

    def parse_args(self, args):
        self.which = None
        self.percent = None
        self.index = None

        if len(args) != 2:
            raise Mod.ArgumentException(self)

        if args[0] == "first":
            self.which = Drop.FIRST
        elif args[0] == "last":
            self.which = Drop.LAST
        elif args[0] == "random":
            self.which = Drop.RANDOM
        else:
            self.which = Drop.INDEX
            self.index = int(args[0])

        self.percent = float(args[1])
        if not (0 < self.percent <= 100):
            Mod.ArgumentException(self)

    def apply(self, packets):
        if Drop.probable(self.percent):
            if self.which == Drop.FIRST:
                idx = 0
            elif self.which == Drop.LAST:
                idx = len(packets) - 1
            elif self.which == Drop.RANDOM:
                idx = getrandbits(32) % len(packets)
            else:
                idx = self.index

            if len(packets) > idx >= -len(packets):
                Drop.drop_packet(packets, idx)

    @staticmethod
    def probable(percent):
        return percent == 100 or percent >= (getrandbits(16) % 100)

    @staticmethod
    def drop_packet(packets, idx):
        packets.pop(idx)
