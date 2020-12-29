from random import getrandbits
from copy import copy

from .mod import Mod, recalculate_checksums


class Dup(Mod):
    name = "dup"
    usage = "dup first|last|random|<idx> <prob-%>"
    description = """Duplicate  the  first, last, or a randomly selected
              packet from the queue with a probability of  prob-%
              percent."""

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
            self.which = Dup.FIRST
        elif args[0] == "last":
            self.which = Dup.LAST
        elif args[0] == "random":
            self.which = Dup.RANDOM
        else:
            self.which = Dup.INDEX
            self.index = int(args[0])

        self.percent = float(args[1])
        if not (0 < self.percent <= 100):
            raise Mod.ArgumentException(self)

    def apply(self, packets):
        if Dup.probable(self.percent):
            if self.which == Dup.FIRST:
                idx = 0
            elif self.which == Dup.LAST:
                idx = len(packets) - 1
            elif self.which == Dup.RANDOM:
                idx = getrandbits(32) % len(packets)
            else:
                idx = self.index

            if len(packets) > idx >= -len(packets):
                Dup.duplicate_and_insert(packets, idx)

    @staticmethod
    def probable(percent):
        return percent == 100 or percent >= (getrandbits(16) % 100)

    @staticmethod
    def duplicate_and_insert(packets, src_idx, after=True):
        pkt = packets[src_idx]
        dup = copy(pkt)
        packets.insert(src_idx+1, dup)
