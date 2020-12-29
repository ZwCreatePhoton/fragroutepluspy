from random import getrandbits
from copy import copy

from .mod import Mod, parse_conf_file


class Apply(Mod):
    name = "apply"
    usage = "apply first|last|random|<idx> <prob-%> [/path/to/conf|@conf_var]"
    description = """Apply a configuration to the first, last, or a randomly
              selected packet from the queue with a probability
              of prob-% percent."""

    FIRST = 1
    LAST = 2
    RANDOM = 3
    INDEX = 4

    def parse_args(self, args):
        self.which = None
        self.percent = None
        self.index = None
        self.rules = []

        if len(args) != 3:
            raise Mod.ArgumentException(self)

        if args[0] == "first":
            self.which = Apply.FIRST
        elif args[0] == "last":
            self.which = Apply.LAST
        elif args[0] == "random":
            self.which = Apply.RANDOM
        else:
            self.which = Apply.INDEX
            self.index = int(args[0])

        self.percent = float(args[1])
        if not (0 < self.percent <= 100):
            raise Mod.ArgumentException(self)

        conf_path = args[2]
        self.rules = parse_conf_file(conf_path)

    def apply(self, packets):
        if Apply.probable(self.percent):
            if self.which == Apply.FIRST:
                idx = 0
            elif self.which == Apply.LAST:
                idx = len(packets) - 1
            elif self.which == Apply.RANDOM:
                idx = getrandbits(32) % len(packets)
            else:
                idx = self.index

            if len(packets) > idx >= -len(packets):
                pkts = [packets[idx]]
                Apply.do_conf(pkts, self.rules)
                packets.pop(idx)
                packets[idx:idx] = pkts


    @staticmethod
    def probable(percent):
        return percent == 100 or percent >= (getrandbits(16) % 100)

    @staticmethod
    def do_conf(packets, rules):
        for rule in rules:
            print("Applying {0} to {1} packets.".format(rule.name, len(packets)))
            rule.apply(packets)
