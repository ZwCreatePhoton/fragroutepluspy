import random

from .mod import Mod


class Order(Mod):
    name = "order"
    usage = "order random|reverse"
    description = """Re-order the packets in the queue randomly,  or  in
              reverse."""

    RANDOM = 1
    REVERSE = 2

    def parse_args(self, args):
        self.type = None

        if len(args) != 1:
            raise Mod.ArgumentException(self)
        type = args[0]
        if type == "random":
            self.type = Order.RANDOM
        elif type == "reverse":
            self.type = Order.REVERSE
        else:
            raise Mod.ArgumentException(self)

    def apply(self, packets):
        if self.type == Order.RANDOM:
            Order._random(packets)
        else: # self.type == Order.REVERSE:
            Order._reverse(packets)

    @staticmethod
    def _random(packets):
        random.shuffle(packets)

    @staticmethod
    def _reverse(packets):
        packets.reverse()
