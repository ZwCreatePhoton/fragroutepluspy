from dpkt.ip import IP

from .mod import Mod, recalculate_checksums


class IpTtl(Mod):
    name = "ip_ttl"
    usage = "ip_ttl <ttl>"
    description = """Set the IP time-to-live value of  every  packet  to
              ttl."""

    def parse_args(self, args):
        self.ttl = None

        if len(args) != 1:
            raise Mod.ArgumentException(self)
        try:
            self.ttl = int(args[0])
            assert 0 <= self.ttl <= 255
        except:
            raise Mod.ArgumentException(self, "ttl value must be between 0 and 255 inclusive")

    def apply(self, packets):
        for packet in packets:
            IpTtl.set_ttl(packet, self.ttl)

    @staticmethod
    def set_ttl(packet, ttl):
        packet.ttl = ttl
        recalculate_checksums(packet, calc_tl_sum=False)
