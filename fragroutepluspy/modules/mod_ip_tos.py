from dpkt.ip import IP

from .mod import Mod, recalculate_checksums


class IpTos(Mod):
    name = "ip_tos"
    usage = "ip_tos <tos>"
    description = """Set the IP type-of-service bits for every packet to
              tos."""

    def parse_args(self, args):
        self.tos = 0

        if len(args) != 1:
            raise Mod.ArgumentException(self)
        try:
            self.tos = int(args[0])
            assert 0 <= self.tos <= 255
        except:
            raise Mod.ArgumentException(self, "tos value must be between 0 and 255 inclusive")

    def apply(self, packets):
        for packet in packets:
            IpTos.set_tos(packet, self.tos)

    @staticmethod
    def set_tos(packet, tos):
        packet.tos = tos
        recalculate_checksums(packet, calc_tl_sum=False)
