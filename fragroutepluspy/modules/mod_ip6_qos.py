from .mod import Mod


class Ip6Qos(Mod):
    name = "ip6_qos"
    usage = "ip6_qos <tc> <fl>"
    description = """Set the IPv6 quality-of-service traffic class and flow label to tc and fl"""

    def parse_args(self, args):
        self.tc = 0
        self.fl = 0

        if len(args) != 2:
            raise Mod.ArgumentException(self)
        try:
            self.tc = int(args[0])
            assert 0 <= self.tc <= 255
        except:
            raise Mod.ArgumentException(self, "tc value must be between 0 and 255 inclusive")
        try:
            self.fl = int(args[1])
            assert 0 <= self.fl <= 1048575
        except:
            raise Mod.ArgumentException(self, "fl value must be between 0 and 1048575 inclusive")

    def apply(self, packets):
        for packet in packets:
            Ip6Qos.set_qos(packet, self.tc, self.fl)

    @staticmethod
    def set_qos(packet, tc, fl):
        packet.fc = tc
        packet.flow = fl
