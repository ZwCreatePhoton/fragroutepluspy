from dpkt.ip import IP, IP_PROTO_TCP
from dpkt.ip6 import IP6
from dpkt.tcp import TCP

from .mod import Mod, recalculate_checksums


class TcpOpt(Mod):
    name = "tcp_opt"
    usage = "tcp_opt mss|wscale size"
    description = """Add  TCP  options  to  every TCP packet, to set the
              maximum segment size or window scaling factor."""
    MSS = 1
    WSCALE = 2

    def parse_args(self, args):
        self.type = None
        self.size = None
        self.option = None

        if len(args) < 2:
            raise Mod.ArgumentException(self)

        if args[0] == "mss":
            self.type = TcpOpt.MSS
            self.size = int(args[1])
            if not (0 < self.size <= 65535):
                raise Mod.ArgumentException(self, "mss <size> must be from 0-65535")
        elif args[0] == "wscale":
            self.opt_type = TcpOpt.WSCALE
            self.size = int(args[1])
            if not (0 < self.size <= 255):
                raise Mod.ArgumentException(self, "wscale <size> must be from 0-255")
        else:
            raise Mod.ArgumentException(self)

        if self.type == TcpOpt.MSS:
            self.option = b'\x02\x04' + chr(self.size // 256) + chr(self.size % 256)
        else: # self.type == TcpOpt.WSCALE
            self.option = b'\x03\x03' + chr(self.size)

    def apply(self, packets):
        for packet in packets:
            if not TcpOpt.should_add_option(packet):
                continue
            TcpOpt.add_option(self.option, packet)

    @staticmethod
    def add_option(option, packet):
        # assumption: header length already a multiple of 4 bytes
        # does not check if option offset extends past the maximum allowed value

        # Replaces option if present
        old_opts = str(packet.data.opts)
        idx = old_opts.find(option[:2])
        if idx != -1: # option already exists
            packet.data.opts = old_opts[:idx] + option + old_opts[idx + len(option):]
        else:
            packet.data.opts += option + b"\x01" * (4 - len(option))  # pad to 4 byte align
            packet.data.off += ((4 - 1) + len(option)) // 4

        recalculate_checksums(packet)

    @staticmethod
    def should_add_option(packet):
        ip = packet
        tl = ip.data

        is_fragmented = False
        if ip.v == 4:
            is_fragmented = not ((packet.mf == 0) and (packet.offset == 0))
        else:
            is_fragmented = packet.extension_hdrs.get(44) is not None


        return (not is_fragmented and # Don't chaff IP fragments.
                ip.p == IP_PROTO_TCP and
                tl and isinstance(tl, TCP)
                )
