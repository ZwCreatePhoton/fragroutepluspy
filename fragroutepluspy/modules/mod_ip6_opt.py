from dpkt.ip6 import EXT_HDRS_CLS

from .mod import Mod, recalculate_checksums


class Ip6Opt(Mod):
    name = "ip6_opt"
    usage = "ip6_opt raw <type> <byte stream> [fragmentable|unfragmentable]"
    description = """Add IPv6 options to every packet. <byte stream> should not include the 'Next Header' field."""

    RAW = 0

    def parse_args(self, args):
        self.type = None
        self.ext_hdr_type = 0
        self.option = None
        self.fragmentable = None

        if len(args) < 2:
            raise Mod.ArgumentException(self)
        if False:
            pass
        elif args[0] == "raw":
            self.type = Ip6Opt.RAW
            self.ext_hdr_type = int(args[1])
            buf = str(args[2]).decode("hex")
            self.option = Ip6Opt.parse_extension_header(self.ext_hdr_type, buf)
        else:
            raise Mod.ArgumentException(self)
        if args[-1].lower().endswith("fragmentable"):
            self.fragmentable = (args[-1].lower() == "fragmentable")

    def apply(self, packets):
        for packet in packets:
            Ip6Opt.add_option(self.ext_hdr_type, self.option, packet, self.fragmentable)

    @staticmethod
    def parse_extension_header(type, buf):
        return ext_hdrs_cls[type](buf)

    @staticmethod
    def add_option(type, option, packet, fragmentable=None):
        # option is of class dpkt.ip6.IP6ExtensionHeader
        # if fragmentable then treat option as payload data instead of extension header

        if fragmentable is None:
            fragmentable = (type > 44)
        option.fragmentable = fragmentable

        packet.extension_hdrs[type] = option
        headers = [packet] + packet.all_extension_headers
        option.nxt = headers[-1].nxt
        headers[-1].nxt = type
        packet.all_extension_headers.append(option)
        packet.plen = packet.plen + len(option)
