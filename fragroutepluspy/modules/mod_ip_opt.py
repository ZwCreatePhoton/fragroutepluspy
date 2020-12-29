import socket

from dpkt.ip import IP_OPT_LEN, IP_ADDR_LEN

from .mod import Mod, recalculate_checksums


class IpOpt(Mod):
    name = "ip_opt"
    usage = "ip_opt [lsrr|ssrr <ptr> <ip-addr> ...] | [raw <byte stream>]"
    description = """Add IP options to every packet, to enable loose  or
              strict  source  routing or raw options as hex bytes.
              The route should be specified as  list  of  IP
              addresses,  and  a  bytewise pointer  into  them
              (e.g. the minimum ptr value is 4). """

    LSRR = 1
    SSRR = 2
    RAW = 0

    def parse_args(self, args):
        self.type = None
        self.ptr = None
        self.iplist = []
        self.len = 0
        self.option = ''

        if len(args) < 2:
            raise Mod.ArgumentException(self)
        if args[0] == "lsrr":
            self.type = IpOpt.LSRR
            pointer = int(args[1])
            addresses = args[2:]
            self.option = IpOpt.construct_record_route("\x83", pointer, addresses)
        elif args[0] == "ssrr":
            self.type = IpOpt.SSRR
            pointer = int(args[1])
            addresses = args[2:]
            self.option = IpOpt.construct_record_route("\x89", pointer, addresses)
        elif args[0] == "raw":
            self.type = IpOpt.RAW
            self.option = str(args[1]).decode("hex")
        else:
            raise Mod.ArgumentException(self)


    @staticmethod
    def construct_record_route(type, pointer, addresses):
        data_len = 1 + IP_ADDR_LEN * len(addresses)
        option = type
        option += chr(2 + data_len)
        option += chr(pointer)
        option += ''.join(socket.inet_aton(a) for a in addresses)
        return option

    def apply(self, packets):
        for packet in packets:

            # if not IpOpt.should_add_option(packet):
            if not True:
                continue

            IpOpt.add_option(self.option, packet)


    @staticmethod
    def add_option(option, packet):
        # option is raw bytes of IP option

        # does not check if option offset extends past the maximum allowed value. TODO: add the check?

        # assumption: opts is aligned before adding this option
        packet.opts += option + b"\x01" * ((4 - (len(option) % 4)) % 4)  # pad to 4 byte alignment
        # due to the assumption, opts is still aligned to 4 bytes
        packet.hl = 5 + len(packet.opts) // 4

        recalculate_checksums(packet)
