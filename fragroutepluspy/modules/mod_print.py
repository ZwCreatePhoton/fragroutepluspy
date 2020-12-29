from socket import AF_INET, AF_INET6, inet_ntop

from dpkt.ip import IP_PROTO_TCP

from .mod import Mod

class Print(Mod):
    name = "print"
    usage = "print"
    description  = """Print  each  packet  in  the queue in tcpdump-style
              format."""

    def parse_args(self, args):
        pass

    def print_ip(self, packet):
        ip = packet
        print('IP: %s -> %s   (id=%x len=%d ttl=%d tos=%d DF=%d MF=%d offset=%d sum=%x)' % (
        inet_ntop(AF_INET, ip.src), inet_ntop(AF_INET, ip.dst), ip.id, ip.len, ip.ttl, ip.tos, ip.df, ip.mf, ip.offset,
        ip.sum))

    def print_ip6(self, packet):
        ip6 = packet
        fh = packet.extension_hdrs.get(44)
        fragment_part = ""
        if fh is not None:
            fragment_part = "(id=%x MF=%d offset=%d)" % (fh.id, fh.m_flag, fh.frag_off)
        print('IP6: %s -> %s (fc=%d flow=%x plen=%d nxt=%d hlim=%d)' % (inet_ntop(AF_INET6, ip6.src), inet_ntop(AF_INET6, ip6.dst), ip6.fc, ip6.flow, ip6.plen, ip6.nxt, ip6.hlim) + fragment_part)
        if ip6.all_extension_headers:
            for ext_hdr in ip6.all_extension_headers:
                print("  " + repr(ext_hdr))

    def print_data(self, data):
        print(data)

    def apply(self, packets):
        for packet in packets:
            ip = packet

            if ip.v == 4:
                self.print_ip(ip)
            else:
                self.print_ip6(ip)
            self.print_data('\t' + repr(ip.data))
