from dpkt.tcp import TH_SYN, TH_ACK, TH_FIN, TH_RST, TH_PUSH, TH_CWR, TH_ECE, TH_URG

from .mod import Mod, parse_conf_file


class If(Mod):
    name = "if"
    usage = 'if "(conditional)" [/path/to/true.conf|@conf_var] [/path/to/false.conf|@conf_var]'
    description = """Apply the first conf to incoming traffic if the
              conditional evaluates to true. Otherwise apply the
              second conf."""

    def parse_args(self, args):
        self.conditional = None
        self.true_rules = []
        self.false_rules = []


        if not (len(args) == 2 or len(args) == 3):
            raise Mod.ArgumentException(self)
        try:
            self.conditional = args[0]
        except Exception as e:
            print(e)
        try:
            conf_filepath = args[1]
            self.true_rules = parse_conf_file(conf_filepath)
        except Exception as e:
            print(e)
        try:
            if len(args) == 3:
                conf_filepath = args[2]
                self.false_rules = parse_conf_file(conf_filepath)
        except Exception as e:
            print(e)

    def apply(self, packets):
        pkts = []
        for packet in packets:
            ps = [packet]
            payload = str(packet.data)
            if eval(self.conditional):
                for rule in self.true_rules:
                    print("Applying {0} to {1} packets.".format(rule.name, len(ps)))
                    rule.apply(ps)
            else:
                for rule in self.false_rules:
                    print("Applying {0} to {1} packets.".format(rule.name, len(ps)))
                    rule.apply(ps)
            pkts.extend(ps)

        del packets[:]
        packets.extend(pkts)
