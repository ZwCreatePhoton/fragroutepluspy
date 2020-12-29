from abc import ABCMeta, abstractmethod
import shlex
import os

from dpkt.ip import IP
from dpkt.ip6 import IP6

class classproperty(object):

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, owner):
        return self.f(owner)


class Mod(object):
    __metaclass__ = ABCMeta

    _name = ""
    _usage = ""
    _description = ""

    def __init__(self, *args):
        args = [str(a) for a in args]
        if args and args[0] == self.name:
            args.pop(0)

        for i in range(len(args)):
            if args[i][0] == "$":
                try:
                    args[i] = os.environ[args[i][1:]]
                except:
                    raise Mod.ArgumentException(self, "Environment variable {0} not found".format(args[i][1:]))

        self.cmd = " ".join([self.name] + args)
        self.parse_args(args)

    @abstractmethod
    def parse_args(self, args):
        """

        :type args: list of str
        """
        pass

    @abstractmethod
    def apply(self, packets):
        """

        :type packets: list of dpkt IP packets
        """
        pass

    @classproperty
    def mod(cls):
        return cls

    @classproperty
    def name(cls):
        return cls._name.lower()

    @classproperty
    def usage(cls):
        return cls._usage

    @classproperty
    def description(cls):
        return cls._description

    class ArgumentException(ValueError):
        def __init__(self, cls, extra=""):
            self.value = "invalid arguments for directive '{0}'".format(cls.name)
            if extra:
                self.value += "\n{0}".format(extra)

        def __str__(self):
            return self.value


def find(directive):
    for m in Mod.__subclasses__():
        mod_name = directive.lower()
        # backwards capability for directives ip_frag6 and ip_chaff6
        if mod_name.startswith("ip_") and mod_name.endswith("6"):
            mod_name = "ip6_" + mod_name.split("_")[1][:-1]
        if mod_name == m.name.lower():
            return m
    raise KeyError("unknown directive '{0}'".format(directive))


sub_confs = {}


def parse_conf(conf):
    rules = []

    lines = [line.rstrip('\n') for line in conf.splitlines()]

    i = 0
    while i < len(lines):
        line = lines[i]
        if not line:
            i += 1
            continue
        if line.startswith("#"):
            if line.startswith("#define"):
                j = i
                conf_name = line.split()[1]
                nested_defines = -1
                while i < len(lines):
                    if lines[i].startswith("#define") and len(lines[i].split()) < 3:
                        # dont up counter for single line defines. e.g. "#define foo bar"
                        nested_defines += 1
                    if lines[i].startswith("#enddefine"):
                        if nested_defines == 0:
                            conf_value = "\n".join(lines[j+1:i])
                            sub_confs[conf_name] = conf_value
                            break
                        else:
                            nested_defines -= 1
                    i += 1
                else:
                    raise Exception('No corresponding "#enddefine" for "{}"'.format(line))
                i += 1
                continue
            else:
                i += 1
                continue

        directive = shlex.split(line)
        name, args = directive[0], directive[1:]
        try:
            m = find(name)
            rule = m(*args)
            rules.append(rule)
        except Exception as e:
            print(e)
            raise
        i += 1

    return rules


def parse_conf_file(conf_file):
    """

    :type config: filepath to configuration file or @variable to configuration
    """

    if conf_file.startswith("@"): # conf_file is an @variable
        conf = sub_confs[conf_file[1:]]
    else:  # conf_file is a filepath
        with open(conf_file, 'r') as config:
            conf = config.read()

    return parse_conf(conf)


def recalculate_checksums(packet, calc_tl_sum=True):
    ip = packet
    tl = packet.data
    if ip.v == 4:
        ip.sum = 0
        ip.len = 0
    else:
        # length is recalculated for IP but not for IPv6
        ip.plen = len(ip.data)
        # is it neccessary to add length from the ext headers too?

    try:
        if calc_tl_sum:
            tl.sum = 0
    except Exception as e:
        pass

    if ip.v == 4:
        ip2 = IP(bytes(ip))  # recalculates checksums while packing (in __bytes__) and unpacks (IP)
    else:
        ip2 = IP6(bytes(ip))
    ip.data = ip2.data
    if ip.v == 4:
        ip.sum = ip2.sum
        ip.len = ip2.len
