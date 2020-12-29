#!/usr/bin/env python2

from os import path
import logging
import time
from multiprocessing import Process
from threading import current_thread
import threading
import atexit
import re
from socket import socket, AF_INET, AF_INET6, SOCK_RAW, IPPROTO_RAW, error as serror, inet_aton, inet_ntoa
import os
import socket

from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.ethernet import Ethernet
from dpkt.pcap import Reader as PcapReader
from dpkt.pcap import Writer as PcapWriter

import modules

# Applies fragroute rules to the packets passed into Fragroute.process
class Fragroute(object):

    DEFAULT_CONF = path.join(path.dirname(__file__), "scripts", "default.conf")

    def __init__(self, dst, conf=DEFAULT_CONF, mac=None, pcap_in=None, pcap_out=None, iface="eth0"):
        self.dst = dst
        self.mac = mac
        self.pcap_in = pcap_in
        self.pcap_out = pcap_out
        self.iface = iface
        self.rules = modules.parse_conf_file(conf)
        print(" -> ".join([rule.cmd for rule in self.rules]))

    @property
    def ip_version(self):
        if is_valid_ipv4(self.dst):
            return 4
        elif is_valid_ipv6(self.dst):
            return 6
        else:
            raise Exception

    # callback for the outgoing packets intercepted to self.dst
    # input: raw IP packet
    def process(self, buf):

        # ensures correct len and checksum (?)
        if self.ip_version == 4:
            packet = IP(buf)
            packet.len = 0
            packet.sum = 0
            packet = IP(str(packet))
        else: # self.ip_version == 6:
            packet = IP6(buf)
            packet = IP6(str(packet))

        packet.ts = 0

        # Only process one TCP segment with data
        # if packet.data.data:
        #     if self.some_flag: return
        #     self.some_flag = True

        packets = [packet]

        # don't manipulate fragmented packets
        is_fragmented = False
        if self.ip_version == 4:
            is_fragmented = not (packet.mf == 0) and (packet.offset == 0)
        else:
            is_fragmented = packet.extension_hdrs.get(44) is not None

        if not is_fragmented:
            for rule in self.rules:
                print("Applying {0} to {1} packets.".format(rule.name, len(packets)))
                rule.apply(packets)

        # maybe should consider sorting packets by ts (delay)
        for pkt in packets:
            print("delay = {0}".format(pkt.ts))
            self.send_outgoing(pkt, pkt.ts)

    def process_pcap(self):
        assert os.path.exists(self.pcap_in), "file {} does not exists".format(self.pcap_in)
        out_f = open(self.pcap_out, "wb")
        pcap_writer = PcapWriter(out_f)

        with open(self.pcap_in, "rb") as in_f:
            pcap_reader = PcapReader(in_f)
            for timestamp, buf in pcap_reader:
                eth = Ethernet(buf)

                def write_outgoing(packet, ts):
                    eth.data = packet
                    pcap_writer.writepkt(str(eth), timestamp)

                fr.send_outgoing = write_outgoing
                ip = eth.data

                if ip.v == 6:
                    dst_addr = socket.inet_ntop(socket.AF_INET6, ip.dst)
                else:
                    dst_addr = socket.inet_ntop(socket.AF_INET, ip.dst)

                if dst_addr == fr.dst:
                    fr.process(str(ip))
                else:
                    pcap_writer.writepkt(str(eth), timestamp)

        pcap_writer.close()
        out_f.close()


    # TODO: remove dependence on Scapy
    def start(self, blocking=True):
        if self.pcap_in and self.pcap_out:
            return self.process_pcap()

        from scapy.all import conf
        from scapy.all import IP as ScapyIP
        from scapy.all import IPv6 as ScapyIP6
        from scapy.all import getmacbyip
        from scapy.all import getmacbyip6

        # force default interface to this interface so that the layer 2 src address will be the address of this interface
        conf.iface = self.iface
        # not required for conf.iface6

        # setup output socket
        try:
            socket = conf.L3socket()
            atexit.register(socket.close)
        except serror as msg:
            print('Socket could not be created. Error Code: {0}. Message: {1}'.format(*msg))
            return

        if self.mac is not None and is_valid_mac(self.mac):
            # put mac+ip in arp/neighbor cache indefinitely
            if self.ip_version == 4:
                conf.netcache.arp_cache[self.dst] = self.mac
                conf.netcache.arp_cache.timeout = None
            else:
                conf.netcache.in6_neighbor[self.dst] = self.mac
                conf.netcache.in6_neighbor.timeout = None
        else:
            # getmacbyip* performs address resolution if the mac is not in Scapy's arp/neighbor cache
            if self.ip_version == 4:
                getmacbyip(self.dst)
            else:
                getmacbyip6(self.dst)

        def send_outgoing(packet, timeout=0):
            if timeout > 0.001: # only worth-wild to delay packets with ~ ms wait times
                print("delaying packet {0} milliseconds".format(timeout * 1000.0))
                # Spawning a new process ended up being faster than spawning a new thread for some reason
                def wait_timeout():
                    time.sleep(timeout)
                    if packet.v == 4:
                        pkt = ScapyIP(bytes(packet))
                    else: # packet.v == 6:
                        pkt = ScapyIP6(bytes(packet))
                    socket.send(pkt)
                t = Process(target=wait_timeout, args=())
                t.start()
            else:
                print("Sending packet...")
                if packet.v == 4:
                    pkt = ScapyIP(bytes(packet))
                else:  # packet.v == 6:
                    pkt = ScapyIP6(bytes(packet))
                socket.send(pkt)

        self.send_outgoing = send_outgoing
        self.intercept_packets(self.dst, self.process, self.ip_version)


    @staticmethod
    def intercept_packets(dst, cb, ip_version=4):
        import nfqueue

        """
        :type dst: hostname
        :type cb:  callback function to process each outgoing raw packet to the host dst
        :type ip_version:   IP version. 4 or 6
        """

        def prepare_callback(payload):
            data = payload.get_data()
            cb(data)
            payload.set_verdict(nfqueue.NF_DROP)

        if ip_version == 4:
            os.system("iptables -F")
            os.system("iptables -X")
            os.system("iptables -A OUTPUT -d {dst} ! -f -j NFQUEUE".format(dst=dst))
        else:
            os.system("ip6tables -F")
            os.system("ip6tables -X")
            os.system("ip6tables -A OUTPUT -d {dst} ! -p icmpv6 -j NFQUEUE".format(dst=dst))
            os.system("ip6tables -A OUTPUT -d {dst} -p icmpv6 --icmpv6-type echo-request -j NFQUEUE".format(dst=dst))
            os.system("ip6tables -A OUTPUT -d {dst} -p icmpv6 --icmpv6-type echo-reply -j NFQUEUE".format(dst=dst))

        q = nfqueue.queue()
        q.open()
        if ip_version == 4:
            q.bind(socket.AF_INET)
        else:
            q.bind(socket.AF_INET6)
        q.set_callback(prepare_callback)
        q.create_queue(0)
        try:
            q.try_run()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(e)
            raise
        finally:
            q.unbind(socket.AF_INET)
            q.close()
            if ip_version == 4:
                os.system('iptables -F')
                os.system('iptables -X')
            else:
                os.system('ip6tables -F')
                os.system('ip6tables -X')


def is_valid_mac(mac):
    """Validates MAC addresses.
    """
    return re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())


def is_valid_ipv4(ip):
    """Validates IPv4 addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None


def is_valid_ipv6(ip):
    """Validates IPv6 addresses.
    """
    pattern = re.compile(r"""
        ^
        \s*                         # Leading whitespace
        (?!.*::.*::)                # Only a single whildcard allowed
        (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
        (?:                         # Repeat 6 times:
            [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
        ){6}                        #
        (?:                         # Either
            [0-9a-f]{0,4}           #   Another group
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
            [0-9a-f]{0,4}           #   Last group
            (?: (?<=::)             #   Colon iff preceeded by exacly one colon
             |  (?<!:)              #
             |  (?<=:) (?<!::) :    #
             )                      # OR
         |                          #   A v4 address with NO leading zeros 
            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            (?: \.
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            ){3}
        )
        \s*                         # Trailing whitespace
        $
    """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
    return pattern.match(ip) is not None


if __name__ == "__main__":

    from sys import argv

    #logger.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger()
    logger.disabled = True

    config_file = Fragroute.DEFAULT_CONF
    host = ""
    mac = None
    infilepath = ""
    outfilepath = ""

    try:
        if (argv[1].lower() == "help" or
                argv[1].lower() == "-h" or
                argv[1].lower() == "--h" or
                argv[1].lower() == "-?" or
                argv[1].lower() == "--?"):
            raise Exception
        elif argv[1] == "-f":
            config_file = argv[2]
            host = argv[3]
            if len(argv) > 4:
                mac = argv[4]

        last_args = argv[-3:]
        if last_args[-3].lower() == "-pcap":
            infilepath = argv[-2]
            outfilepath = argv[-1]

    except Exception as e:
        print("Usage: " + argv[0] + " -f config.conf host [mac] [-pcap infilepath outfilepath]")
        print("Rules:")
        for mod in modules.Mod.__subclasses__():
            print("\t{}\n\t\t{}".format(mod.usage, mod.description))
        exit(1)

    fr = Fragroute(host, config_file, mac, infilepath, outfilepath)
    fr.start()
