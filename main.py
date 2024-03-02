from scapy.all import *
from scapy.layers.inet import IP, TCP
import ipaddress


TIMEOUT = 0.5


def is_valid_ip(ip):
    """
    Checks if a string is a valid IP.
    :param ip: The string.
    :type ip: str
    :return: Whether the string is a valid IP address.
    :rtype: bool
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_syn_ack_packet(pack):
    """
    Checks if a packet is SYN + ACK.
    :param pack: The packet.
    :type pack: Packet
    :return: Whether the packet is SYN + ACK.
    :rtype: bool
    """
    if not pack:
        return False
    return 'S' in pack[TCP].flags and 'A' in pack[TCP].flags


def main():
    """
    The main function.
    :return: None.
    """
    target_ip = input('Enter target IP: ')

    if not is_valid_ip(target_ip):
        print('Invalid IP.')
        return

    for i in range(20, 1024):
        syn_packet = IP(dst=target_ip) / TCP(dport=i, flags='S')
        answer_packet = sr1(syn_packet, verbose=False, timeout=TIMEOUT)
        if is_syn_ack_packet(answer_packet):
            print(f'Port {i} is open!')


if __name__ == '__main__':
    assert is_valid_ip('127.0.0.1')
    assert is_valid_ip('1.2.3.4')
    assert not is_valid_ip('256.2.0.1')
    assert not is_valid_ip('hello')
    main()
