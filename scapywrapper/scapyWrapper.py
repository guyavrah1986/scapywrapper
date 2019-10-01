#########################################################################################
#########################################################################################
# 0) This is a quick and basic how-to regarding the usage in scapy library.
#
# 1) Installation (Python 3, Ubuntu 18.04):
# ----------------------------------------
# a) pip3 install scapy
# b) to verify it is installed correctly:
# python3 -c "import scapy"
# echo $? (output should be "0")
#########################################################################################
#########################################################################################
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether

from learnPython.scapyWrapper.pcapFileParser import PcapFileParser
from learnPython.scapyWrapper.basePacketParser import BasePacketParser

# NOTE!! Even though this import seems to be redundant, keep it anyways cause otherwise the ISIS
# packet parsing seems not to work entirely.
from scapy.contrib.isis import absolute_import


def scapy_usage_example(argv):
    func_name = "scapy_usage_example - "
    print(func_name + "start")
    pcap_file_name = argv[0]
    print(func_name + "got pcap file name:" + pcap_file_name)
    #process_pcap(pcap_file_name)
    pcap_file_parser = PcapFileParser(pcap_file_name)
    packet_to_analyze_number = int(argv[1])
    packet_data_to_analyze = pcap_file_parser.get_specific_packet(packet_to_analyze_number)
    if packet_data_to_analyze is None:
        print(func_name + "the given pcap file did not contain the " + str(packet_to_analyze_number))
        return 1

    base_packet = BasePacketParser(packet_data_to_analyze)
    packet_time = base_packet.packet_parser_get_packet_time()
    print(func_name + "packet time is:" + str(packet_time))
    return 0


def process_pcap(pcap_file_name):
    func_name = "process_pcap - "
    print(func_name + "opening file:" + pcap_file_name)
    count = 0
    interesting_packet_count = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_file_name):
        count += 1

        ether_pkt = Ether(pkt_data)
        '''
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue
        '''
        print(func_name + "packet[" + str(count) + "] content:\n")
        #print(ether_pkt.show())
        isis_common_header = "ISIS Common Header"

        for key,val in ether_pkt.fields.items():
            print(str(key) + ":" + str(val))

        if not ether_pkt.haslayer(isis_common_header):
            print(func_name + "packet[" + str(count) + "] is NOT an ISIS packet, ignore it")
            continue

        isis_hello_pdu_type_num = 17
        isis_common_header_feilds = ether_pkt.getlayer(isis_common_header).fields
        for key,val in isis_common_header_feilds.items():
            print(str(key) + ":" + str(val))
            if val == isis_hello_pdu_type_num:
                print(func_name + "packet[" + str(count) + "] is ISIS Hello PDU")

        '''
        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue
        '''
