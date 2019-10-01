import os
import sys

from scapywrapper.utilities.loggable import Loggable
from scapywrapper.pcapFileParser.pcapFileParser import PcapFileParser
from scapywrapper.packetParser.igpPacketParser import IgpPacketParser

class MainClass(Loggable):

    def __init__(self):
        Loggable.__init__(self, self.__class__.__name__)
        print(self.log_me())

    def create_pcap_file_parser_for_pcap_file(self, pcap_file):
        if pcap_file is None:
            print(self.log_me() + "the pcap file that was provides is None")
            return None

        if not os.path.isfile(pcap_file):
            print(self.log_me() + "the given pcap file does not exist")
            return None

        return PcapFileParser(pcap_file)

    def get_packet_igp_protocol_type(self, packet_data):
        igp_packet_parser = IgpPacketParser()
        return igp_packet_parser.igp_packet_parser_get_packet_protocol_type(packet_data)


if __name__ == "__main__":
    func_name = "main - "
    print(func_name + "start")
    main_obj = MainClass()
    print(func_name + "got command line arguments:\n" + str(sys.argv))
    pcap_file_parser = main_obj.create_pcap_file_parser_for_pcap_file(sys.argv[1])
    packet_num = int(sys.argv[2])
    packet_data = pcap_file_parser.get_specific_packet(packet_num)
    packet_protocol_type = main_obj.get_packet_igp_protocol_type(packet_data)
    if packet_protocol_type is not None:
        print(func_name + "the packet is of type:" + packet_protocol_type)

    print(func_name + "end")
