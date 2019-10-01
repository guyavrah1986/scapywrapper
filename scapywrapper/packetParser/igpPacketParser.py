from scapy.layers.l2 import Ether

from scapywrapper.utilities.loggable import Loggable
from scapywrapper.packetParser.igpPacketParserInterface import IgpPacketParserInterface

# NOTE!! Even though this import seems to be redundant, keep it anyways cause otherwise the ISIS
# and OSPF packet parsing seems not to work entirely (even though the parsed packets are fine)
from scapy.contrib.isis import *
from scapy.contrib.ospf import *


class IgpPacketParser(Loggable, IgpPacketParserInterface):

    def __init__(self):
        Loggable.__init__(self, self.__class__.__name__)
        print(self.log_me())

    def igp_packet_parser_get_packet_protocol_type(self, packet_data):
        if packet_data is None:
            print(self.log_me() + "got None packet data")
            return None

        ether_pkt = Ether(packet_data)
        if ether_pkt is None:
            print(self.log_me() + "had an error extracting the packet")
            return None

        '''
        print(self.log_me() + "the entire packet (frame) content received is:\n")
        ether_pkt.show()
        for key, val in ether_pkt.fields.items():
            print(str(key) + ":" + str(val))

        if not ether_pkt.haslayer("Ethernet") or not ether_pkt.haslayer("802.3"):
            print(self.log_me() + "the frame is not of ethernet type, ignoring it (not supported)")
            return None
        '''
        # first check the frame fo ISIS header (remember that ISIS does not rely on IP
        # so there is no point to "cast" the frame to an IP packet)
        isis_common_header = "ISIS Common Header"
        if ether_pkt.haslayer(isis_common_header):
            return "ISIS"

        # second check if it is an OSPF packet that DOES ride on IP
        ospf_common_header = "OSPF Header"
        ip_pkt = ether_pkt[IP]

        '''
        ip_pkt.show()
        for key,val in ip_pkt.fields.items():
            print(str(key) + ":" + str(val))
        '''
        if ip_pkt.haslayer(ospf_common_header):
            return "OSPF"

        print(self.log_me() + "packet is not an ISIS nor OSPF control packet")
        return None

