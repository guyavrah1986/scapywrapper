from scapy.utils import RawPcapReader
from scapywrapper.utilities.loggable import Loggable


class PcapFileParser(Loggable):

    def __init__(self, pcap_file_name):
        Loggable.__init__(self, self.__class__.__name__)
        self.pcap_file_name = pcap_file_name
        print(self.log_me() + "got pcap file name:" + self.pcap_file_name)

    def get_specific_packet(self, packet_number):
        print(self.log_me() + "trying to extract packet number:" + str(packet_number))
        count = 0
        for (pkt_data, pkt_metadata) in RawPcapReader(self.pcap_file_name):
            print(self.log_me() + "packet meta data:" + str(pkt_metadata))
            packet_seconds_since_epoc_time_stamp = pkt_metadata.sec
            print(self.log_me() + "packet meta seconds since epoc:" + str(packet_seconds_since_epoc_time_stamp))
            count += 1
            if count == packet_number:
                return pkt_data, packet_seconds_since_epoc_time_stamp

        print(self.log_me() + "packet number:" + str(packet_number) + " does not exist in this pcap file")
        return None
