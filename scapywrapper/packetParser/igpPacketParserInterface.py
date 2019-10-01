import abc


class IgpPacketParserInterface(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def igp_packet_parser_get_packet_protocol_type(self, packet_data):
        """
        :param packet_data: The entire packet data.
        :rtype: Returns a string indicates the type of the IGP that this packet holds: ISIS, OSPF or None if neither
        one of them is the case.
        """
        pass