from scapywrapper.utilities.loggable import Loggable


class BasePacket(Loggable):

    def __init__(self, packet_data):
        Loggable.__init__(self, self.__class__.__name__)
        self.packet_data = packet_data
        print(self.log_me())

    def get_packet_time(self):
        return None
