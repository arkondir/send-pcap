import socket
import sys
import time
import logging
import threading
from scapy.all import *

__author__ = 'Nikolay Alexeev'
__all__ = ['TcpClient', 'TcpCError']

logger = logging.getLogger("tester")

if sys.version_info < (3, 5):
    print("Error. Use python 3.5 or greater")
    sys.exit(1)


class TcpClient:
    """
    Класс создает TCP клиента, для посылки содержимого сообщений из pcap файла на указанный хост и порт
    """

    def start_client(self):
        """
        Создает tcp клиет и зануляет таймер
        """
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.info("Client started")
        self.timer = 0


    def send_data(self, file, ip, port):
        """
        Создает Thread с методом send_pcap(file, ip, port)

        file - путь до pcap файла
        ip - адрес сервера
        port - порт сервера

        """
        self.tcp_stream = threading.Thread(target=self.send_pcap, args=(file, ip, int(port)))
        self.tcp_stream.start() 
            
    def send_pcap(self, file, ip, port):
        """
        Отсылает содержимое сообщений pcap файла с сохранением временных интервалов на указанный хост и порт


        file - путь до pcap файла
        ip - адрес сервера
        port - порт сервера

        """
        logger.info("Start reading pcap")
        pcap = rdpcap(file)
        logger.info("Succesfull")
        address_to_server = (ip, int(port))
        logger.info("Start sending packets")
        self.client.connect(address_to_server)

        for pkt in pcap:
            if not self.timer:
                self.timer = pkt.time
            else:
                time.sleep(pkt.time - self.timer)
                self.timer = pkt.time
            logger.debug(f"Packet payload:\n{pkt[Raw].load}")
            self.client.send(pkt[Raw].load)

class TcpCError(Exception):
    pass


if __name__ == "__main__":
    a = TcpClient()
    a.start_client()
    a.send_data("data/chain_cfu_B.pcap", 'localhost', "8686")
    #while True:
    #    time.sleep(1)
    #    print("1 sec passed")

# https://github.com/robotframework/robotframework/issues/1792

