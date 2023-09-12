
#include <iostream>
#include <vector>
#include "pcap.h"
#include "time.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "ArpLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "UdpLayer.h"

class Machine {
public:

  Machine() {left = NULL; right = NULL; }

  void set_left(Machine* left) { this->left = left; }
  void set_right(Machine* right) { this->right = right; }

  virtual void recieve_from_left(const u_char* packet, int size) = 0;
  virtual void recieve_from_right(const u_char* packet, int size) = 0;

protected:

  Machine* left;
  Machine* right;

};

class Wire : public Machine {
public:

  Wire() : Machine::Machine() {}

  void recieve_from_left(const u_char* packet, int size) override { 
    right->recieve_from_left(packet, size);
  }

  void recieve_from_right(const u_char* packet, int size) override { 
    left->recieve_from_right(packet, size);
  }

};

class EndPoint : public Machine {
public:

  EndPoint(pcap_t* handle) : handle(handle), Machine::Machine() {}

  void recieve_from_left(const u_char* packet, int size) override { 
    if (right == NULL) {
      if (pcap_sendpacket(handle, packet, size) != 0) {
        std::cout << pcap_geterr(handle) << std::endl;
      }
    }
    else {
      right->recieve_from_left(packet, size);
    }
  }

  void recieve_from_right(const u_char* packet, int size) override { 
    if (left == NULL) {
      if (pcap_sendpacket(handle, packet, size) != 0) {
        std::cout << pcap_geterr(handle) << std::endl;
      }
    }
    else {
      left->recieve_from_right(packet, size);
    }
  }

private:

  pcap_t* handle;

};

class ArpResponder : public Machine {
public:

  ArpResponder(std::string target_ip, std::string target_mac) : target_ip(target_ip), target_mac(target_mac), Machine::Machine() {}

  void recieve_from_left(const u_char* packet, int size) override { 
    check_arp(packet, size, "left");
    right->recieve_from_left(packet, size);
  }

  void recieve_from_right(const u_char* packet, int size) override { 
    check_arp(packet, size, "right");
    left->recieve_from_right(packet, size);
  }

  virtual void response(pcpp::Packet parsed, int size, const std::string& dir) = 0;

protected:

  std::string target_ip;
  std::string target_mac;

private:

  void check_arp(const u_char* packet, int size, const std::string& dir) {

    timespec ts;
    timespec_get(&ts, TIME_UTC);
    pcpp::RawPacket raw((const uint8_t*)packet, size, ts, false);
    pcpp::Packet parsed(&raw);

    pcpp::EthLayer* eth = parsed.getLayerOfType<pcpp::EthLayer>(); 
    if (eth == NULL) { return; }

    if (eth->getEthHeader()->etherType == 1544) {

      pcpp::ArpLayer* arp = parsed.getLayerOfType<pcpp::ArpLayer>(); 

      if (arp->getTargetIpAddr() == target_ip) {

        pcpp::EthLayer eth_response(target_mac, eth->getSourceMac(), 0x0806);
        pcpp::ArpLayer arp_response(pcpp::ARP_REPLY, target_mac, eth->getSourceMac(), arp->getTargetIpAddr(), arp->getSenderIpAddr());

        pcpp::Packet parsed_response;
        parsed_response.addLayer(&eth_response, false);
        parsed_response.addLayer(&arp_response, false);
        parsed_response.computeCalculateFields();

        pcpp::RawPacket* raw_response = parsed_response.getRawPacket();
        const uint8_t* data = raw_response->getRawData();
        const u_char* response = (const u_char*) data;

        if (dir == "left") {
          left->recieve_from_right(response, size);
        }
        else {
          right->recieve_from_left(response, size);
        }

      } 

    }
    else if (eth->getDestMac() == target_mac) { response(parsed, size, dir); }

  }

};

class IcmpResponder : public ArpResponder {
public:

  IcmpResponder(std::string target_ip, std::string target_mac) : ArpResponder::ArpResponder(target_ip, target_mac) {}

  void response(pcpp::Packet parsed, int size, const std::string& dir) override {

    pcpp::EthLayer* eth = parsed.getLayerOfType<pcpp::EthLayer>(); 
    pcpp::IPv4Layer* ipv4 = parsed.getLayerOfType<pcpp::IPv4Layer>();

    if (ipv4 == NULL) { return; }
    if (ipv4->getIPv4Header()->protocol != 1) { return; }
    if (ipv4->getDstIPAddress() != target_ip) { return; }

    pcpp::IcmpLayer* icmp = parsed.getLayerOfType<pcpp::IcmpLayer>();
    if (icmp == NULL) { return; }

    pcpp::EthLayer eth_response(eth->getDestMac(), eth->getSourceMac(), 0x0800);
    pcpp::IPv4Layer ipv4_response(ipv4->getDstIPv4Address(), ipv4->getSrcIPv4Address());
    pcpp::IcmpLayer icmp_response;
    pcpp::icmp_echo_request* request_echo = icmp->getEchoRequestData();

    static int k = 0;
    icmp_response.setEchoReplyData(49273, ++k, std::time(0), request_echo->data, request_echo->dataLength);
    ipv4_response.getIPv4Header()->timeToLive = ipv4->getIPv4Header()->timeToLive;

    pcpp::Packet parsed_response;
    parsed_response.addLayer(&eth_response, false);
    parsed_response.addLayer(&ipv4_response, false);
    parsed_response.addLayer(&icmp_response, false);
    parsed_response.computeCalculateFields();

    pcpp::RawPacket* raw_response = parsed_response.getRawPacket();
    const uint8_t* data = raw_response->getRawData();
    const u_char* response = (const u_char*) data;

    if (dir == "left") {
      left->recieve_from_right(response, size);
    }
    else {
      right->recieve_from_left(response, size);
    }

  }

};

class UdpResponder : public ArpResponder {
public:

  UdpResponder(std::string target_ip, std::string target_mac) : ArpResponder::ArpResponder(target_ip, target_mac) {}

  void response(pcpp::Packet parsed, int size, const std::string& dir) override {

    pcpp::EthLayer* eth = parsed.getLayerOfType<pcpp::EthLayer>(); 
    pcpp::IPv4Layer* ipv4 = parsed.getLayerOfType<pcpp::IPv4Layer>();

    if (ipv4 == NULL) { return; }
    if (ipv4->getIPv4Header()->protocol != 17) { return; }
    if (ipv4->getDstIPAddress() != target_ip) { return; }

    pcpp::UdpLayer* udp = parsed.getLayerOfType<pcpp::UdpLayer>();
    if (udp == NULL) { return; }

    pcpp::EthLayer eth_response(eth->getDestMac(), eth->getSourceMac(), 0x0800);
    pcpp::IPv4Layer ipv4_response(ipv4->getDstIPv4Address(), ipv4->getSrcIPv4Address());
    pcpp::udphdr* udp_header = udp->getUdpHeader();
    pcpp::UdpLayer udp_response(udp_header->portDst, udp_header->portSrc);

    ipv4_response.getIPv4Header()->timeToLive = ipv4->getIPv4Header()->timeToLive;

    pcpp::Packet parsed_response;
    parsed_response.addLayer(&eth_response, false);
    parsed_response.addLayer(&ipv4_response, false);
    parsed_response.addLayer(&udp_response, false);
    parsed_response.computeCalculateFields();

    pcpp::RawPacket* raw_response = parsed_response.getRawPacket();
    const uint8_t* data = raw_response->getRawData();
    const u_char* response = (const u_char*) data;

    if (dir == "left") {
      left->recieve_from_right(response, size);
    }
    else {
      right->recieve_from_left(response, size);
    }

  }

};

int main(int argc, char* argv[]) {

  pcap_t* left = pcap_open_live(
    argv[1], BUFSIZ, 1, -1, NULL
  );

  pcap_t* right = pcap_open_live(
    argv[2], BUFSIZ, 1, -1, NULL
  );

  std::vector<Machine*> line;
  EndPoint left_end_point(left), right_end_point(right);
  UdpResponder udp_responder("10.0.0.5", "86:7e:fa:6e:38:4a");
  IcmpResponder icmp_responder("10.0.0.6", "86:7e:fa:6e:38:4b");

  line.push_back(&left_end_point);
  for (int i = 0; i < 3; i++) {
    line.push_back(new Wire);
  }
  line.push_back(&udp_responder);
  for (int i = 0; i < 3; i++) {
    line.push_back(new Wire);
  }
  line.push_back(&icmp_responder);
  for (int i = 0; i < 3; i++) {
    line.push_back(new Wire);
  }
  line.push_back(&right_end_point);

  int len = line.size();
  for (int i = 1; i < len; i++) {
    line[i]->set_left(line[i - 1]);
  }
  for (int i = len - 2; i >= 0; i--) {
    line[i]->set_right(line[i + 1]);
  }

  while (true) {
    const u_char* packet;
    struct pcap_pkthdr* packet_header;
    if (pcap_next_ex(left, &packet_header, &packet) == 1) {
      line[0]->recieve_from_left(packet, packet_header->len);
    }
    if (pcap_next_ex(right, &packet_header, &packet) == 1) {
      line[len - 1]->recieve_from_right(packet, packet_header->len);
    }
  }

  return 0;

}
