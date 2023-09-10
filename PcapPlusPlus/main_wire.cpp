
#include <iostream>
#include "pcap.h"
#include <vector>

class Machine {
public:
  Machine() {left = NULL; right = NULL; }
  void set_left(Machine* left) { this->left = left; }
  void set_right(Machine* right) { this->right = right; }
  void set_packet(const u_char* packet) { this->packet = packet; }
  const u_char* get_packet() { return packet; }
protected:
  Machine* left;
  Machine* right;
  const u_char* packet;
};

class Wire : public Machine {
public:
  Wire() : Machine::Machine() {}
  void capture_right() {
    if (right != NULL) {
      packet = right->get_packet();
    }
  }
  void capture_left()  {
    if (left != NULL) {
      packet = left->get_packet();
    }
  }
};

void evoke_wires_to_right(std::vector<Wire>& wires) {
  for (int i = 1; i < wires.size(); i++) {
    wires[i].capture_left();
  }
}
void evoke_wires_to_left(std::vector<Wire>& wires) {
  for (int i = wires.size() - 2; i >= 0; i--) {
    wires[i].capture_right();
  }
}

int main(int argc, char* argv[]) {

  pcap_t* left = pcap_open_live(
    argv[1], BUFSIZ, 1, -1, NULL
  );

  pcap_t* right = pcap_open_live(
    argv[2], BUFSIZ, 1, -1, NULL
  );

  int length = 10;
  std::vector<Wire> wires(length);

  for (int i = 1; i < length; i++) {
    wires[i].set_left(&wires[i - 1]);
  }
  for (int i = length - 2; i >= 0; i--) {
    wires[i].set_right(&wires[i + 1]);
  }

  while (true) {

    const u_char* packet;
    struct pcap_pkthdr* packet_header;

    if (pcap_next_ex(left, &packet_header, &packet) == 1) {
      wires[0].set_packet(packet);
      evoke_wires_to_right(wires);
      if (pcap_sendpacket(right, wires[length - 1].get_packet(), 100) != 0) {
        std::cout << pcap_geterr(right) << std::endl;
      }
    }

    if (pcap_next_ex(right, &packet_header, &packet) == 1) {
      wires[length - 1].set_packet(packet);
      evoke_wires_to_left(wires);
      if (pcap_sendpacket(left, wires[0].get_packet(), 100) != 0) {
        std::cout << pcap_geterr(left) << std::endl;
      }
    }

  }

  return 0;

}
