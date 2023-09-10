
#include <iostream>
#include "pcap.h"
#include <vector>

class Machine {
public:
  Machine() {left = NULL; right = NULL; }
  void set_left(Machine* left) { this->left = left; }
  void set_right(Machine* right) { this->right = right; }
  const u_char* get_packet() { return packet; }

  void send_to_right() {
    if (right != NULL) {
      right->recieve_from_left(packet);
    }
  }
  void recieve_from_left(const u_char* packet) { 
    this->packet = packet;
    send_to_right();
  }

  void send_to_left()  {
    if (left != NULL) {
      left->recieve_from_right(packet);
    }
  }
  void recieve_from_right(const u_char* packet) { 
    this->packet = packet;
    send_to_left();
  }

protected:
  Machine* left;
  Machine* right;
  const u_char* packet;
};

class Wire : public Machine {
public:
  Wire() : Machine::Machine() {}
};

int main(int argc, char* argv[]) {

  pcap_t* left = pcap_open_live(
    argv[1], BUFSIZ, 1, -1, NULL
  );

  pcap_t* right = pcap_open_live(
    argv[2], BUFSIZ, 1, -1, NULL
  );

  int length = 10;
  std::vector<Machine> wires(length, Wire());

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
      wires[0].recieve_from_left(packet);
      if (pcap_sendpacket(right, wires[length - 1].get_packet(), 100) != 0) {
        std::cout << pcap_geterr(right) << std::endl;
      }
    }

    if (pcap_next_ex(right, &packet_header, &packet) == 1) {
      wires[length - 1].recieve_from_right(packet);
      if (pcap_sendpacket(left, wires[0].get_packet(), 100) != 0) {
        std::cout << pcap_geterr(left) << std::endl;
      }
    }

  }

  return 0;

}
