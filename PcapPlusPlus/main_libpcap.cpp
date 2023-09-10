
#include <iostream>
#include "pcap.h"

void mirror(pcap_t* capture, pcap_t* send) {
  const u_char* packet;
  struct pcap_pkthdr* packet_header;
  if (pcap_next_ex(capture, &packet_header, &packet) == 1) {
    if (pcap_sendpacket(send, packet, 100) != 0) {
      std::cout << pcap_geterr(send) << std::endl;
    }
  }
}

int main(int argc, char* argv[]) {

  pcap_t* handle_1 = pcap_open_live(
    argv[1], BUFSIZ, 1, -1, NULL
  );

  pcap_t* handle_2 = pcap_open_live(
    argv[2], BUFSIZ, 1, -1, NULL
  );

  while (true) {
    mirror(handle_1, handle_2);
    mirror(handle_2, handle_1);
  }

  return 0;

}
