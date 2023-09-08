
#include <iostream>
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
  pcpp::PcapLiveDevice* other = (pcpp::PcapLiveDevice*)cookie;
  if (!other->sendPacket(*packet)) {
    std::cout << "Couldn't send packet!" << std::endl;
  }
  return true;
}

int main(int argc, char* argv[]) {
  
  std::string interface_name_1 = argv[1];
  std::string interface_name_2 = argv[2];
  
  pcpp::PcapLiveDevice* dev_1 = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name_1);
  pcpp::PcapLiveDevice* dev_2 = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name_2);
  
  if (dev_1 == NULL) {
    std::cout << "Could not find interface 1!" << std::endl;
    return 1;
  }
  if (dev_2 == NULL) {
    std::cout << "Could not find interface 2!" << std::endl;
    return 1;
  }
  
  if (!dev_1->open()) {
    std::cout << "Could not open the dev_1!" << std::endl;
    return 1; 
  }
  if (!dev_2->open()) {
    std::cout << "Could not open the dev_2!" << std::endl;
    return 1; 
  }

  while (true) {
    dev_1->startCaptureBlockingMode(onPacketArrivesBlockingMode, dev_2, 10);
    dev_2->startCaptureBlockingMode(onPacketArrivesBlockingMode, dev_1, 10);
  }

  return 0;

}
