
#include <iostream>
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
  pcpp::PcapLiveDevice* other = (pcpp::PcapLiveDevice*)cookie;
  if (!other->sendPacket(*packet)) {
    std::cerr << "Couldn't send packet." << std::endl;
  }
}

int main(int argc, char* argv[]) {

  std::string interface_name_1 = argv[1];
  std::string interface_name_2 = argv[2];
  
  pcpp::PcapLiveDevice* dev_1 = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name_1);
  pcpp::PcapLiveDevice* dev_2 = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name_2);


  if (dev_1 == NULL) {
    std::cerr << "Could not find interface 1!" << std::endl;
    return 1;
  }
  if (dev_2 == NULL) {
    std::cerr << "Could not find interface 2!" << std::endl;
    return 1;
  }
  
  if (!dev_1->open()) {
    std::cerr << "Could not open dev_1!" << std::endl;
    return 1; 
  }
  if (!dev_2->open()) {
    std::cerr << "Could not open dev_2!" << std::endl;
    return 1; 
  }

  dev_1->startCapture(onPacketArrives, dev_2);
  dev_2->startCapture(onPacketArrives, dev_1);
  
  while(true){}

  dev_1->stopCapture();
  dev_2->stopCapture();

  return 0;

}
