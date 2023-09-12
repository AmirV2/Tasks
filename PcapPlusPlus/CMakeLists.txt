
find_package(PcapPlusPlus CONFIG REQUIRED)

add_executable(main main_machine.cpp)

target_link_libraries(main
    pcap PcapPlusPlus::Pcap++
)
