
add_executable(main main.cpp)

find_package(PcapPlusPlus CONFIG REQUIRED)

target_link_libraries(main
    PcapPlusPlus::Pcap++
)
