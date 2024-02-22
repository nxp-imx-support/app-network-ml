cmake_minimum_required (VERSION 3.22)
project (preprocess)

aux_source_directory (. DIR_SRCS)

set (COMMON_FILES extract_protocols.cpp read_packets.cpp)

add_executable (pcap_parser ${COMMON_FILES} pcap_parser.cpp)
target_link_libraries (pcap_parser pcap)

add_executable (live_parser ${COMMON_FILES} live_parser.cpp)
target_link_libraries (live_parser pcap)

add_library(preprocess ${COMMON_FILES})
target_link_libraries(preprocess pcap)


