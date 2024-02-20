cmake_minimum_required (VERSION 3.22)
project (preprocess)

aux_source_directory (. DIR_SRCS)

add_executable (pcap_parser ${DIR_SRCS})
target_link_libraries (pcap_parser pcap)

add_library(preprocess ${DIR_SRCS})
target_link_libraries(preprocess pcap)


