cmake_minimum_required (VERSION 3.22)
project (preprocess)

aux_source_directory (. DIR_SRCS)

# add_executable (live_cap ${DIR_SRCS})
# target_link_libraries (live_cap pcap)

add_library(preprocess ${DIR_SRCS})
target_link_libraries(preprocess pcap)


