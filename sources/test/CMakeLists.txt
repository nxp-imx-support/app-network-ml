cmake_minimum_required (VERSION 3.22)
project (test_preprocess)

add_subdirectory(../preprocess proprocess_build)
# set(BINARY_DIR .)
include_directories(../preprocess)

add_executable(test_live_process test_live_process.cpp)
target_link_libraries(test_live_process preprocess)

add_executable(test_offline_process test_offline_process.cpp)
target_link_libraries(test_offline_process preprocess)
