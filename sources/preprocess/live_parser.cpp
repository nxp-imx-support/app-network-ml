#include "read_packets.h"
#include <iostream>
#include <sstream>
#include <string>


int main(int argc, char* argv[]) {
    /*
    * argv[1]: device
    * argv[2]: capture break timeout
    * argv[3]: capture packets number
    * argv[4]: pipe name
    */
    if (argc != 5) {
        std::cout << "invalid arguments." << std::endl;
        return -1;
    }
    int cap_time = 0;
    int cap_num = 0;

    std::stringstream ss;
    ss << argv[2];
    ss >> cap_time;
    ss.clear();
    ss << argv[3];
    ss >> cap_num;

    start_capture(argv[1], cap_time, cap_num, argv[4]);
    return 0;
}