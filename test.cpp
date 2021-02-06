#include <iostream>
#include "pcapng_transform.hpp"
int main() {
    pcapng_transform pt;
    pt.batch_transform("./");
    pt.batch_process_pcaps("./");
    
    return 0;
}