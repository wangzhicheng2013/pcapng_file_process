#pragma once
#include <time.h>
#include <sys/time.h>
struct daq_pkt_header {
    daq_pkt_header(struct timeval &ts_, uint32_t cap_len_, uint32_t pkt_len_) : ts(ts_), cap_len(cap_len_), pkt_len(pkt_len_) {
    }
    struct timeval ts;
    uint32_t cap_len = 0;           // length of the portion present
    uint32_t pkt_len = 0;           // length of the packet (off wire)
    int32_t ingress_index = -1;     // index of the inbound interface
    int32_t egress_index = -1;      // index of the outbound interface
    int32_t ingress_group = -1;     // index of the inbound group
    int32_t egress_group = -1;      // index of the outbound group
    uint32_t flags = 0;             // flags for packet 
    uint32_t opaque = 0;            // opaque context value from the DAQ module or underlying hardware directly relate to the opaque value in FlowStats
    void *priv_ptr = nullptr;       // private data 
    uint32_t flow_id = 0;
    uint16_t address_space_ud = 0;  // unique ID of the address space
};