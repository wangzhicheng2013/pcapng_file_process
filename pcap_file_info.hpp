#pragma once
#include <stdio.h>
#include <stdint.h>
/*
struct pcap_file_header {
    uint32_t magic = 0;
    uint16_t max_version = 0;
    uint16_t min_version = 0;
    uint32_t time_zone = 0;
    uint32_t sig_flag = 0;
    uint32_t snap_len = 0;
    uint32_t link_type = 0;
};*/
struct pcap_pkt_header {
    uint32_t time_sec;
    uint32_t time_usec;
    uint32_t cap_len;
    uint32_t pkt_len;
};
const static uint32_t G_PCAP_FILE_HEADER_LEN = sizeof(pcap_file_header);
const static uint32_t G_PCAP_HEADER_LEN = sizeof(pcap_pkt_header);
const static uint32_t G_MAX_PCAP_BUFFER_LEN = 65535;
const static uint32_t G_MAX_PCAP_BUFFER_BODY_LEN = G_MAX_PCAP_BUFFER_LEN - G_PCAP_HEADER_LEN;