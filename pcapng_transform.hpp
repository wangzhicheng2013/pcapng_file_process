#pragma once
#include <dirent.h>
#include <fcntl.h>
#include "pcap_file_info.hpp"
#include "daq_pkt_info.hpp"
#include "file_utility.hpp"
class pcapng_transform {
public:
    pcapng_transform() = default;
    virtual ~pcapng_transform() = default;
public:
    bool batch_transform(const char *dir_path) {
        if (!dir_path) {
            return false;
        }
        DIR *dir = opendir(dir_path);
        if (!dir) {
            std::cerr << dir_path << " open dir failed." << std::endl;
            return false;
        }
        struct dirent *ptr = nullptr;
        FILE *fp = nullptr;
        std::string pcapng_file_path;
        std::string pcap_file_path;
        while ((ptr = readdir(dir))) {
            // filter pcapng
            if (!strstr(ptr->d_name, ".pcapng")) {
                continue;
            }
            // transform pcapng to pcap
            pcapng_file_path = dir_path;
            pcapng_file_path += "/";
            pcapng_file_path += ptr->d_name;
            if (!G_FILE_UTILITY.change_pcapng_to_pcap(pcapng_file_path.c_str(), pcap_file_path)) {
                std::cerr << "change to pcap failed for file:" << pcapng_file_path << std::endl;
                continue;
            }
            // read pcap
            fp = fopen(pcap_file_path.c_str(), "rb");
            if (!fp) {
                std::cerr << pcap_file_path << " fopen with rb mode failed." << std::endl;
                continue;
            }
            // first read 4 bytes
            if (fread(pcap_buffer_, 1, 4, fp) != 4) {
                std::cerr << "read first 4 bytes failed from pcap file:" << pcap_file_path << std::endl;
                fclose(fp);
                G_FILE_UTILITY.delete_file(pcapng_file_path.c_str());   // keep error pcap file
                continue;
            }
            if (((uint8_t)pcap_buffer_[0] == 0xd4) && 
                ((uint8_t)pcap_buffer_[1] == 0xc3) &&
                ((uint8_t)pcap_buffer_[2] == 0xb2) &&
                ((uint8_t)pcap_buffer_[3] == 0xa1)) {
                    fseek(fp, G_PCAP_FILE_HEADER_LEN, SEEK_SET);
            }
            else {
                std::cerr << "first 4 bytes data exception from pcap file:" << pcap_file_path << std::endl;
                fclose(fp);
                G_FILE_UTILITY.delete_file(pcapng_file_path.c_str());   // keep error pcap file
                continue;
            }
            uint32_t cap_len = 0;
            uint32_t pkt_len = 0;
            struct timeval tv = { 0 };
            struct timezone tz = { 0 };
            bool read_header_error = false;
            pcap_pkt_header header;
            while (true) {
                if (fread(&header, 1, G_PCAP_HEADER_LEN, fp) != G_PCAP_HEADER_LEN) {
                    read_header_error = true;
                    std::cerr << "read pcap head failed." << std::endl;
                    break;
                }
                if (header.cap_len > G_MAX_PCAP_BUFFER_BODY_LEN) {
                    std::cerr << "read pcap body error." << std::endl;
                    break;
                }
                cap_len = header.cap_len;
                pkt_len = header.pkt_len;
                std::cout << "cap_len = " << cap_len << std::endl;
                std::cout << "pkt_len = " << pkt_len << std::endl;
                if (fread(pcap_buffer_, 1, cap_len, fp) != cap_len) {
                    std::cerr << "read pcap data failed." << std::endl;
                    break;
                }
                pcap_buffer_[cap_len] = 0;
                gettimeofday(&tv, &tz);
                daq_pkt_header dph(tv, cap_len, pkt_len);
                packet_call_back(dph, (uint8_t *)pcap_buffer_);
            }
            fclose(fp);
            G_FILE_UTILITY.delete_file(pcapng_file_path.c_str());
            if (false == read_header_error) {        // keep error pcap file
                G_FILE_UTILITY.delete_file(pcap_file_path.c_str());
            }
        }
        closedir(dir);
    }
public:
    virtual void packet_call_back(daq_pkt_header &headr, uint8_t *pcap_buffer) {
    }
private:
    pcap_pkt_header pcap_header_;
    char pcap_buffer_[G_MAX_PCAP_BUFFER_LEN + 1] = "";
};