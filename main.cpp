#include "ap.h"
#include "wireless.h"

#include <chrono>
#include <csignal>
#include <iostream>
#include <pcap/pcap.h>
#include <thread>

namespace {

volatile std::sig_atomic_t stop_requested = 0;

void stop_capture(int) {
    stop_requested = 1;
}

void print_usage() {
    std::cout << "syntax : airodump <interface>\n";
    std::cout << "sample : airodump mon0\n";
}

bool install_filter(pcap_t* handle) {
    bpf_program program{};
    const char* expression =
        "type mgt subtype beacon or type mgt subtype probe-req or type data";
    if (pcap_compile(handle, &program, expression, 1,
                     PCAP_NETMASK_UNKNOWN) < 0) {
        return false;
    }
    const int result = pcap_setfilter(handle, &program);
    pcap_freecode(&program);
    return result == 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        print_usage();
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE] = {};
    pcap_t* handle = pcap_open_live(argv[1], 65535, 1, 250, error_buffer);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live: " << error_buffer << '\n';
        return 1;
    }

    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        std::cerr << "Radiotap monitor interface required.\n";
        pcap_close(handle);
        return 1;
    }

    if (!install_filter(handle)) {
        std::cerr << "pcap filter: " << pcap_geterr(handle) << '\n';
        pcap_close(handle);
        return 1;
    }

    std::signal(SIGINT, stop_capture);
    std::signal(SIGTERM, stop_capture);

    airodump::NetworkTable table;
    auto next_render = std::chrono::steady_clock::now();
    while (stop_requested == 0) {
        pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;
        const int result = pcap_next_ex(handle, &header, &packet);
        if (result == 1) {
            const airodump::RadiotapInfo radio =
                airodump::parse_radiotap(packet, header->caplen);
            if (radio.valid && radio.header_length < header->caplen) {
                const std::uint8_t* frame = packet + radio.header_length;
                std::size_t length = header->caplen - radio.header_length;
                if (radio.fcs_at_end && length >= 4) {
                    length -= 4;
                }
                table.observe(frame, length, radio);
            }
        } else if (result == PCAP_ERROR) {
            std::cerr << "capture: " << pcap_geterr(handle) << '\n';
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_render) {
            std::cout << "\x1b[2J\x1b[H";
            std::cout << "interface: " << argv[1] << "\n\n";
            table.print();
            std::cout.flush();
            next_render = now + std::chrono::milliseconds(500);
        }
    }

    pcap_close(handle);
    return 0;
}
