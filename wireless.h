#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

namespace airodump {

struct MacAddress {
    std::array<std::uint8_t, 6> bytes{};

    static MacAddress from(const std::uint8_t* data) {
        MacAddress result;
        for (std::size_t i = 0; i < result.bytes.size(); ++i) {
            result.bytes[i] = data[i];
        }
        return result;
    }

    bool is_group() const { return (bytes[0] & 1u) != 0; }
    bool is_zero() const { return bytes == std::array<std::uint8_t, 6>{}; }

    std::string to_string() const {
        char text[18] = {};
        std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                      bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        return text;
    }

    bool operator<(const MacAddress& other) const { return bytes < other.bytes; }
    bool operator==(const MacAddress& other) const { return bytes == other.bytes; }
    bool operator!=(const MacAddress& other) const { return !(*this == other); }
};

struct RadiotapInfo {
    bool valid = false;
    std::size_t header_length = 0;
    bool fcs_at_end = false;
    bool has_signal = false;
    int signal_dbm = 0;
};

RadiotapInfo parse_radiotap(const std::uint8_t* packet,
                            std::size_t captured_length);

}  // namespace airodump
