#pragma once

#include "wireless.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace airodump {

class NetworkTable {
public:
    void observe(const std::uint8_t* frame, std::size_t length,
                 const RadiotapInfo& radio);
    void print() const;

private:
    struct AccessPoint {
        MacAddress bssid;
        std::uint64_t beacons = 0;
        std::uint64_t data_frames = 0;
        bool has_power = false;
        int power = 0;
        std::string encryption = "?";
        std::string essid = "<unknown>";
    };

    struct Station {
        MacAddress address;
        MacAddress bssid;
        bool associated = false;
        bool has_power = false;
        int power = 0;
        std::uint64_t frames = 0;
        std::uint64_t probes = 0;
        std::set<std::string> probed_essids;
    };

    std::map<MacAddress, AccessPoint> access_points_;
    std::map<MacAddress, Station> stations_;
};

}  // namespace airodump
