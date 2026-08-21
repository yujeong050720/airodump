#include "ap.h"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace airodump {
namespace {

std::uint16_t read_le16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(data[0]) |
           static_cast<std::uint16_t>(data[1] << 8);
}

std::uint32_t read_le32(const std::uint8_t* data) {
    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) |
           (static_cast<std::uint32_t>(data[3]) << 24);
}

std::size_t align_up(std::size_t offset, std::size_t alignment) {
    return (offset + alignment - 1) & ~(alignment - 1);
}

bool valid_address(const MacAddress& address) {
    return !address.is_zero() && !address.is_group();
}

std::string readable_essid(const std::uint8_t* data, std::size_t length) {
    if (length == 0) {
        return "<hidden>";
    }

    std::string result;
    for (std::size_t i = 0; i < length && i < 32; ++i) {
        const unsigned char value = data[i];
        result.push_back(value >= 32 && value <= 126
                             ? static_cast<char>(value)
                             : '.');
    }
    return result;
}

std::string encryption_name(bool privacy, bool has_wpa, bool has_rsn) {
    if (has_rsn) {
        return "WPA2";
    }
    if (has_wpa) {
        return "WPA";
    }
    return privacy ? "WEP" : "OPN";
}

bool parse_beacon(const std::uint8_t* frame, std::size_t length,
                  MacAddress* bssid, std::string* essid,
                  std::string* encryption) {
    if (length < 36 || frame[0] != 0x80) {
        return false;
    }

    *bssid = MacAddress::from(frame + 16);
    if (!valid_address(*bssid)) {
        return false;
    }

    const bool privacy = (read_le16(frame + 34) & 0x0010u) != 0;
    bool has_wpa = false;
    bool has_rsn = false;
    *essid = "<hidden>";

    std::size_t offset = 36;
    while (offset + 2 <= length) {
        const std::uint8_t tag = frame[offset];
        const std::size_t tag_length = frame[offset + 1];
        offset += 2;
        if (tag_length > length - offset) {
            break;
        }

        const std::uint8_t* value = frame + offset;
        if (tag == 0) {
            *essid = readable_essid(value, tag_length);
        } else if (tag == 48) {
            has_rsn = true;
        } else if (tag == 221 && tag_length >= 4 &&
                   value[0] == 0x00 && value[1] == 0x50 &&
                   value[2] == 0xf2 && value[3] == 0x01) {
            has_wpa = true;
        }
        offset += tag_length;
    }

    *encryption = encryption_name(privacy, has_wpa, has_rsn);
    return true;
}

struct DataInfo {
    MacAddress bssid;
    MacAddress station;
    bool valid = false;
    bool ap_transmitted = false;
};

DataInfo parse_data(const std::uint8_t* frame, std::size_t length) {
    DataInfo result;
    if (length < 24 || ((frame[0] >> 2) & 0x03u) != 2) {
        return result;
    }

    const bool to_ds = (frame[1] & 0x01u) != 0;
    const bool from_ds = (frame[1] & 0x02u) != 0;
    if (to_ds && from_ds) {
        return result;
    }

    if (to_ds) {
        result.bssid = MacAddress::from(frame + 4);
        result.station = MacAddress::from(frame + 10);
    } else if (from_ds) {
        result.bssid = MacAddress::from(frame + 10);
        result.station = MacAddress::from(frame + 4);
        result.ap_transmitted = true;
    } else {
        result.bssid = MacAddress::from(frame + 16);
        result.station = MacAddress::from(frame + 10);
    }

    result.valid = valid_address(result.bssid);
    return result;
}

bool parse_probe(const std::uint8_t* frame, std::size_t length,
                 MacAddress* station, std::string* essid) {
    if (length < 24 || frame[0] != 0x40) {
        return false;
    }

    *station = MacAddress::from(frame + 10);
    if (!valid_address(*station)) {
        return false;
    }

    essid->clear();
    std::size_t offset = 24;
    while (offset + 2 <= length) {
        const std::uint8_t tag = frame[offset];
        const std::size_t tag_length = frame[offset + 1];
        offset += 2;
        if (tag_length > length - offset) {
            break;
        }
        if (tag == 0 && tag_length != 0) {
            *essid = readable_essid(frame + offset, tag_length);
            break;
        }
        offset += tag_length;
    }
    return true;
}

std::string power_text(bool available, int power) {
    return available ? std::to_string(power) : "-";
}

std::string probes_text(const std::set<std::string>& probes) {
    std::ostringstream result;
    bool first = true;
    for (const std::string& probe : probes) {
        if (!first) {
            result << ',';
        }
        result << probe;
        first = false;
    }
    return result.str();
}

}  // namespace

RadiotapInfo parse_radiotap(const std::uint8_t* packet,
                            std::size_t captured_length) {
    RadiotapInfo result;
    if (packet == nullptr || captured_length < 8 || packet[0] != 0) {
        return result;
    }

    result.header_length = read_le16(packet + 2);
    if (result.header_length < 8 || result.header_length > captured_length) {
        return RadiotapInfo{};
    }

    std::vector<std::uint32_t> present_words;
    std::size_t present_offset = 4;
    while (true) {
        if (present_offset + 4 > result.header_length) {
            return RadiotapInfo{};
        }
        const std::uint32_t word = read_le32(packet + present_offset);
        present_words.push_back(word);
        present_offset += 4;
        if ((word & (1u << 31)) == 0) {
            break;
        }
    }

    std::size_t cursor = present_offset;
    const std::size_t alignments[] = {8, 1, 1, 2, 2, 1};
    const std::size_t sizes[] = {8, 1, 1, 4, 2, 1};
    const std::uint32_t first_word = present_words.front();

    for (int field = 0; field <= 5; ++field) {
        if ((first_word & (1u << field)) == 0) {
            continue;
        }
        cursor = align_up(cursor, alignments[field]);
        if (cursor > result.header_length ||
            sizes[field] > result.header_length - cursor) {
            return RadiotapInfo{};
        }

        if (field == 1) {
            result.fcs_at_end = (packet[cursor] & 0x10u) != 0;
        } else if (field == 5) {
            result.signal_dbm = static_cast<int>(
                static_cast<std::int8_t>(packet[cursor]));
            result.has_signal = true;
        }
        cursor += sizes[field];
    }

    result.valid = true;
    return result;
}

void NetworkTable::observe(const std::uint8_t* frame, std::size_t length,
                           const RadiotapInfo& radio) {
    if (frame == nullptr || length < 2) {
        return;
    }

    const std::uint8_t type = static_cast<std::uint8_t>((frame[0] >> 2) & 0x03u);
    const std::uint8_t subtype = static_cast<std::uint8_t>((frame[0] >> 4) & 0x0fu);

    if (type == 0 && subtype == 8) {
        MacAddress bssid;
        std::string essid;
        std::string encryption;
        if (!parse_beacon(frame, length, &bssid, &essid, &encryption)) {
            return;
        }

        AccessPoint& ap = access_points_[bssid];
        ap.bssid = bssid;
        ++ap.beacons;
        ap.essid = essid;
        ap.encryption = encryption;
        if (radio.has_signal) {
            ap.has_power = true;
            ap.power = radio.signal_dbm;
        }
        return;
    }

    if (type == 2) {
        const DataInfo data = parse_data(frame, length);
        if (!data.valid) {
            return;
        }

        AccessPoint& ap = access_points_[data.bssid];
        ap.bssid = data.bssid;
        ++ap.data_frames;
        if (radio.has_signal && data.ap_transmitted) {
            ap.has_power = true;
            ap.power = radio.signal_dbm;
        }

        if (valid_address(data.station) && data.station != data.bssid) {
            Station& station = stations_[data.station];
            station.address = data.station;
            station.bssid = data.bssid;
            station.associated = true;
            ++station.frames;
            if (radio.has_signal && !data.ap_transmitted) {
                station.has_power = true;
                station.power = radio.signal_dbm;
            }
        }
        return;
    }

    if (type == 0 && subtype == 4) {
        MacAddress address;
        std::string essid;
        if (!parse_probe(frame, length, &address, &essid)) {
            return;
        }

        Station& station = stations_[address];
        station.address = address;
        ++station.frames;
        ++station.probes;
        if (radio.has_signal) {
            station.has_power = true;
            station.power = radio.signal_dbm;
        }
        if (!essid.empty()) {
            station.probed_essids.insert(essid);
        }
    }
}

void NetworkTable::print() const {
    std::cout << "BSSID              PWR   Beacons    #Data    ENC       ESSID\n";
    for (const auto& item : access_points_) {
        const AccessPoint& ap = item.second;
        std::cout << std::left << std::setw(19) << ap.bssid.to_string()
                  << std::setw(6) << power_text(ap.has_power, ap.power)
                  << std::setw(11) << ap.beacons
                  << std::setw(9) << ap.data_frames
                  << std::setw(10) << ap.encryption
                  << ap.essid << '\n';
    }

    std::cout << "\nBSSID              STATION            PWR   Frames    Probes  PROBED ESSIDs\n";
    for (const auto& item : stations_) {
        const Station& station = item.second;
        const std::string bssid = station.associated
                                      ? station.bssid.to_string()
                                      : "(not associated)";
        std::cout << std::left << std::setw(19) << bssid
                  << std::setw(19) << station.address.to_string()
                  << std::setw(6) << power_text(station.has_power, station.power)
                  << std::setw(10) << station.frames
                  << std::setw(8) << station.probes
                  << probes_text(station.probed_essids) << '\n';
    }
}

}  // namespace airodump
