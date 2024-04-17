#ifndef PACKETFILTER_PACKETFILTER_H
#define PACKETFILTER_PACKETFILTER_H

// C++ standard library headers
#include <stdexcept>
#include <iostream>
#include <optional>

// external dependencies
#include <arpa/inet.h>
#include <sys/socket.h>
#include <yaml-cpp/yaml.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ifaddrs.h>

// generated headers
#include "packetfilter.skel.h"

// shared datatypes
#include "common_types.h"


static const char *const ALLOW = "allow";
static const char *const BLOCK = "block";

// configuration data structure
struct config {
    struct {
        std::string interface;
        struct {
            std::string defaultAction;
            std::vector<std::string> allow;
            std::vector<std::string> block;
        } ipv4;
        struct {
            std::string defaultAction;
            std::vector<std::string> allow;
            std::vector<std::string> block;
        } ipv6;
    } rules;
};

// MissingConfigValue is thrown when a mandatory parameter is missing in the configuration
class MissingConfigValue : public std::exception {
private:
    std::string message;

public:
    explicit MissingConfigValue(const std::string &name) {
        this->message = std::string("missing config value \"" + name + "\"");
    }

    [[nodiscard]] const char *what() const noexcept override {
        return this->message.c_str();
    }
};

// InvalidConfigValue is thrown when an unexpected configuration value was set that is considered invalid in the current context
class InvalidConfigValue : public std::exception {
private:
    std::string message;

public:
    explicit InvalidConfigValue(const std::string &value, const std::string &option) {
        this->message = std::string("invalid value \"" + value + "\" for config option \"" + option + "\"");
    }

    [[nodiscard]] const char *what() const noexcept override {
        return this->message.c_str();
    }
};

// readConfigFile reads the configuration file and initializes the above-defined configuration data structure with the given values
config readConfigFile() {
    YAML::Node yamlFile = YAML::LoadFile("config.yml");

    // ensure mandatory values are set
    if (!yamlFile["rules"]) {
        throw MissingConfigValue("rules");
    }
    if (!yamlFile["rules"]["interface"]) {
        throw MissingConfigValue("rules.interface");
    }

    if (!yamlFile["rules"]["ipv4"]) {
        throw MissingConfigValue("rules.ipv4");
    }
    if (!yamlFile["rules"]["ipv4"]["default"]) {
        throw MissingConfigValue("rules.ipv4.default");
    }
    auto defaultIPv4Value = yamlFile["rules"]["ipv4"]["default"].as<std::string>();
    if (defaultIPv4Value != ALLOW && defaultIPv4Value != BLOCK) {
        throw InvalidConfigValue(defaultIPv4Value, "rules.ipv4.default");
    }

    if (!yamlFile["rules"]["ipv6"]) {
        throw MissingConfigValue("rules.ipv6");
    }
    if (!yamlFile["rules"]["ipv6"]["default"]) {
        throw MissingConfigValue("rules.ipv6.default");
    }
    auto defaultIPv6Value = yamlFile["rules"]["ipv6"]["default"].as<std::string>();
    if (defaultIPv6Value != ALLOW && defaultIPv6Value != BLOCK) {
        throw InvalidConfigValue(defaultIPv6Value, "rules.ipv6.default");
    }

    config cfg;
    cfg.rules.interface = yamlFile["rules"]["interface"].as<std::string>();
    cfg.rules.ipv4.defaultAction = defaultIPv4Value;
    cfg.rules.ipv6.defaultAction = defaultIPv6Value;

    if (yamlFile["rules"]["ipv4"][ALLOW]) {
        cfg.rules.ipv4.allow = yamlFile["rules"]["ipv4"][ALLOW].as<std::vector<std::string>>();
    }
    if (yamlFile["rules"]["ipv4"][BLOCK]) {
        cfg.rules.ipv4.block = yamlFile["rules"]["ipv4"][BLOCK].as<std::vector<std::string>>();
    }
    if (yamlFile["rules"]["ipv6"][ALLOW]) {
        cfg.rules.ipv6.allow = yamlFile["rules"]["ipv6"][ALLOW].as<std::vector<std::string>>();
    }
    if (yamlFile["rules"]["ipv6"][BLOCK]) {
        cfg.rules.ipv6.block = yamlFile["rules"]["ipv6"][BLOCK].as<std::vector<std::string>>();
    }
    return cfg;
}

// getNetworkInterfaceByName returns the nic id if it exists
std::optional<int> getNetworkInterfaceByName(const std::string &name) {
    struct ifaddrs *ifaddrs = nullptr;
    auto ret = getifaddrs(&ifaddrs);
    if (ret != 0) {
        throw std::runtime_error("failed to retrieve interfaces from system");
    }
    int idx = 0;
    for (auto entry = ifaddrs; entry != nullptr; entry = entry->ifa_next) {
        idx++;
        if (name == std::string(entry->ifa_name)) {
            return idx;
        }
    }
    return {};
}

// get a raw pointer to the given value
template<typename T>
T *toPtr(T &&value) {
    return &value;
}

// setIPConfigs populates the BPF lists containing the IP filter rules
void setIPConfigs(packetfilter_bpf *skel, const config &cfg) {
    if (cfg.rules.ipv4.defaultAction == ALLOW) {
        bpf_map_update_elem(bpf_map__fd(skel->maps.default_config), toPtr(0), toPtr(true), 0);
    } else {
        bpf_map_update_elem(bpf_map__fd(skel->maps.default_config), toPtr(0), toPtr(false), 0);
    }
    if (cfg.rules.ipv6.defaultAction == ALLOW) {
        bpf_map_update_elem(bpf_map__fd(skel->maps.default_config), toPtr(1), toPtr(true), 0);
    } else {
        bpf_map_update_elem(bpf_map__fd(skel->maps.default_config), toPtr(1), toPtr(false), 0);
    }

    for (auto &&ip4: cfg.rules.ipv4.allow) {
        char ipstr[INET_ADDRSTRLEN];
        auto ret = inet_pton(AF_INET, ip4.c_str(), ipstr);
        if (ret != 1) {
            throw InvalidConfigValue(ip4, "rules.ipv4.allow");
        }
        bpf_map_update_elem(bpf_map__fd(skel->maps.ip4_rules), ipstr, toPtr(true), 0);
    }
    for (auto &&ip4: cfg.rules.ipv4.block) {
        char ipstr[INET_ADDRSTRLEN];
        auto ret = inet_pton(AF_INET, ip4.c_str(), ipstr);
        if (ret != 1) {
            throw InvalidConfigValue(ip4, "rules.ipv4.block");
        }
        bpf_map_update_elem(bpf_map__fd(skel->maps.ip4_rules), ipstr, toPtr(false), 0);
    }

    for (auto &&ip6: cfg.rules.ipv6.allow) {
        char ipstr[INET6_ADDRSTRLEN];
        auto ret = inet_pton(AF_INET6, ip6.c_str(), ipstr);
        if (ret != 1) {
            throw InvalidConfigValue(ip6, "rules.ipv6.allow");
        }
        bpf_map_update_elem(bpf_map__fd(skel->maps.ip6_rules), ipstr, toPtr(true), 0);
    }
    for (auto &&ip6: cfg.rules.ipv6.block) {
        char ipstr[INET6_ADDRSTRLEN];
        auto ret = inet_pton(AF_INET6, ip6.c_str(), ipstr);
        if (ret != 1) {
            throw InvalidConfigValue(ip6, "rules.ipv6.block");
        }
        bpf_map_update_elem(bpf_map__fd(skel->maps.ip6_rules), ipstr, toPtr(false), 0);
    }
}

// ipToStr converts a src_ip_type to the appropriate string representation,
// depending on whether it is an IPv4 or IPv6 address
std::string ipToStr(src_ip_type ip) {
    std::string ipStr;
    if (ip.type == IPV4) {
        char tmpIpStr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ip.ip.ipv4, tmpIpStr, INET_ADDRSTRLEN);
        ipStr = tmpIpStr;
    } else {
        char tmpIpStr[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &ip.ip.ipv6, tmpIpStr, INET6_ADDRSTRLEN);
        ipStr = tmpIpStr;
    }
    return ipStr;
}


// handlePacketEvent prints a message when a network packet was processed by the filter
int handlePacketEvent(void *ctx, void *data, size_t data_sz) {
    auto event = static_cast<src_ip_type *>(data);
    if(event->passed == true) {
        std::cout << "A packet was allowed for address " << ipToStr(*event) << std::endl;
    } else {
        std::cout << "A packet was dropped for address " << ipToStr(*event) << std::endl;
    }
    return 0;
}





#endif //PACKETFILTER_PACKETFILTER_H
