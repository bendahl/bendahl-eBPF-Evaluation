#ifndef LOADBALANCER_H
#define LOADBALANCER_H

// C++ standard library headers
#include <iostream>
#include <optional>
#include <stdexcept>
#include <sstream>

// external dependencies
#include <arpa/inet.h>
#include <yaml-cpp/yaml.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ifaddrs.h>
#include <utility>
#include <vector>

// generated headers
#include "loadbalancer.skel.h"

static const char *const ALLOW = "allow";
static const char *const BLOCK = "block";

// configuration data structure (program parameters)
struct config {
    std::string listenInterface;
    uint16_t tcpPort{};
    std::vector<std::string> backends;
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
    for (auto field: {"listenInterface", "tcp_port", "backends"}) {
        if (!yamlFile[field]) {
            throw MissingConfigValue(field);
        }
    }

    config cfg;
    cfg.listenInterface = yamlFile["listenInterface"].as<std::string>();
    cfg.tcpPort = yamlFile["tcp_port"].as<unsigned short>();
    cfg.backends = yamlFile["backends"].as<std::vector<std::string>>();

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

// toMac converts a given mac address string to a byte array representation
void toMac(const std::string &macStr, uint8_t *macAddrOut) {
    auto tmpStream = std::stringstream(macStr);
    std::string token;
    int idx = 0;
    while (std::getline(tmpStream, token, ':')) {
        macAddrOut[idx] = (uint8_t) strtoul(token.c_str(), nullptr, 16);
        idx++;
    }
}

// initSettings populates the program settings BPF map
void initSettings(loadbalancer_bpf *skel, const config &cfg) {
    std::uint32_t idx = 0;
    for (const auto &backend: cfg.backends) {
        uint8_t addr[6] = {0};
        toMac(backend, addr);
        bpf_map_update_elem(bpf_map__fd(skel->maps.backends), &idx, &addr, 0);
        idx++;
    }
    bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(0), &cfg.tcpPort, 0);
    bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(1), toPtr((uint16_t) cfg.backends.size()), 0);

    auto outIf = (uint16_t) getNetworkInterfaceByName(cfg.listenInterface).value();
    bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(2), &outIf, 0);
}

#endif //LOADBALANCER_H
