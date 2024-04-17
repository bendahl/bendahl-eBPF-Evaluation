/*
    This program is intended to simulate different network conditions, such as jitter, packet drop and packet reordering.
    Due to various issues regarding the resulting BPF binary, this program is not in a usable state.
*/
#ifndef JITTERGEN_H
#define JITTERGEN_H

// C++ standard library headers
#include <stdexcept>
#include <iostream>
#include <optional>

// external dependencies
#include <arpa/inet.h>
#include <yaml-cpp/yaml.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>

#include "common_types.h"

// generated headers
#include "jittergen.skel.h"

static const char *const ALLOW = "allow";
static const char *const BLOCK = "block";

// configuration data structure
struct config {
    std::string outIf;
    std::string action;
    struct {
        uint16_t percent;
        std::string protocol;
        uint16_t port;
    } match;
    struct {
        uint16_t minDelayMs;
        uint16_t maxDelayMs;
    } jitter;
    struct {
        uint16_t delayMs;
    } reorder;
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
    if (!yamlFile["outIf"]) {
        throw MissingConfigValue("outIf");
    }
    if (!yamlFile["action"]) {
        throw MissingConfigValue("action");
    }
    if (!yamlFile["match"]) {
        throw MissingConfigValue("match");
    }
    if (!yamlFile["match"]["percent"]) {
        throw MissingConfigValue("match.percent");
    }
    if (!yamlFile["match"]["protocol"]) {
        throw MissingConfigValue("match.protocol");
    }
    if (!yamlFile["match"]["port"]) {
        throw MissingConfigValue("match.port");
    }

    config cfg;
    cfg.outIf = yamlFile["outIf"].as<std::string>();
    cfg.action = yamlFile["action"].as<std::string>();
    cfg.match.percent = yamlFile["match"]["percent"].as<uint16_t>();
    cfg.match.protocol = yamlFile["match"]["protocol"].as<std::string>();
    cfg.match.port = yamlFile["match"]["port"].as<uint16_t>();

    if (cfg.action == "jitter") {
        if (!yamlFile["jitter"]) {
            throw MissingConfigValue("jitter");
        }
        if (!yamlFile["jitter"]["minDelayMs"]) {
            throw MissingConfigValue("jitter.minDelayMs");
        }
        if (!yamlFile["jitter"]["maxDelayMs"]) {
            throw MissingConfigValue("jitter.maxDelayMs");
        }
        cfg.jitter.minDelayMs = yamlFile["jitter"]["minDelayMs"].as<uint16_t>();
        cfg.jitter.maxDelayMs = yamlFile["jitter"]["maxDelayMs"].as<uint16_t>();
    }

    if (cfg.action == "reorder") {
        if (!yamlFile["reorder"]) {
            throw MissingConfigValue("reorder");
        }
        if (!yamlFile["reorder"]["delayMs"]) {
            throw MissingConfigValue("reorder.delayMs");
        }
        cfg.reorder.delayMs = yamlFile["reorder"]["delayMs"].as<uint16_t>();
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

// toAction parses an action string from the configuration and maps it to a constant value
uint16_t toAction(const std::string& actionStr) {
    if (actionStr == "drop") {
        return ACTION_DROP;
    }
    if (actionStr == "jitter") {
        return ACTION_JITTER;
    }
    if (actionStr == "reorder") {
        return ACTION_REORDER;
    }
    throw InvalidConfigValue(actionStr, "action");
}

// toProtocol parses a protocol value as specified in the config file and maps it to a constant
unsigned char toProtocol(const std::string& protocolStr) {
    if (protocolStr == "ip") {
        return (unsigned char)ETH_P_IP;
    }
    if (protocolStr == "udp") {
        return IP_P_UDP;
    }
    if (protocolStr == "tcp") {
        return IP_P_TCP;
    }
    throw InvalidConfigValue(protocolStr, "match.protocol");
}

// initSettings populates the BPF map that holds the program settings
void initSettings(jittergen_bpf *skel, const config &cfg) {
    auto action = toAction(cfg.action);
    bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(ACTIONS), &action, 0);
    bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(PROTOCOL), toPtr(toProtocol(cfg.match.protocol)), 0);
    bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(PORT), &cfg.match.port, 0);
    bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(PERCENT), &cfg.match.percent, 0);

    if (action == ACTION_JITTER) {
        bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(MIN_LAT), &cfg.jitter.minDelayMs, 0);
        bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(MAX_LAT), &cfg.jitter.maxDelayMs, 0);
    }

    if (action == ACTION_REORDER) {
        bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(MIN_LAT), &cfg.reorder.delayMs, 0);
        bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(MAX_LAT), &cfg.reorder.delayMs, 0);
    }
}

// exec executes a given command in the system's shell
// original code taken from example on Stack Overflow
// see: https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
std::string exec(const char* cmd) {
    std::array<char, 128> buffer{};
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// TcHandler manages qdiscs and filters of the selected nic
class TcHandler {
public:
    TcHandler(std::string interfaceName) {
        this->interfaceName = std::move(interfaceName);
        std::cout << "setting up qdiscs for network interface \"" << this->interfaceName << "\"" << std::endl;
        std::cout << "adding root qdisc (type fq)" << std::endl;
        std::string cmd = "tc qdisc add dev " + this->interfaceName + " root fq";
        exec(cmd.c_str());
        std::cout << "adding child qdisc (type clsact)" << std::endl;
        cmd = "tc qdisc add dev " + this->interfaceName + " clsact";
        exec(cmd.c_str());
    }

    ~TcHandler() {
        std::cout << "resetting qdiscs for network interface \"" << this->interfaceName << "\"" << std::endl;
        std::string cmd = "tc qdisc delete dev "+ this->interfaceName + " clsact";
        exec(cmd.c_str());
        cmd = "tc qdisc delete dev "+ this->interfaceName + " root";
        exec(cmd.c_str());
    }

private:
    std::string interfaceName;
};

#endif //JITTERGEN_H
