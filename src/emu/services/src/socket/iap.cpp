/*
 * Copyright (c) 2026 EKA2L1 Team
 *
 * This file is part of EKA2L1 project.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <services/socket/iap.h>

#include <common/algorithm.h>
#include <common/cvt.h>
#include <common/log.h>

#include <uv.h>

#include <cstdio>
#include <cstring>

namespace eka2l1::epoc::socket {
    static std::vector<host_iap> iap_list_;
    static bool iap_list_built_ = false;

    static bool looks_wireless(const std::string &name) {
        static const char *keywords[] = {
            "wlan", "wi-fi", "wifi", "wireless", "wlp", "wlo", "ath", "ra0", "airport"
        };

        const std::string lowered = common::lowercase_string(name);

        for (const char *keyword : keywords) {
            if (lowered.find(keyword) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    static bool looks_virtual(const std::string &name) {
        static const char *keywords[] = {
            "vmware", "virtualbox", "vethernet", "hyper-v", "loopback", "docker", "tap-", "tun",
            "bluetooth", "teredo", "isatap", "npcap", "zerotier", "tailscale"
        };

        const std::string lowered = common::lowercase_string(name);

        for (const char *keyword : keywords) {
            if (lowered.find(keyword) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    static std::string ipv4_to_string(const void *raw_addr) {
        std::uint8_t bytes[4];
        std::memcpy(bytes, raw_addr, 4);

        char buffer[32] = { 0 };
        std::snprintf(buffer, sizeof(buffer) - 1, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);

        return buffer;
    }

    static std::string guess_gateway(const void *raw_addr, const void *raw_mask) {
        std::uint8_t addr_bytes[4];
        std::uint8_t mask_bytes[4];

        std::memcpy(addr_bytes, raw_addr, 4);
        std::memcpy(mask_bytes, raw_mask, 4);

        std::uint8_t gateway_bytes[4];

        for (int i = 0; i < 4; i++) {
            gateway_bytes[i] = static_cast<std::uint8_t>(addr_bytes[i] & mask_bytes[i]);
        }

        // Almost every consumer router sits on the first usable address of the subnet.
        gateway_bytes[3] = static_cast<std::uint8_t>(gateway_bytes[3] | 1);

        char buffer[32] = { 0 };
        std::snprintf(buffer, sizeof(buffer) - 1, "%u.%u.%u.%u", gateway_bytes[0], gateway_bytes[1],
            gateway_bytes[2], gateway_bytes[3]);

        return buffer;
    }

    static void add_synthetic_iap() {
        host_iap fallback;

        fallback.id_ = 1;
        fallback.service_id_ = 1;
        fallback.bearer_id_ = 1;
        fallback.network_id_ = 1;
        fallback.bearer_set_ = COMMDB_BEARER_LAN;
        fallback.conn_bearer_ = IAP_CONN_BEARER_LAN;
        fallback.name_ = u"EKA2L1 Internet";
        fallback.host_if_name_ = "host";
        fallback.synthetic_ = true;

        iap_list_.push_back(fallback);
    }

    static void build_iap_list() {
        iap_list_.clear();

        uv_interface_address_t *interfaces = nullptr;
        int interface_count = 0;

        const int enumerate_result = uv_interface_addresses(&interfaces, &interface_count);

        if (enumerate_result != 0) {
            LOG_WARN(SERVICE_ESOCK, "Unable to enumerate host network interfaces ({}), using a synthetic access point",
                uv_strerror(enumerate_result));

            add_synthetic_iap();
            iap_list_built_ = true;

            return;
        }

        std::uint32_t next_id = 1;

        for (int i = 0; i < interface_count; i++) {
            const uv_interface_address_t &current = interfaces[i];

            if (current.is_internal) {
                continue;
            }

            if (current.address.address4.sin_family != AF_INET) {
                // Only IPv4 interfaces are exported. Symbian applications of this era almost always
                // request an IPv4 access point, and the IPv6 alias of an interface would just be a duplicate.
                continue;
            }

            const std::string interface_name = current.name ? current.name : "Network";

            if (looks_virtual(interface_name)) {
                continue;
            }

            const std::string address_string = ipv4_to_string(&current.address.address4.sin_addr);

            if ((address_string == "0.0.0.0") || (address_string.rfind("169.254.", 0) == 0)) {
                // Unconfigured or link-local-only interface, it cannot reach the internet.
                continue;
            }

            bool duplicated = false;

            for (const host_iap &existing : iap_list_) {
                if (existing.host_if_name_ == interface_name) {
                    duplicated = true;
                    break;
                }
            }

            if (duplicated) {
                continue;
            }

            host_iap entry;

            entry.id_ = next_id;
            entry.service_id_ = next_id;
            entry.bearer_id_ = next_id;
            entry.network_id_ = 1;

            entry.host_if_name_ = interface_name;
            entry.wireless_ = looks_wireless(interface_name);
            entry.name_ = common::utf8_to_ucs2(interface_name);

            entry.bearer_set_ = entry.wireless_ ? (COMMDB_BEARER_LAN | COMMDB_BEARER_WLAN) : COMMDB_BEARER_LAN;
            entry.conn_bearer_ = entry.wireless_ ? IAP_CONN_BEARER_WLAN : IAP_CONN_BEARER_LAN;

            entry.service_type_ = u"LANService";
            entry.bearer_type_ = u"LANBearer";

            entry.ip_address_ = common::utf8_to_ucs2(address_string);
            entry.ip_netmask_ = common::utf8_to_ucs2(ipv4_to_string(&current.netmask.netmask4.sin_addr));

            const std::string gateway_string = guess_gateway(&current.address.address4.sin_addr,
                &current.netmask.netmask4.sin_addr);

            entry.ip_gateway_ = common::utf8_to_ucs2(gateway_string);

            // The host resolver of the emulator performs the actual name lookup through the operating
            // system, so the address handed to the guest only has to be plausible. The gateway is the
            // best guess available without pulling in per-platform resolver configuration APIs.
            entry.ip_name_server_1_ = entry.ip_gateway_;
            entry.ip_name_server_2_ = u"0.0.0.0";

            iap_list_.push_back(entry);
            next_id++;

            LOG_INFO(SERVICE_ESOCK, "Host interface \"{}\" exported as access point {} (addr={}, gateway={}, wireless={})",
                interface_name, entry.id_, address_string, gateway_string, entry.wireless_);
        }

        uv_free_interface_addresses(interfaces, interface_count);

        if (iap_list_.empty()) {
            LOG_WARN(SERVICE_ESOCK, "No usable host network interface found, using a synthetic access point");
            add_synthetic_iap();
        }

        iap_list_built_ = true;
    }

    const std::vector<host_iap> &get_host_iap_list(const bool force_refresh) {
        if (force_refresh || !iap_list_built_) {
            build_iap_list();
        }

        return iap_list_;
    }

    const host_iap *find_host_iap(const std::uint32_t id) {
        const std::vector<host_iap> &list = get_host_iap_list();

        for (const host_iap &entry : list) {
            if (entry.id_ == id) {
                return &entry;
            }
        }

        return nullptr;
    }

    const host_iap *get_default_host_iap() {
        const std::vector<host_iap> &list = get_host_iap_list();

        if (list.empty()) {
            return nullptr;
        }

        // Prefer a wired interface, it is the one most likely to actually have a route out.
        for (const host_iap &entry : list) {
            if (!entry.wireless_ && !entry.synthetic_) {
                return &entry;
            }
        }

        return &list[0];
    }

    std::uint32_t match_iap_id_from_pref_buffer(const std::uint8_t *buffer, const std::size_t size) {
        if (!buffer || (size < sizeof(std::uint32_t))) {
            return 0;
        }

        const std::size_t words = common::min<std::size_t>(size / sizeof(std::uint32_t), 8);

        for (std::size_t i = 0; i < words; i++) {
            std::uint32_t candidate = 0;
            std::memcpy(&candidate, buffer + (i * sizeof(std::uint32_t)), sizeof(std::uint32_t));

            if ((candidate == 0) || (candidate > 0xFFFF)) {
                continue;
            }

            if (find_host_iap(candidate)) {
                return candidate;
            }
        }

        return 0;
    }
}
