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

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace eka2l1::epoc::socket {
    /**
     * @brief Bearer bitmask, mirror of KCommDbBearer* constants in Symbian's commdb.h.
     */
    enum commdb_bearer : std::uint32_t {
        COMMDB_BEARER_UNKNOWN = 0x00,
        COMMDB_BEARER_CSD = 0x01,
        COMMDB_BEARER_PSD = 0x02,
        COMMDB_BEARER_LAN = 0x04,
        COMMDB_BEARER_VIRTUAL = 0x08,
        COMMDB_BEARER_WLAN = 0x10
    };

    /**
     * @brief Bearer identifier used by the connection monitor server (TConnMonBearerId).
     */
    enum iap_conn_bearer : std::uint32_t {
        IAP_CONN_BEARER_GPRS = 2000000,
        IAP_CONN_BEARER_WLAN = 2000004,
        IAP_CONN_BEARER_LAN = 2000005
    };

    /**
     * @brief A Symbian internet access point (IAP) backed by a real host network interface.
     *
     * The emulator does not own a CommsDat database, so instead of feeding fake data to the
     * guest, every usable host interface is exported as one IAP record. Settings that guest
     * applications query through RConnection / NifMan / CommDB are then answered with the
     * real address, netmask and gateway of that interface.
     */
    struct host_iap {
        std::uint32_t id_ = 1; ///< IAP record id (CommDB IAP\Id), 1-based.
        std::uint32_t service_id_ = 1; ///< IAP\IAPService record id.
        std::uint32_t bearer_id_ = 1; ///< IAP\IAPBearer record id.
        std::uint32_t network_id_ = 1; ///< IAP\IAPNetwork record id.
        std::uint32_t bearer_set_ = COMMDB_BEARER_LAN; ///< Bitmask of commdb_bearer.
        std::uint32_t conn_bearer_ = IAP_CONN_BEARER_LAN; ///< Connection monitor bearer id.

        std::u16string name_; ///< Human readable access point name, shown in guest UI.
        std::u16string service_type_ = u"LANService"; ///< IAP\IAPServiceType.
        std::u16string bearer_type_ = u"LANBearer"; ///< IAP\IAPBearerType.
        std::u16string network_name_ = u"Internet"; ///< Network\Name.

        std::string host_if_name_; ///< Name of the backing host interface.
        std::u16string ip_address_ = u"0.0.0.0";
        std::u16string ip_netmask_ = u"255.255.255.0";
        std::u16string ip_gateway_ = u"0.0.0.0";
        std::u16string ip_name_server_1_ = u"0.0.0.0";
        std::u16string ip_name_server_2_ = u"0.0.0.0";

        bool wireless_ = false; ///< True when the interface looks like a Wi-Fi adapter.
        bool synthetic_ = false; ///< True when no host interface was found and this is a fallback.
    };

    /**
     * @brief Get the list of access points mapped from host network interfaces.
     *
     * The list is built once and cached. It always contains at least one entry: when no usable
     * host interface exists, a synthetic entry is returned so the guest still has something to
     * select (host networking may come back later, e.g. Wi-Fi reconnecting).
     *
     * @param force_refresh Rebuild the list by re-enumerating host interfaces.
     */
    const std::vector<host_iap> &get_host_iap_list(const bool force_refresh = false);

    /**
     * @brief Find an access point by its IAP record id. Returns nullptr when not found.
     */
    const host_iap *find_host_iap(const std::uint32_t id);

    /**
     * @brief Get the access point that should be used when the guest does not ask for a specific one.
     */
    const host_iap *get_default_host_iap();

    /**
     * @brief Look through a raw TCommDbConnPref-alike buffer for an IAP id known to us.
     *
     * Guest applications pass connection preferences as an opaque package. Rather than assuming a
     * fixed layout across Symbian versions, scan the first few words for a value that matches one
     * of our records.
     *
     * @returns The matched IAP id, or 0 when nothing matched.
     */
    std::uint32_t match_iap_id_from_pref_buffer(const std::uint8_t *buffer, const std::size_t size);
}
