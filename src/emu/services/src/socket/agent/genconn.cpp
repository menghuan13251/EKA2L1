/*
 * Copyright (c) 2021 EKA2L1 Team
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

#include <common/log.h>
#include <services/internet/protocols/common.h>
#include <services/socket/agent/genconn.h>
#include <services/socket/iap.h>
#include <services/socket/server.h>

namespace eka2l1::epoc::socket {
    std::unique_ptr<connection> generic_connect_agent::start_connection(conn_preferences &prefs) {
        // On a phone this is where the user would be asked which access point to dial. The host
        // machine is already on a network, so pick the access point that was mapped from the host
        // interface and bridge the connection straight to it.
        protocol *bridged = nullptr;

        if (sock_serv_) {
            bridged = sock_serv_->find_protocol(epoc::internet::INET_ADDRESS_FAMILY, epoc::internet::INET_TCP_PROTOCOL_ID);
        }

        const host_iap *target = get_default_host_iap();

        if (!target) {
            LOG_ERROR(SERVICE_ESOCK, "No host network interface is available to start a connection with");
            return nullptr;
        }

        std::unique_ptr<host_connection> conn = std::make_unique<host_connection>(bridged, saddress{}, target->id_);

        if (!conn->start()) {
            return nullptr;
        }

        return conn;
    }
}
