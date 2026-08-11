/*
 * Copyright (c) 2024 EKA2L1 Team
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
 * along with this program.  See <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <kernel/server.h>
#include <services/framework.h>

namespace eka2l1 {
    /**
     * \brief Dbms (Database Management System) server.
     *
     * Symbian's CommDB access point list, and most system databases, are read by
     * the guest through the Dbms server (RDbs / RDbNamedDatabase). EKA2L1 never
     * implemented this server, so the "Select access point" dialog always shows
     * an empty list. This is a first-stage skeleton that accepts connections and
     * logs every IPC it receives, so we can capture the exact opcodes/arguments
     * the guest sends (especially when opening CommDB and enumerating the IAP
     * table) before implementing the real backend.
     */
    class dbms_server : public service::typical_server {
    public:
        explicit dbms_server(eka2l1::system *sys, const std::string &name);
        void connect(service::ipc_context &context) override;
    };

    struct dbms_client_session : public service::typical_session {
        explicit dbms_client_session(service::typical_server *serv, const kernel::uid ss_id, epoc::version client_version);
        void fetch(service::ipc_context *ctx) override;
    };
}
