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

#include <common/cvt.h>
#include <services/dbms/dbms.h>
#include <system/epoc.h>
#include <utils/err.h>

namespace eka2l1 {
    dbms_server::dbms_server(eka2l1::system *sys, const std::string &name)
        : service::typical_server(sys, name) {
    }

    void dbms_server::connect(service::ipc_context &context) {
        create_session<dbms_client_session>(&context);
        LOG_WARN(SERVICE_DBMS, "Dbms server: client session created");
        context.complete(epoc::error_none);
    }

    dbms_client_session::dbms_client_session(service::typical_server *serv, const kernel::uid ss_id, epoc::version client_version)
        : service::typical_session(serv, ss_id, client_version) {
    }

    void dbms_client_session::fetch(service::ipc_context *ctx) {
        const std::int32_t func = ctx->msg->function;
        LOG_WARN(SERVICE_DBMS, "Dbms IPC func=0x{:X} (dec {})", func, func);

        // Best-effort dump of the four IPC arguments, so we can see the database
        // name, table name and column/row data the guest is asking for.
        for (int i = 0; i < 4; i++) {
            auto des16 = ctx->get_argument_value<std::u16string>(i);
            if (des16 && !des16.value().empty()) {
                LOG_WARN(SERVICE_DBMS, "  arg[{}] des16 = {}", i, common::ucs2_to_utf8(des16.value()));
                continue;
            }

            auto des8 = ctx->get_argument_value<std::string>(i);
            if (des8 && !des8.value().empty()) {
                LOG_WARN(SERVICE_DBMS, "  arg[{}] des8 = {}", i, des8.value());
                continue;
            }

            auto i32 = ctx->get_argument_value<std::int32_t>(i);
            if (i32) {
                LOG_WARN(SERVICE_DBMS, "  arg[{}] int = 0x{:X} ({})", i, i32.value(), i32.value());
            }
        }

        // Stub: complete everything as success for now, so the guest keeps sending
        // the next IPC and we can capture the full sequence. Real behaviour comes
        // once we know the opcodes.
        ctx->complete(epoc::error_none);
    }
}
