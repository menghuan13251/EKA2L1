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

#include <services/internet/nifman.h>
#include <services/socket/server.h>
#include <system/epoc.h>

#include <common/cvt.h>
#include <common/log.h>
#include <utils/err.h>

namespace eka2l1 {
    nifman_server::nifman_server(eka2l1::system *sys)
        : service::typical_server(sys, "NifmanServer")
        , sock_serv_(nullptr) {
    }

    void nifman_server::connect(service::ipc_context &context) {
        if (!sock_serv_) {
            sock_serv_ = reinterpret_cast<socket_server *>(kern->get_by_name<service::server>(
                get_socket_server_name_by_epocver(kern->get_epoc_version())));
        }

        create_session<nifman_client_session>(&context);
        context.complete(epoc::error_none);
    }

    nifman_client_session::nifman_client_session(service::typical_server *serv, const kernel::uid ss_id,
        epoc::version client_version)
        : service::typical_session(serv, ss_id, client_version)
        , agent_(nullptr)
        , conn_(nullptr) {
    }

    void nifman_client_session::open(service::ipc_context *ctx) {
        std::optional<std::u16string> agt_name = ctx->get_argument_value<std::u16string>(0);
        if (!agt_name.has_value()) {
            ctx->complete(epoc::error_argument);
            return;
        }

        // Find this connect agent in socket server
        socket_server *ssock = server<nifman_server>()->get_socket_server();
        if (!ssock) {
            LOG_ERROR(SERVICE_INTERNET, "Nifman requires HLE Socket server to be present!");
            ctx->complete(epoc::error_not_supported);

            return;
        }

        agent_ = ssock->get_connect_agent(agt_name.value());
        if (!agent_) {
            LOG_ERROR(SERVICE_INTERNET, "Agent with name {} not found!", common::ucs2_to_utf8(agt_name.value()));
            ctx->complete(epoc::error_not_found);

            return;
        }

        ctx->complete(epoc::error_none);
    }

    void nifman_client_session::get_active_settings(service::ipc_context *ctx, const epoc::socket::setting_type type) {
        // We mock this even if no real connection is established, to please HTTP applications
        // checking the active IAP ID.

        std::optional<std::u16string> table_name = ctx->get_argument_value<std::u16string>(0);
        std::optional<std::u16string> column_name = ctx->get_argument_value<std::u16string>(1);

        if (!table_name.has_value() || !column_name.has_value()) {
            ctx->complete(epoc::error_argument);
            return;
        }

        const std::u16string setting_name = table_name.value() + u"\\" + column_name.value();

        std::uint8_t *dest_buffer = ctx->get_descriptor_argument_ptr(2);
        std::size_t max_size = ctx->get_argument_max_data_size(2);

        if (!dest_buffer) {
            ctx->complete(epoc::error_argument);
            return;
        }

        if (type == epoc::socket::setting_type_int) {
            if (max_size >= 4) {
                // Return a dummy IAP ID (e.g. 1)
                std::uint32_t simulated_id = 1;
                std::memcpy(dest_buffer, &simulated_id, 4);
                res = 4;
            } else {
                res = max_size; // Truncated but whatever
            }
        } else {
            // Unhandled setting type, just zero it or return empty
            std::memset(dest_buffer, 0, max_size);
            res = max_size;
        }

        ctx->set_descriptor_argument_length(2, static_cast<std::uint32_t>(res));
        ctx->complete(epoc::error_none);
    }

    void nifman_client_session::fetch(service::ipc_context *ctx) {
        switch (ctx->msg->function) {
        case nifman_open:
            open(ctx);
            break;

        case nifman_get_active_int_setting:
            get_active_settings(ctx, epoc::socket::setting_type_int);
            return;

        default:
            LOG_ERROR(SERVICE_INTERNET, "Unimplemented opcode for NifMan 0x{:X}, complete all", ctx->msg->function);
            ctx->complete(epoc::error_none);

            break;
        }
    }
}
