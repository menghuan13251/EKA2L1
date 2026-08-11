/*
 * Copyright (c) 2020 EKA2L1 Team
 * 
 * This file is part of EKA2L1 project
 * (see bentokun.github.com/EKA2L1).
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

#include <services/socket/common.h>
#include <services/socket/connection.h>
#include <services/socket/iap.h>
#include <services/socket/server.h>
#include <services/socket/socket.h>

#include <common/algorithm.h>
#include <common/cvt.h>
#include <common/log.h>
#include <utils/err.h>
#include <system/epoc.h>

#include <cstring>

namespace eka2l1::epoc::socket {
    connection::connection(protocol *pr, saddress dest)
        : pr_(pr)
        , sock_(nullptr)
        , dest_(dest) {
    }

    std::size_t connection::register_progress_advance_callback(progress_advance_callback cb) {
        return progress_callbacks_.add(cb);
    }

    bool connection::remove_progress_advance_callback(const std::size_t handle) {
        return progress_callbacks_.remove(handle);
    }

    void connection::advance_progress(const std::int32_t stage, const std::int32_t error) {
        conn_progress progress;
        progress.stage_ = stage;
        progress.error_ = error;

        for (auto &callback : progress_callbacks_) {
            if (callback) {
                callback(&progress);
            }
        }
    }

    static constexpr std::uint32_t SETTING_TIMEOUT_INFINITE = 0xFFFFFFFF;

    /**
     * @brief Split a CommsDat setting name into its table and column part, lowercased.
     *
     * Setting names arrive in the form "<table>\<column>", but some applications only pass the
     * column. Both forms have to resolve to the same value.
     */
    static void split_setting_name(const std::u16string &setting_name, std::u16string &table, std::u16string &column) {
        const std::u16string lowered = common::lowercase_ucs2_string(setting_name);
        const std::size_t separator = lowered.find_last_of(u'\\');

        if (separator == std::u16string::npos) {
            table.clear();
            column = lowered;
        } else {
            table = lowered.substr(0, separator);
            column = lowered.substr(separator + 1);
        }
    }

    host_connection::host_connection(protocol *pr, saddress dest, const std::uint32_t iap_id)
        : connection(pr, dest)
        , iap_id_(iap_id)
        , started_(false) {
        if (iap_id_ == 0) {
            const host_iap *default_iap = get_default_host_iap();

            if (default_iap) {
                iap_id_ = default_iap->id_;
            }
        }
    }

    const host_iap *host_connection::iap() const {
        const host_iap *result = find_host_iap(iap_id_);

        if (!result) {
            result = get_default_host_iap();
        }

        return result;
    }

    bool host_connection::start() {
        const host_iap *target = iap();

        if (!target) {
            LOG_ERROR(SERVICE_ESOCK, "No access point is available to start a connection with!");
            return false;
        }

        iap_id_ = target->id_;
        started_ = true;

        LOG_INFO(SERVICE_ESOCK, "Connection started on access point {} (\"{}\", host interface {})",
            target->id_, common::ucs2_to_utf8(target->name_), target->host_if_name_);

        advance_progress(conn_progress_connection_opened, epoc::error_none);
        return true;
    }

    void host_connection::stop() {
        if (!started_) {
            return;
        }

        started_ = false;
        advance_progress(conn_progress_connection_closed, epoc::error_none);
    }

    std::optional<std::uint32_t> host_connection::get_int_setting(const std::u16string &setting_name) {
        const host_iap *target = iap();

        if (!target) {
            return std::nullopt;
        }

        std::u16string table;
        std::u16string column;

        split_setting_name(setting_name, table, column);

        // ---- IAP table ----
        if ((column == u"id") || (column == u"iapid") || (column == u"commdb_id")) {
            return target->id_;
        }

        if ((column == u"iapservice") || (column == u"service")) {
            return target->service_id_;
        }

        if ((column == u"iapbearer") || (column == u"bearer")) {
            return target->bearer_id_;
        }

        if ((column == u"iapnetwork") || (column == u"networkid")) {
            return target->network_id_;
        }

        if (column == u"iapnetworkweighting") {
            return 0;
        }

        if ((column == u"location") || (column == u"iaplocation")) {
            return 1;
        }

        if ((column == u"bearerset") || (column == u"iapbearerset") || (column == u"connectiontype")
            || (column == u"iapconnectiontype")) {
            return target->bearer_set_;
        }

        if (column == u"connectionattempts") {
            return 1;
        }

        // ---- Service / bearer tables ----
        if ((column == u"lastsocketactivitytimeout") || (column == u"lastsessionclosedtimeout")
            || (column == u"lastsocketclosedtimeout")) {
            // KMaxTUint32 means "never time out", which matches an always-on host connection.
            return SETTING_TIMEOUT_INFINITE;
        }

        if ((column == u"ipaddrfromserver") || (column == u"ipdnsaddrfromserver")
            || (column == u"ipnetmaskfromserver") || (column == u"ipgatewayfromserver")
            || (column == u"configdaemonmanagername")) {
            // The host stack already configured everything, so the guest must not try to negotiate it.
            return 0;
        }

        if ((column == u"enablelcpextension") || (column == u"disableplaintextauth")
            || (column == u"enableswcomp") || (column == u"usealwaysonline")
            || (column == u"promptforauth") || (column == u"usealwaysonlinemode")) {
            return 0;
        }

        if ((column == u"ifpromptforauth") || (column == u"ifcallbackenabled")) {
            return 0;
        }

        if ((column == u"nifmanenableipv6") || (column == u"ipv6enabled")) {
            return 0;
        }

        if ((column == u"speedmetric") || (column == u"bearertechnology")) {
            return 0;
        }

        if (column == u"maxconnattempts") {
            return 1;
        }

        LOG_WARN(SERVICE_ESOCK, "Unhandled integer connection setting \"{}\", reporting zero",
            common::ucs2_to_utf8(setting_name));

        return 0;
    }

    std::optional<std::u16string> host_connection::get_string_setting(const std::u16string &setting_name) {
        const host_iap *target = iap();

        if (!target) {
            return std::nullopt;
        }

        std::u16string table;
        std::u16string column;

        split_setting_name(setting_name, table, column);

        if ((column == u"name") || (column == u"iapname") || (column == u"connectionname")) {
            if (table == u"network") {
                return target->network_name_;
            }

            return target->name_;
        }

        if ((column == u"iapservicetype") || (column == u"servicetype")) {
            return target->service_type_;
        }

        if ((column == u"iapbearertype") || (column == u"bearertype")) {
            return target->bearer_type_;
        }

        if (column == u"ifname") {
            return common::utf8_to_ucs2(target->host_if_name_);
        }

        if (column == u"ifnetworks") {
            return u"ip";
        }

        if ((column == u"ifparams") || (column == u"ifauthname") || (column == u"ifauthpass")
            || (column == u"ifextraparams")) {
            return u"";
        }

        if ((column == u"ipaddr") || (column == u"iplocaladdr")) {
            return target->ip_address_;
        }

        if (column == u"ipnetmask") {
            return target->ip_netmask_;
        }

        if (column == u"ipgateway") {
            return target->ip_gateway_;
        }

        if ((column == u"ipnameserver1") || (column == u"ip6nameserver1")) {
            return target->ip_name_server_1_;
        }

        if ((column == u"ipnameserver2") || (column == u"ip6nameserver2")) {
            return target->ip_name_server_2_;
        }

        if ((column == u"apn") || (column == u"gprsapn") || (column == u"accesspointname")) {
            return u"internet";
        }

        if (column == u"agent") {
            return u"nullagt.agt";
        }

        if ((column == u"lddname") || (column == u"pddname")) {
            return u"";
        }

        if (column == u"servicecentreaddress") {
            return u"";
        }

        if (column == u"defaultgprs") {
            return target->ip_gateway_;
        }

        LOG_WARN(SERVICE_ESOCK, "Unhandled string connection setting \"{}\", reporting an empty value",
            common::ucs2_to_utf8(setting_name));

        return u"";
    }

    std::size_t host_connection::get_setting(const std::u16string &setting_name, const setting_type type,
        std::uint8_t *dest_buffer, std::size_t avail_size) {
        if (!dest_buffer) {
            return static_cast<std::size_t>(-1);
        }

        switch (type) {
        case setting_type_bool:
        case setting_type_int: {
            std::optional<std::uint32_t> value = get_int_setting(setting_name);

            if (!value.has_value()) {
                return static_cast<std::size_t>(-1);
            }

            if (avail_size < sizeof(std::uint32_t)) {
                return static_cast<std::size_t>(-1);
            }

            const std::uint32_t final_value = (type == setting_type_bool) ? (value.value() ? 1 : 0) : value.value();
            std::memcpy(dest_buffer, &final_value, sizeof(std::uint32_t));

            return sizeof(std::uint32_t);
        }

        case setting_type_des: {
            std::optional<std::u16string> value = get_string_setting(setting_name);

            if (!value.has_value()) {
                return static_cast<std::size_t>(-1);
            }

            const std::size_t byte_size = common::min<std::size_t>(value->length() * sizeof(char16_t), avail_size);
            std::memcpy(dest_buffer, value->data(), byte_size);

            return byte_size;
        }

        default:
            break;
        }

        return static_cast<std::size_t>(-1);
    }

    socket_connection_proxy::socket_connection_proxy(socket_client_session *parent, connection *conn)
        : socket_subsession(parent)
        , conn_(conn)
        , owned_conn_(nullptr)
        , progress_reported_(false) {
    }

    connection *socket_connection_proxy::ensure_connection() {
        if (conn_) {
            return conn_;
        }

        // The guest opened RConnection without going through an agent, which is the usual path on
        // Symbian since the agent is only consulted when the connection is actually started.
        // Create the host-backed connection lazily so settings can be read right away.
        std::unique_ptr<connection> new_conn = std::make_unique<host_connection>(nullptr, saddress{}, 0);

        owned_conn_ = std::move(new_conn);
        conn_ = owned_conn_.get();

        return conn_;
    }

    void socket_connection_proxy::start(service::ipc_context *ctx) {
        connection *conn = ensure_connection();
        host_connection *host_conn = dynamic_cast<host_connection *>(conn);

        if (host_conn) {
            // The guest may hand us a preference package telling which access point it wants.
            std::uint8_t *pref_buffer = ctx->get_descriptor_argument_ptr(0);

            if (pref_buffer) {
                const std::size_t pref_size = ctx->get_argument_data_size(0);
                const std::uint32_t wanted_iap = match_iap_id_from_pref_buffer(pref_buffer, pref_size);

                if (wanted_iap != 0) {
                    host_conn->set_iap_id(wanted_iap);
                }
            }

            if (!host_conn->start()) {
                ctx->complete(epoc::error_could_not_connect);
                return;
            }
        }

        progress_reported_ = false;
        ctx->complete(epoc::error_none);
    }

    void socket_connection_proxy::stop(service::ipc_context *ctx) {
        host_connection *host_conn = dynamic_cast<host_connection *>(conn_);

        if (host_conn) {
            host_conn->stop();
        }

        progress_reported_ = false;
        ctx->complete(epoc::error_none);
    }

    void socket_connection_proxy::get_int_setting(service::ipc_context *ctx) {
        std::optional<std::u16string> setting_name = ctx->get_argument_value<std::u16string>(0);

        if (!setting_name.has_value()) {
            ctx->complete(epoc::error_argument);
            return;
        }

        connection *conn = ensure_connection();

        std::uint8_t *dest = ctx->get_descriptor_argument_ptr(1);
        const std::size_t max_size = ctx->get_argument_max_data_size(1);

        if (!dest || (max_size < sizeof(std::uint32_t))) {
            ctx->complete(epoc::error_argument);
            return;
        }

        std::uint32_t value = 0;
        const std::size_t written = conn->get_setting(setting_name.value(), setting_type_int,
            reinterpret_cast<std::uint8_t *>(&value), sizeof(value));

        if (written == static_cast<std::size_t>(-1)) {
            ctx->complete(epoc::error_not_found);
            return;
        }

        ctx->write_data_to_descriptor_argument<std::uint32_t>(1, value);
        ctx->complete(epoc::error_none);

        LOG_TRACE(SERVICE_ESOCK, "Connection integer setting \"{}\" = {}", common::ucs2_to_utf8(setting_name.value()), value);
    }

    void socket_connection_proxy::get_des_setting(service::ipc_context *ctx) {
        std::optional<std::u16string> setting_name = ctx->get_argument_value<std::u16string>(0);

        if (!setting_name.has_value()) {
            ctx->complete(epoc::error_argument);
            return;
        }

        connection *conn = ensure_connection();

        std::uint8_t setting_data[512];
        const std::size_t written = conn->get_setting(setting_name.value(), setting_type_des, setting_data,
            sizeof(setting_data));

        if (written == static_cast<std::size_t>(-1)) {
            ctx->complete(epoc::error_not_found);
            return;
        }

        const std::u16string result(reinterpret_cast<char16_t *>(setting_data), written / sizeof(char16_t));
        const ipc_arg_type dest_type = ctx->msg->args.get_arg_type(1);

        bool write_result = false;

        if (static_cast<int>(dest_type) & static_cast<int>(ipc_arg_type::flag_16b)) {
            write_result = ctx->write_data_to_descriptor_argument(1, setting_data,
                static_cast<std::uint32_t>(written), nullptr, true);
        } else {
            // The eight bit overload of GetDesSetting expects the value in the narrow encoding.
            const std::string narrowed = common::ucs2_to_utf8(result);
            write_result = ctx->write_data_to_descriptor_argument(1,
                reinterpret_cast<const std::uint8_t *>(narrowed.data()),
                static_cast<std::uint32_t>(narrowed.length()), nullptr, true);
        }

        if (!write_result) {
            ctx->complete(epoc::error_overflow);
            return;
        }

        ctx->complete(epoc::error_none);

        LOG_TRACE(SERVICE_ESOCK, "Connection string setting \"{}\" = \"{}\"",
            common::ucs2_to_utf8(setting_name.value()), common::ucs2_to_utf8(result));
    }

    void socket_connection_proxy::progress_notify(service::ipc_context *ctx) {
        if (!progress_reported_) {
            host_connection *host_conn = dynamic_cast<host_connection *>(conn_);

            epoc::socket::conn_progress progress;
            progress.error_ = 0;
            progress.stage_ = (host_conn && !host_conn->started())
                ? epoc::socket::conn_progress_connection_closed
                : epoc::socket::conn_progress_connection_opened;

            ctx->write_data_to_descriptor_argument<epoc::socket::conn_progress>(0, progress);
            ctx->complete(epoc::error_none);

            progress_reported_ = true;
        }

        // Nothing else is reported: the host link does not change state on its own.
    }

    void socket_connection_proxy::dispatch(service::ipc_context *ctx) {
        if (parent_->is_oldarch()) {
            switch (ctx->msg->function) {
            
            default:
                LOG_ERROR(SERVICE_ESOCK, "Unimplemented socket connection opcode: {}", ctx->msg->function);
                ctx->complete(epoc::error_none);

                break;
            }
        } else {
            if (ctx->sys->get_symbian_version_use() >= epocver::epoc95) {
                switch (ctx->msg->function) {
                case socket_reform_cn_get_long_des_setting:
                    get_des_setting(ctx);
                    break;

                default:
                    LOG_ERROR(SERVICE_ESOCK, "Unimplemented socket connection opcode: {}", ctx->msg->function);
                    ctx->complete(epoc::error_none);

                    break;
                }
            } else {
                switch (ctx->msg->function) {
                case socket_cm_api_ext_interface_send_receive:
                    // Async, but we should complete it in sometimes
                    // Complete with not right result will create stuck or crash sometimes
                    break;

                case socket_cn_start:
                    start(ctx);
                    break;

                case socket_cn_stop:
                    stop(ctx);
                    break;

                case socket_cn_progress_notification:
                    progress_notify(ctx);
                    break;

                case socket_cn_get_int_setting:
                    get_int_setting(ctx);
                    break;

                case socket_cn_get_des_setting:
                case socket_cn_get_long_des_setting:
                    get_des_setting(ctx);
                    break;

                default:
                    LOG_ERROR(SERVICE_ESOCK, "Unimplemented socket connection opcode: {}", ctx->msg->function);
                    ctx->complete(epoc::error_none);

                    break;
                }
            }
        }
    }
}
