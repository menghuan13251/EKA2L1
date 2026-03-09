/*
 * Copyright (c) 2020 EKA2L1 Team
 *
 * This file is part of EKA2L1 project.
 */

#include <services/socket/common.h>
#include <services/socket/connection.h>
#include <services/socket/server.h>
#include <services/socket/socket.h>

#include <common/log.h>
#include <system/epoc.h>
#include <utils/err.h>

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

    socket_connection_proxy::socket_connection_proxy(socket_client_session *parent, connection *conn)
        : socket_subsession(parent)
        , conn_(conn)
        , progress_reported_(false) {
    }

    void socket_connection_proxy::progress_notify(service::ipc_context *ctx) {
        if (!progress_reported_) {
            epoc::socket::conn_progress progress;
            progress.error_ = 0;
            // 模拟“已连接”状态：KConnectionUp (0x06) 或 KConfigDaemonFinished
            progress.stage_ = epoc::socket::conn_progress_connection_opened;

            ctx->write_data_to_descriptor_argument<epoc::socket::conn_progress>(0, progress);
            ctx->complete(epoc::error_none);

            progress_reported_ = true;
            LOG_TRACE(SERVICE_ESOCK, "Connection progress notify: stubbed to 'Opened'");
        } else {
            // 如果已经报告过开启，后续调用暂时挂起或返回完成
            // 某些应用会循环等待进度变化，这里保持简单处理
            ctx->complete(epoc::error_none);
        }
    }

    void socket_connection_proxy::dispatch(service::ipc_context *ctx) {
        if (parent_->is_oldarch()) {
            switch (ctx->msg->function) {
            case socket_cn_start:
            case socket_reform_cn_start:
            case socket_cn_stop:
                ctx->complete(epoc::error_none);
                break;

            case socket_cm_api_ext_interface_send_receive:
                ctx->complete(epoc::error_not_supported);
                break;

            default:
                LOG_ERROR(SERVICE_ESOCK, "Unimplemented old-arch connection opcode: {}", ctx->msg->function);
                ctx->complete(epoc::error_none);
                break;
            }
        } else {
            // 处理 Symbian OS 9.1+ (EKA2)
            if (ctx->sys->get_symbian_version_use() >= epocver::epoc95) {
                switch (ctx->msg->function) {
                case socket_cn_start:
                case socket_cn_stop:
                    ctx->complete(epoc::error_none);
                    break;

                case socket_cn_progress_notification: // 补全：9.5+ 版本的进度通知处理
                    progress_notify(ctx);
                    break;

                case socket_cm_api_ext_interface_send_receive:
                    ctx->complete(epoc::error_not_supported);
                    break;

                default:
                    LOG_ERROR(SERVICE_ESOCK, "Unimplemented 9.5+ connection opcode: {}", ctx->msg->function);
                    ctx->complete(epoc::error_none);
                    break;
                }
            } else {
                // 处理 Symbian OS 9.1 以下的 EKA2 (如初期版本的 9.1)
                switch (ctx->msg->function) {
                case socket_cn_start:
                case socket_cn_stop:
                    ctx->complete(epoc::error_none);
                    break;

                case socket_cm_api_ext_interface_send_receive:
                    ctx->complete(epoc::error_not_supported);
                    break;

                case socket_cn_progress_notification:
                    progress_notify(ctx);
                    break;

                default:
                    LOG_ERROR(SERVICE_ESOCK, "Unimplemented EKA2 connection opcode: {}", ctx->msg->function);
                    ctx->complete(epoc::error_none);
                    break;
                }
            }
        }
    }
}