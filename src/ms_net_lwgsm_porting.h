/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_lwgsm_porting.h lwgsm MS-RTOS porting.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#ifndef MS_NET_LWGSM_PORTING_H
#define MS_NET_LWGSM_PORTING_H

#include <stdint.h>
#include <stdlib.h>
#include "lwgsm/lwgsm_opt.h"
#include "ms_rtos.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if LWGSM_CFG_OS && !__DOXYGEN__

typedef ms_handle_t                 lwgsm_sys_mutex_t;
typedef ms_handle_t                 lwgsm_sys_sem_t;
typedef ms_handle_t                 lwgsm_sys_mbox_t;
typedef ms_handle_t                 lwgsm_sys_thread_t;
typedef ms_handle_t                 lwgsm_sys_thread_prio_t;

#define LWGSM_SYS_MUTEX_NULL        ((lwgsm_sys_mutex_t)MS_HANDLE_INVALID)
#define LWGSM_SYS_SEM_NULL          ((lwgsm_sys_sem_t)MS_HANDLE_INVALID)
#define LWGSM_SYS_MBOX_NULL         ((lwgsm_sys_mbox_t)MS_HANDLE_INVALID)
#define LWGSM_SYS_TIMEOUT           ((uint32_t)MS_TIMEOUT_FOREVER)
#define LWGSM_SYS_THREAD_PRIO       (16)
#define LWGSM_SYS_THREAD_SS         (1024)

int ms_lwgsm_socket_poll_notify(ms_ptr_t ctx, ms_pollevent_t event);

#endif /* LWGSM_CFG_OS && !__DOXYGEN__ */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MS_NET_LWGSM_PORTING_H */
