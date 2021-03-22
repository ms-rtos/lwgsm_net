/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_lwgsm.c lwgsm network implement.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#ifndef MS_NET_ESP_AT_H
#define MS_NET_ESP_AT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MS_KERNEL_SPACE
/**
 * @brief Initialize lwgsm network component.
 *
 * @param[in] init_done_callback    Pointer to lwgsm network initialize done call back function
 * @param[in] arg                   The argument of init_done_callback
 *
 * @return Error number
 */
ms_err_t ms_lwgsm_net_init(void (*init_done_callback)(ms_ptr_t arg), ms_ptr_t arg);

#endif

#ifdef __cplusplus
}
#endif

#endif /* MS_NET_ESP_AT_H */
