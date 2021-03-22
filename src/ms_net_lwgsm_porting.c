/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_lwgsm_porting.c lwgsm MS-RTOS porting.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#include "system/lwgsm_sys.h"

#if !__DOXYGEN__

static ms_handle_t ms_lwgsm_lockid;

uint8_t
lwgsm_sys_init(void) {
    lwgsm_sys_mutex_create(&ms_lwgsm_lockid);
    return 1;
}

uint32_t
lwgsm_sys_now(void) {
    return ms_time_get();
}

uint8_t
lwgsm_sys_protect(void) {
    return ms_mutex_lock(ms_lwgsm_lockid, MS_TIMEOUT_FOREVER) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_unprotect(void) {
    return ms_mutex_unlock(ms_lwgsm_lockid) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_mutex_create(lwgsm_sys_mutex_t* p) {
    return ms_mutex_create("lwgsm_mutex", MS_WAIT_TYPE_PRIO, p) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_mutex_delete(lwgsm_sys_mutex_t* p) {
    return ms_mutex_destroy(*p) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_mutex_lock(lwgsm_sys_mutex_t* p) {
    return ms_mutex_lock(*p, MS_TIMEOUT_FOREVER) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_mutex_unlock(lwgsm_sys_mutex_t* p) {
    return ms_mutex_unlock(*p) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_mutex_isvalid(lwgsm_sys_mutex_t* p) {
    return p != MS_NULL && *p != LWGSM_SYS_MUTEX_NULL;
}

uint8_t
lwgsm_sys_mutex_invalid(lwgsm_sys_mutex_t* p) {
    *p = LWGSM_SYS_MUTEX_NULL;
    return 1;
}

uint8_t
lwgsm_sys_sem_create(lwgsm_sys_sem_t* p, uint8_t cnt) {
    return ms_semb_create("lwgsm_semb", cnt > 0 ? MS_TRUE : MS_FALSE, MS_WAIT_TYPE_PRIO, p) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_sem_delete(lwgsm_sys_sem_t* p) {
    return ms_semb_destroy(*p) == MS_ERR_NONE;
}

uint32_t
lwgsm_sys_sem_wait(lwgsm_sys_sem_t* p, uint32_t timeout) {
    ms_tick64_t tick = ms_time_get();
    return (ms_semb_wait(*p, timeout == 0 ? MS_TIMEOUT_FOREVER : timeout) == MS_ERR_NONE) ? \
            (ms_time_get() - tick) : LWGSM_SYS_TIMEOUT;
}

uint8_t
lwgsm_sys_sem_release(lwgsm_sys_sem_t* p) {
    return ms_semb_post(*p) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_sem_isvalid(lwgsm_sys_sem_t* p) {
    return p != MS_NULL && *p != LWGSM_SYS_SEM_NULL;
}

uint8_t
lwgsm_sys_sem_invalid(lwgsm_sys_sem_t* p) {
    *p = LWGSM_SYS_SEM_NULL;
    return 1;
}

uint8_t
lwgsm_sys_mbox_create(lwgsm_sys_mbox_t* b, size_t size) {
    void *msg_buf = ms_kmalloc(size * sizeof(void *));
    uint8_t ret = 0;

    if (msg_buf != MS_NULL) {
        if (ms_mqueue_create("lwgsm_mq", msg_buf, size, sizeof(void *),
                             MS_WAIT_TYPE_PRIO, b) != MS_ERR_NONE) {
            ms_kfree(msg_buf);
        } else {
            ret = 1;
        }
    }

    return ret;
}

uint8_t
lwgsm_sys_mbox_delete(lwgsm_sys_mbox_t* b) {
    uint8_t ret = 0;
    ms_mqueue_stat_t stat;

    if ((ms_mqueue_stat(*b, &stat) == MS_ERR_NONE) && (stat.msg_count == 0)) {
        if (ms_mqueue_destroy(*b) == MS_ERR_NONE) {
            ms_kfree(stat.msg_buf);
            ret = 1;
        }
    }

    return ret;
}

uint32_t
lwgsm_sys_mbox_put(lwgsm_sys_mbox_t* b, void* m) {
    ms_tick64_t tick = ms_time_get();
    return ms_mqueue_post(*b, &m, MS_TIMEOUT_FOREVER) == MS_ERR_NONE ? \
            (ms_time_get() - tick) : LWGSM_SYS_TIMEOUT;
}

uint32_t
lwgsm_sys_mbox_get(lwgsm_sys_mbox_t* b, void** m, uint32_t timeout) {
    ms_tick64_t tick = ms_time_get();
    return (ms_mqueue_wait(*b, m, timeout == 0 ? MS_TIMEOUT_FOREVER : timeout) == MS_ERR_NONE) ? \
            (ms_time_get() - tick) : LWGSM_SYS_TIMEOUT;
}

uint8_t
lwgsm_sys_mbox_putnow(lwgsm_sys_mbox_t* b, void* m) {
    return ms_mqueue_post(*b, &m, MS_TIMEOUT_NO_WAIT) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_mbox_getnow(lwgsm_sys_mbox_t* b, void** m) {
    return ms_mqueue_wait(*b, m, MS_TIMEOUT_NO_WAIT) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_mbox_isvalid(lwgsm_sys_mbox_t* b) {
    return b != MS_NULL && *b != LWGSM_SYS_MBOX_NULL;
}

uint8_t
lwgsm_sys_mbox_invalid(lwgsm_sys_mbox_t* b) {
    *b = LWGSM_SYS_MBOX_NULL;
    return 1;
}

uint8_t
lwgsm_sys_thread_create(lwgsm_sys_thread_t* t, const char* name, lwgsm_sys_thread_fn thread_func, void* const arg, size_t stack_size, lwgsm_sys_thread_prio_t prio) {
    return ms_thread_create(name, (ms_thread_entry_t)thread_func, (ms_ptr_t)arg,
                            stack_size, prio, 0U,
                            MS_THREAD_OPT_SUPER | MS_THREAD_OPT_REENT_EN,
                            t) == MS_ERR_NONE;
}

uint8_t
lwgsm_sys_thread_terminate(lwgsm_sys_thread_t* t) {
    uint8_t ret;

    if (t != MS_NULL) {
        ret = ms_thread_kill(*t) == MS_ERR_NONE;
    } else {
        ret = ms_thread_exit() == MS_ERR_NONE;
    }

    return ret;
}

uint8_t
lwgsm_sys_thread_yield(void) {
    return ms_thread_yield() == MS_ERR_NONE;
}

#endif /* !__DOXYGEN__ */
