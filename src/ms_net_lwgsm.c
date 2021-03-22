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

#define __MS_NET
#define __MS_IO
#include "ms_kern.h"
#include "ms_io_core.h"
#include "ms_net_core.h"

#include "arpa/inet.h"
#include "net/if.h"
#include "net/if_types.h"
#include "net/if_arp.h"
#include "net/if_hwaddr.h"
#include "sys/socket.h"
#include "netdb.h"

#include "lwgsm/lwgsm.h"
#include "lwgsm/lwgsm_private.h"
#include "lwgsm/lwgsm_network_api.h"

#include "ms_net_lwgsm.h"

/**
 * @brief Network.
 */

#define SOCK_ADDR_TYPE_MATCH(name, sock) \
        IS_SOCK_ADDR_TYPE_VALID(name)

#define MS_LWGSM_NET_IMPL_NAME     "ms_lwgsm_net"
#define MS_LWGSM_SOCKET_DRV_NAME   "ms_lwgsm_socket"
#define MS_LWGSM_IF_NAME           "lwgsm"

extern int       lwgsm_msrtos_netconn_ctx_set(lwgsm_netconn_p conn, ms_ptr_t ctx);
extern ms_bool_t lwgsm_msrtos_netconn_readable_check(lwgsm_netconn_p conn);
extern ms_bool_t lwgsm_msrtos_netconn_writable_check(lwgsm_netconn_p conn);
extern ms_bool_t lwgsm_msrtos_netconn_except_check(lwgsm_netconn_p conn);

static int __ms_lwgsm_err_to_errno(lwgsmr_t err)
{
    int ret;

    switch (err) {
    case lwgsmOK:             /*!< Function succeeded */
        ret = 0;
        break;

    case lwgsmOKIGNOREMORE:   /*!< Function succedded, should continue as lwgsmOK but ignore sending more data. This result is possible on connection data receive callback */
        ret = 0;
        break;

    case lwgsmERR:
        ret = EIO;
        break;

    case lwgsmPARERR:         /*!< Wrong parameters on function call */
        ret = EINVAL;
        break;

    case lwgsmERRMEM:         /*!< Memory error occurred */
        ret = ENOMEM;
        break;

    case lwgsmTIMEOUT:        /*!< Timeout occurred on command */
        ret = ETIMEDOUT;
        break;

    case lwgsmCONT:           /*!< There is still some command to be processed in current command */
        ret = EBUSY;
        break;

    case lwgsmCLOSED:         /*!< Connection just closed */
        ret = EBADF;
        break;

    case lwgsmINPROG:         /*!< Operation is in progress */
        ret = EBUSY;
        break;

    case lwgsmERRNOTENABLED:  /*!< Feature not enabled error */
        ret = ENOTSUP;
        break;

    case lwgsmERRNOIP:        /*!< Station does not have IP address */
        ret = EIO;
        break;

    case lwgsmERRNOFREECONN:  /*!< There is no free connection available to start */
        ret = ENOMEM;
        break;

    case lwgsmERRCONNTIMEOUT: /*!< Timeout received when connection to access point */
        ret = ETIMEDOUT;
        break;

    case lwgsmERRPASS:        /*!< Invalid password for access point */
        ret = EINVAL;
        break;

    case lwgsmERRNOAP:        /*!< No access point found with specific SSID and MAC address */
        ret = EIO;
        break;

    case lwgsmERRCONNFAIL:    /*!< Connection failed to access point */
        ret = EIO;
        break;

    case lwgsmERRWIFINOTCONNECTED: /*!< Wifi not connected to access point */
        ret = EIO;
        break;

    case lwgsmERRNODEVICE:    /*!< Device is not present */
        ret = EIO;
        break;

    case lwgsmERRBLOCKING:    /*!< Blocking mode command is not allowed */
        ret = EWOULDBLOCK;
        break;

    default:
        ret = EINVAL;
        break;
    }

    return ret;
}

static int __ms_lwgsm_getpeername(lwgsm_netconn_p conn, struct sockaddr *name, socklen_t *namelen)
{
    int ret = -1;

    if (conn != MS_NULL) {
        if ((conn->type == LWGSM_NETCONN_TYPE_TCP) ||
            (conn->type == LWGSM_NETCONN_TYPE_SSL)) {
            if ((name != MS_NULL) && (namelen != MS_NULL)) {
                union sockaddr_aligned saddr;
                ip_addr_t remote_ip;

                ms_net_ip_addr4(&remote_ip,
                                conn->conn->remote_ip.ip[0],
                                conn->conn->remote_ip.ip[1],
                                conn->conn->remote_ip.ip[2],
                                conn->conn->remote_ip.ip[3]);

                ms_net_ipaddr_port_to_sockaddr(&saddr, &remote_ip, conn->conn->remote_port);
                if (*namelen > saddr.sa.sa_len) {
                    *namelen = saddr.sa.sa_len;
                }
                LWGSM_MEMCPY(name, &saddr, *namelen);

                ret = 0;
            } else {
                ms_thread_set_errno(EINVAL);
            }
        } else {
            ms_thread_set_errno(EOPNOTSUPP);
        }
    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static int __ms_lwgsm_getsockname(lwgsm_netconn_p conn, struct sockaddr *name, socklen_t *namelen)
{
    int ret = -1;

    if (conn != MS_NULL) {
        if ((name != MS_NULL) && (namelen != MS_NULL)) {
            union sockaddr_aligned saddr;
            ip_addr_t local_ip;
            lwgsm_ip_t ip;

            lwgsm_network_copy_ip(&ip);
            ms_net_ip_addr4(&local_ip,
                            ip.ip[0], ip.ip[1], ip.ip[2], ip.ip[3]);

            ms_net_ipaddr_port_to_sockaddr(&saddr, &local_ip, conn->conn->local_port);
            if (*namelen > saddr.sa.sa_len) {
                *namelen = saddr.sa.sa_len;
            }
            LWGSM_MEMCPY(name, &saddr, *namelen);

            ret = 0;
        } else {
            ms_thread_set_errno(EINVAL);
        }
    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static int __ms_lwgsm_getsockopt(lwgsm_netconn_p conn, int level, int optname, void *optval, socklen_t *optlen)
{
    int ret;

    if (optname == SO_RCVTIMEO) {
        struct timeval *tv = (struct timeval *)optval;
        uint32_t timeout;

        lwgsm_core_lock();
        timeout = lwgsm_netconn_get_receive_timeout(conn);
        lwgsm_core_unlock();
        tv->tv_sec  = timeout / 1000;
        tv->tv_usec = (timeout % 1000) * 1000;
        *optlen = sizeof(tv);
        ret = 0;

    } else {
        ms_thread_set_errno(ENOTSUP);
        ret = -1;
    }

    return ret;
}

static int __ms_lwgsm_setsockopt(lwgsm_netconn_p conn, int level, int optname, const void *optval, socklen_t optlen)
{
    int ret;

    if (optname == SO_RCVTIMEO) {
        struct timeval *tv = (struct timeval *)optval;
        uint32_t timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;

        lwgsm_core_lock();
        lwgsm_netconn_set_receive_timeout(conn, timeout);
        lwgsm_core_unlock();
        ret = 0;

    } else {
        ms_thread_set_errno(ENOTSUP);
        ret = -1;
    }

    return ret;
}

static int __ms_lwgsm_connect(lwgsm_netconn_p conn, const struct sockaddr *name, socklen_t namelen)
{
    int ret = -1;

    if (conn != MS_NULL) {
        if (SOCK_ADDR_TYPE_MATCH(name, conn)) {
            ip_addr_t remote_addr;
            u16_t remote_port;
            char ip_str[IP4ADDR_STRLEN_MAX];
            lwgsmr_t err;

            LWIP_UNUSED_ARG(namelen);

            /* check size, family and alignment of 'name' */
            LWIP_ERROR("__ms_lwgsm_connect: invalid address", IS_SOCK_ADDR_LEN_VALID(namelen) &&
                       IS_SOCK_ADDR_TYPE_VALID(name) && IS_SOCK_ADDR_ALIGNED(name),
                       ms_thread_set_errno(EIO); return -1;);

            SOCKADDR_TO_IPADDR_PORT(name, &remote_addr, remote_port);

            inet_ntoa_r(remote_addr, ip_str, sizeof(ip_str));

            err = lwgsm_netconn_connect(conn, ip_str, remote_port);
            if (err == lwgsmOK) {
                ret = 0;
            } else {
                ms_thread_set_errno(__ms_lwgsm_err_to_errno(err));
            }
        } else {
            ms_thread_set_errno(EINVAL);
        }
    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static ssize_t __ms_lwgsm_netconn_send(lwgsm_netconn_p conn, const void *dataptr, size_t size, int flags)
{
    lwgsmr_t err;
    ssize_t ret;

    switch (conn->type) {
    case LWGSM_NETCONN_TYPE_TCP:
    case LWGSM_NETCONN_TYPE_SSL:
        err = lwgsm_netconn_write(conn, dataptr, size);
        break;

    case LWGSM_NETCONN_TYPE_UDP:
        err = lwgsm_netconn_send(conn, dataptr, size);
        break;

    default:
        err = lwgsmERR;
        break;
    }

    if (err == lwgsmOK) {
        ret = size;
    } else {
        ms_thread_set_errno(__ms_lwgsm_err_to_errno(err));
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_lwgsm_netconn_recv(lwgsm_netconn_p conn, void *buf, size_t size, int flags, struct sockaddr *from, socklen_t *fromlen)
{
    lwgsm_pbuf_p pbuf;
    lwgsmr_t err;
    ssize_t ret;

    err = lwgsm_netconn_receive(conn, &pbuf);
    if (err == lwgsmOK) {
        ret = lwgsm_pbuf_copy(pbuf, buf, size, 0);

        if ((from != MS_NULL) && (fromlen != MS_NULL)) {
            union sockaddr_aligned saddr;
            ip_addr_t remote_ip;

            ms_net_ip_addr4(&remote_ip,
                            pbuf->ip.ip[0], pbuf->ip.ip[1], pbuf->ip.ip[2], pbuf->ip.ip[3]);

            ms_net_ipaddr_port_to_sockaddr(&saddr, &remote_ip, pbuf->port);
            if (*fromlen > saddr.sa.sa_len) {
                *fromlen = saddr.sa.sa_len;
            }
            LWGSM_MEMCPY(from, &saddr, *fromlen);
        }

        lwgsm_pbuf_free(pbuf);

    } else {
        ms_thread_set_errno(__ms_lwgsm_err_to_errno(err));
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_lwgsm_recv(lwgsm_netconn_p conn, void *mem, size_t len, int flags)
{
    ssize_t ret;

    if (conn != MS_NULL) {
        ret = __ms_lwgsm_netconn_recv(conn, mem, len, flags, MS_NULL, MS_NULL);

    } else {
        ms_thread_set_errno(EBADF);
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_lwgsm_recvfrom(lwgsm_netconn_p conn, void *mem, size_t len, int flags,
                                   struct sockaddr *from, socklen_t *fromlen)
{
    ssize_t ret;

    if (conn != MS_NULL) {
        ret = __ms_lwgsm_netconn_recv(conn, mem, len, flags, from, fromlen);

    } else {
        ms_thread_set_errno(EBADF);
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_lwgsm_send(lwgsm_netconn_p conn, const void *dataptr, size_t size, int flags)
{
    ssize_t ret;

    if (conn != MS_NULL) {
        ret = __ms_lwgsm_netconn_send(conn, dataptr, size, flags);

    } else {
        ms_thread_set_errno(EBADF);
        ret = -1;
    }

    return ret;
}

static ssize_t __ms_lwgsm_sendto(lwgsm_netconn_p conn, const void *dataptr, size_t size, int flags,
                                 const struct sockaddr *to, socklen_t tolen)
{
    ssize_t ret = -1;

    if (conn != MS_NULL) {
        lwgsmr_t err;

        switch (conn->type) {
        case LWGSM_NETCONN_TYPE_TCP:
        case LWGSM_NETCONN_TYPE_SSL:
            err = lwgsm_netconn_write(conn, dataptr, size);
            break;

        case LWGSM_NETCONN_TYPE_UDP: {
            u16_t remote_port;
            ip_addr_t remote_addr;

            LWIP_ERROR("__ms_lwgsm_sendto: invalid address", (((to == MS_NULL) && (tolen == 0)) ||
                       (IS_SOCK_ADDR_LEN_VALID(tolen) &&
                       ((to != MS_NULL) && (IS_SOCK_ADDR_TYPE_VALID(to) && IS_SOCK_ADDR_ALIGNED(to))))),
                       ms_thread_set_errno(EIO); return -1;);
            LWIP_UNUSED_ARG(tolen);

            if (to != MS_NULL) {
                SOCKADDR_TO_IPADDR_PORT(to, &remote_addr, remote_port);
            } else {
                remote_port = 0;
                ms_net_ip_addr_set_any(MS_FALSE, &remote_addr);
            }

            err = lwgsm_netconn_sendto(conn, (const lwgsm_ip_t*)&remote_addr, remote_port,
                                       dataptr, size);
        }
        break;

        default:
            err = lwgsmERR;
            break;
        }

        if (err == lwgsmOK) {
            ret = size;
        } else {
            ms_thread_set_errno(__ms_lwgsm_err_to_errno(err));
        }

    } else {
        ms_thread_set_errno(EBADF);
    }

    return ret;
}

static char *__ms_lwgsm_if_indextoname(unsigned int ifindex, char *ifname)
{
    if (ifname != MS_NULL) {
        strcpy(ifname, MS_LWGSM_IF_NAME);
    }

    return ifname;
}

static unsigned int __ms_lwgsm_if_nametoindex(const char *ifname)
{
    return 0U;
}

/*
 * Open socket device
 */
static int __ms_lwgsm_socket_open(ms_ptr_t ctx, ms_io_file_t *file, int oflag, ms_mode_t mode)
{
    int ret;

    if (ms_atomic_inc(MS_IO_DEV_REF(file)) == 1) {
        ms_io_device_t *dev = MS_IO_FILE_TO_DEV(file);
        ms_net_socket_device_t *sock_dev = MS_CONTAINER_OF(dev, ms_net_socket_device_t, dev);

        ret = lwgsm_msrtos_netconn_ctx_set((lwgsm_netconn_p)ctx, sock_dev);

        file->type |= MS_IO_FILE_TYPE_SOCK;

    } else {
        ms_atomic_dec(MS_IO_DEV_REF(file));
        ms_thread_set_errno(EBUSY);
        ret = -1;
    }

    return ret;
}

/*
 * Close socket device
 */
static int __ms_lwgsm_socket_close(ms_ptr_t ctx, ms_io_file_t *file)
{
    int ret;

    if (ms_atomic_dec(MS_IO_DEV_REF(file)) == 0) {
        lwgsmr_t err;

        (void)lwgsm_netconn_close((lwgsm_netconn_p)ctx);
        err = lwgsm_netconn_delete((lwgsm_netconn_p)ctx);
        if (err == lwgsmOK) {
            ms_io_device_t *dev = MS_IO_FILE_TO_DEV(file);
            ms_net_socket_device_t *sock_dev = MS_CONTAINER_OF(dev, ms_net_socket_device_t, dev);

            (void)ms_io_device_unregister(dev);
            (void)ms_kfree(sock_dev);
            ret = 0;
        } else {
            ms_thread_set_errno(__ms_lwgsm_err_to_errno(err));
            ret = -1;
        }
    } else {
        ret = 0;
    }

    return ret;
}

/*
 * Read socket device
 */
static ssize_t __ms_lwgsm_socket_read(ms_ptr_t ctx, ms_io_file_t *file, ms_ptr_t buf, size_t len)
{
    return __ms_lwgsm_netconn_recv((lwgsm_netconn_p)ctx, buf, len, 0, MS_NULL, MS_NULL);
}

/*
 * Write socket device
 */
static ssize_t __ms_lwgsm_socket_write(ms_ptr_t ctx, ms_io_file_t *file, ms_const_ptr_t buf, size_t len)
{
    return __ms_lwgsm_netconn_send((lwgsm_netconn_p)ctx, buf, len, 0);;
}

/*
 * Control socket device
 */
static int __ms_lwgsm_socket_ioctl(ms_ptr_t ctx, ms_io_file_t *file, int cmd, ms_ptr_t arg)
{
    struct ifreq *pifreq;
    lwgsmr_t err;
    int ret;

    switch (cmd) {
    case SIOCGIFADDR: {
        struct sockaddr_in *psockaddrin;
        lwgsm_ip_t ip;

        pifreq = (struct ifreq *)arg;

        psockaddrin = (struct sockaddr_in *)&(pifreq->ifr_addr);
        psockaddrin->sin_len    = sizeof(struct sockaddr_in);
        psockaddrin->sin_family = AF_INET;
        psockaddrin->sin_port   = 0;

        err = lwgsm_network_copy_ip(&ip);
        if (err == lwgsmOK) {
            psockaddrin->sin_addr.s_addr = htonl(LWIP_MAKEU32(ip.ip[0], ip.ip[1], ip.ip[2], ip.ip[3]));
            ret = 0;
        } else {
            ms_thread_set_errno(__ms_lwgsm_err_to_errno(err));
            ret = -1;
        }
    }
        break;

    case SIOCGIFFLAGS: {
        ms_uint32_t flags = IFF_UP;

        pifreq = (struct ifreq *)arg;

        if (lwgsm_network_is_attached()) {
            flags |= IFF_RUNNING;
        }
        pifreq->ifr_flags = flags;
        ret = 0;
    }
        break;

    case SIOCSIFFLAGS:
        pifreq = (struct ifreq *)arg;

        if (pifreq->ifr_flags & IFF_UP) {
            err = lwgsm_network_request_attach();
        } else {
            err = lwgsm_network_request_detach();
        }
        if (err == lwgsmOK) {
            ret = 0;
        } else {
            ms_thread_set_errno(__ms_lwgsm_err_to_errno(err));
            ret = -1;
        }
        break;

    default:
        ms_thread_set_errno(EOPNOTSUPP);
        ret = -1;
        break;
    }

    return ret;
}

/*
 * Control socket device
 */
static int __ms_lwgsm_socket_fcntl(ms_ptr_t ctx, ms_io_file_t *file, int cmd, int arg)
{
    int ret;

    /*
     * TODO
     */
    ret = 0;
    if ((ret == 0) && (cmd == F_SETFL)) {
        file->flags = arg;
    }

    return ret;
}

/*
 * Check socket device readable
 */
static ms_bool_t __ms_lwgsm_socket_readable_check(ms_ptr_t ctx)
{
    return lwgsm_msrtos_netconn_readable_check((lwgsm_netconn_p)ctx);
}

/*
 * Check socket device writable
 */
static ms_bool_t __ms_lwgsm_socket_writable_check(ms_ptr_t ctx)
{
    return lwgsm_msrtos_netconn_writable_check((lwgsm_netconn_p)ctx);
}

/*
 * Check socket device exception
 */
static ms_bool_t __ms_lwgsm_socket_except_check(ms_ptr_t ctx)
{
    return lwgsm_msrtos_netconn_except_check((lwgsm_netconn_p)ctx);
}

/*
 * Socket device notify
 */
int ms_lwgsm_socket_poll_notify(ms_ptr_t ctx, ms_pollevent_t event)
{
    ms_net_socket_device_t *sock_dev = (ms_net_socket_device_t *)ctx;

    return ms_io_poll_notify_helper(sock_dev->slots, MS_ARRAY_SIZE(sock_dev->slots), event);
}

/*
 * Poll socket device
 */
static int __ms_lwgsm_socket_poll(ms_ptr_t ctx, ms_io_file_t *file, ms_pollfd_t *fds, ms_bool_t setup)
{
    ms_io_device_t *dev = MS_IO_FILE_TO_DEV(file);
    ms_net_socket_device_t *sock_dev = MS_CONTAINER_OF(dev, ms_net_socket_device_t, dev);

    return ms_io_poll_helper(fds, sock_dev->slots, MS_ARRAY_SIZE(sock_dev->slots), setup, ctx,
                             __ms_lwgsm_socket_readable_check,
                             __ms_lwgsm_socket_writable_check,
                             __ms_lwgsm_socket_except_check);
}

/*
 * Socket device operating function set
 */
static ms_io_driver_ops_t ms_lwgsm_socket_drv_ops = {
        .type     = MS_IO_DRV_TYPE_SOCK,
        .open     = __ms_lwgsm_socket_open,
        .close    = __ms_lwgsm_socket_close,
        .write    = __ms_lwgsm_socket_write,
        .read     = __ms_lwgsm_socket_read,
        .ioctl    = __ms_lwgsm_socket_ioctl,
        .fcntl    = __ms_lwgsm_socket_fcntl,
        .poll     = __ms_lwgsm_socket_poll,
};

/*
 * Socket device driver
 */
static ms_io_driver_t ms_lwgsm_socket_drv = {
        .nnode = {
            .name = MS_LWGSM_SOCKET_DRV_NAME,
        },
        .ops = &ms_lwgsm_socket_drv_ops,
};

static int __ms_lwgsm_socket(int domain, int type, int protocol)
{
    lwgsm_netconn_p conn;
    int fd;

    LWIP_UNUSED_ARG(domain);
    LWIP_UNUSED_ARG(protocol);

    /* create a netconn */
    switch (type) {

    case SOCK_DGRAM:
        conn = lwgsm_netconn_new(LWGSM_NETCONN_TYPE_UDP);
        break;

    case SOCK_STREAM:
        conn = lwgsm_netconn_new(LWGSM_NETCONN_TYPE_TCP);
        break;

    case SOCK_SSL:
        conn = lwgsm_netconn_new(LWGSM_NETCONN_TYPE_SSL);
        break;

    default:
        ms_thread_set_errno(EINVAL);
        return -1;
    }

    if (conn == MS_NULL) {
        ms_thread_set_errno(ENOBUFS);
        return -1;
    }

    fd = ms_net_socket_attach(MS_LWGSM_NET_IMPL_NAME, conn);
    if (fd < 0) {
        lwgsm_netconn_delete(conn);
    }

    return fd;
}

static ms_net_impl_ops_t ms_lwgsm_net_impl_ops = {
        .sock_drv_name          = MS_LWGSM_SOCKET_DRV_NAME,
        .socket                 = (ms_net_socket_func_t)__ms_lwgsm_socket,
        .accept                 = (ms_net_accept_func_t)MS_NULL,
        .bind                   = (ms_net_bind_func_t)MS_NULL,
        .getpeername            = (ms_net_getpeername_func_t)__ms_lwgsm_getpeername,
        .getsockname            = (ms_net_getsockname_func_t)__ms_lwgsm_getsockname,
        .getsockopt             = (ms_net_getsockopt_func_t)__ms_lwgsm_getsockopt,
        .setsockopt             = (ms_net_setsockopt_func_t)__ms_lwgsm_setsockopt,
        .connect                = (ms_net_connect_func_t)__ms_lwgsm_connect,
        .listen                 = (ms_net_listen_func_t)MS_NULL,
        .shutdown               = (ms_net_shutdown_func_t)MS_NULL,
        .recv                   = (ms_net_recv_func_t)__ms_lwgsm_recv,
        .recvfrom               = (ms_net_recvfrom_func_t)__ms_lwgsm_recvfrom,
        .recvmsg                = (ms_net_recvmsg_func_t)MS_NULL,
        .send                   = (ms_net_send_func_t)__ms_lwgsm_send,
        .sendmsg                = (ms_net_sendmsg_func_t)MS_NULL,
        .sendto                 = (ms_net_sendto_func_t)__ms_lwgsm_sendto,
        .if_indextoname         = (ms_net_if_indextoname_func_t)__ms_lwgsm_if_indextoname,
        .if_nametoindex         = (ms_net_if_nametoindex_func_t)__ms_lwgsm_if_nametoindex,
        .gethostbyname_addrtype = (ms_net_gethostbyname_addrtype_func_t)MS_NULL,
        .gethostname            = (ms_net_gethostname_func_t)MS_NULL,
        .sethostname            = (ms_net_sethostname_func_t)MS_NULL,
        .getdnsserver           = (ms_net_getdnsserver_func_t)MS_NULL,
        .setdnsserver           = (ms_net_setdnsserver_func_t)MS_NULL,
};

static ms_net_impl_t ms_lwgsm_net_impl = {
        .nnode = {
            .name = MS_LWGSM_NET_IMPL_NAME,
        },
        .ops = &ms_lwgsm_net_impl_ops,
};

/**
 * \brief           RSSI state on network
 */
static int16_t rssi;

/**
 * \brief           Process and print network registration status update
 * \param[in]       evt: GSM event data
 */
static void network_utils_process_reg_change(lwgsm_evt_t* evt)
{
    lwgsm_network_reg_status_t stat;

    stat = lwgsm_network_get_reg_status();        /* Get network status */

    /* Print to console */
    ms_printk(MS_PK_INFO, "LWGSM: Network registration status changed. New status is: ");

    switch (stat) {
    case LWGSM_NETWORK_REG_STATUS_CONNECTED:
        ms_printk(MS_PK_INFO, "Connected to home network!\r\n");
        break;

    case LWGSM_NETWORK_REG_STATUS_CONNECTED_ROAMING:
        ms_printk(MS_PK_INFO, "Connected to network and roaming!\r\n");
        break;

    case LWGSM_NETWORK_REG_STATUS_SEARCHING:
        ms_printk(MS_PK_INFO, "Searching for network!\r\n");
        break;

    case LWGSM_NETWORK_REG_STATUS_SIM_ERR:
        ms_printk(MS_PK_INFO, "SIM CARD ERROR!\r\n");
        break;

    default:
        ms_printk(MS_PK_INFO, "Other\r\n");
    }

    LWGSM_UNUSED(evt);
}

/**
 * \brief           Process and print network current operator status
 * \param[in]       evt: GSM event data
 */
static void network_utils_process_curr_operator(lwgsm_evt_t *evt)
{
    const lwgsm_operator_curr_t *o;

    o = lwgsm_evt_network_operator_get_current(evt);
    if (o != NULL) {
        switch (o->format) {
        case LWGSM_OPERATOR_FORMAT_LONG_NAME:
            ms_printk(MS_PK_INFO, "LWGSM: Operator long name: %s\r\n", o->data.long_name);
            break;

        case LWGSM_OPERATOR_FORMAT_SHORT_NAME:
            ms_printk(MS_PK_INFO, "LWGSM: Operator short name: %s\r\n", o->data.short_name);
            break;

        case LWGSM_OPERATOR_FORMAT_NUMBER:
            ms_printk(MS_PK_INFO, "LWGSM: Operator number: %d\r\n", (int)o->data.num);
            break;

        default:
            break;
        }
    }

    /*
     * Start RSSI info
     */
    lwgsm_network_rssi(&rssi, NULL, NULL, 0);
}

/**
 * \brief           Process and print RSSI info
 * \param[in]       evt: GSM event data
 */
static void network_utils_process_rssi(lwgsm_evt_t *evt)
{
    int16_t rssi;

    /*
     * Get RSSi from event
     */
    rssi = lwgsm_evt_signal_strength_get_rssi(evt);

    /*
     * Print message to screen
     */
    ms_printk(MS_PK_INFO, "LWGSM: Network operator RSSI: %d dBm\r\n", (int)rssi);
}

static lwgsmr_t __ms_lwgsm_callback_func(lwgsm_evt_t *evt)
{
    switch (lwgsm_evt_get_type(evt)) {
    case LWGSM_EVT_INIT_FINISH:
        ms_printk(MS_PK_INFO, "LWGSM: Library initialized!\r\n");
        break;

    /*
     * Process and print registration change
     */
    case LWGSM_EVT_NETWORK_REG_CHANGED:
        ms_printk(MS_PK_INFO, "LWGSM: Network registration change!\n");
        network_utils_process_reg_change(evt);
        break;

    /*
     * Process current network operator
     */
    case LWGSM_EVT_NETWORK_OPERATOR_CURRENT:
        ms_printk(MS_PK_INFO, "LWGSM: Network operator!\n");
        network_utils_process_curr_operator(evt);
        break;
    /*
     * Process signal strength
     */
    case LWGSM_EVT_SIGNAL_STRENGTH:
        ms_printk(MS_PK_INFO, "LWGSM: Signal strength!\n");
        network_utils_process_rssi(evt);
        break;

    /*
     * Other user events here...
     */
    default:
        break;
    }

    return lwgsmOK;
}

/**
 * @brief Initialize lwgsm network component.
 *
 * @param[in] init_done_callback    Pointer to lwgsm network initialize done call back function
 * @param[in] arg                   The argument of init_done_callback
 *
 * @return Error number
 */
ms_err_t ms_lwgsm_net_init(void (*init_done_callback)(ms_ptr_t arg), ms_ptr_t arg)
{
    ms_err_t err;

    err = ms_net_impl_register(&ms_lwgsm_net_impl);
    if (err == MS_ERR_NONE) {

        err = ms_io_driver_register(&ms_lwgsm_socket_drv);
        if (err == MS_ERR_NONE) {
            /*
             * Initialize lwgsm with default callback function
             */
            ms_printk(MS_PK_INFO, "LWGSM: Initializing LWGSM library\n");

            if (lwgsm_init(__ms_lwgsm_callback_func, MS_TRUE) != lwgsmOK) {
                ms_printk(MS_PK_ERR, "LWGSM: Cannot initialize LWGSM library!\n");
                err = MS_ERR;

            } else {
                ms_printk(MS_PK_INFO, "LWGSM: LWGSM library initialized!\n");

                if (init_done_callback != MS_NULL) {
                    init_done_callback(arg);
                }
            }
        }
    }

    return err;
}
