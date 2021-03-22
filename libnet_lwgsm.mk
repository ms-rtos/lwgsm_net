#*********************************************************************************************************
#
#                                 北京翼辉信息技术有限公司
#
#                                   微型安全实时操作系统
#
#                                       MS-RTOS(TM)
#
#                               Copyright All Rights Reserved
#
#--------------文件信息--------------------------------------------------------------------------------
#
# 文   件   名: libnet_lwgsm.mk
#
# 创   建   人: IoT Studio
#
# 文件创建日期: 2021 年 02 月 17 日
#
# 描        述: 本文件由 IoT Studio 生成，用于配置 Makefile 功能，请勿手动修改
#*********************************************************************************************************

#*********************************************************************************************************
# Clear setting
#*********************************************************************************************************
include $(CLEAR_VARS_MK)

#*********************************************************************************************************
# Target
#*********************************************************************************************************
LOCAL_TARGET_NAME := libnet_lwgsm.a

#*********************************************************************************************************
# Source list
#*********************************************************************************************************
LOCAL_SRCS :=  \
src/lwgsm/lwgsm/src/api/lwgsm_netconn.c \
src/lwgsm/lwgsm/src/api/lwgsm_network_api.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_buff.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_call.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_conn.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_debug.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_device_info.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_evt.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_ftp.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_http.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_input.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_int.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_mem.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_network.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_operator.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_parser.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_pbuf.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_phonebook.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_ping.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_sim.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_sms.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_threads.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_timeout.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_unicode.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_ussd.c \
src/lwgsm/lwgsm/src/lwgsm/lwgsm_utils.c \
src/ms_net_lwgsm_porting.c \
src/ms_net_lwgsm.c

#*********************************************************************************************************
# Header file search path (eg. LOCAL_INC_PATH := -I"Your header files search path")
#*********************************************************************************************************
LOCAL_INC_PATH := \
-I"src/lwgsm/lwgsm/src/include" \
-I"src"

#*********************************************************************************************************
# Pre-defined macro (eg. -DYOUR_MARCO=1)
#*********************************************************************************************************
LOCAL_DSYMBOL := \
-D__MS_KERNEL_SPACE

#*********************************************************************************************************
# Compiler flags
#*********************************************************************************************************
LOCAL_CFLAGS   := 
LOCAL_CXXFLAGS := 
LOCAL_LINKFLAGS := 

#*********************************************************************************************************
# Depend library (eg. LOCAL_DEPEND_LIB := -la LOCAL_DEPEND_LIB_PATH := -L"Your library search path")
#*********************************************************************************************************
LOCAL_DEPEND_LIB      := 
LOCAL_DEPEND_LIB_PATH := 

#*********************************************************************************************************
# C++ config
#*********************************************************************************************************
LOCAL_USE_CXX        := no
LOCAL_USE_CXX_EXCEPT := no

#*********************************************************************************************************
# Code coverage config
#*********************************************************************************************************
LOCAL_USE_GCOV := no

#*********************************************************************************************************
# Use short command for link and ar
#*********************************************************************************************************
LOCAL_USE_SHORT_CMD := no

#*********************************************************************************************************
# User link command
#*********************************************************************************************************
LOCAL_PRE_LINK_CMD   := 
LOCAL_POST_LINK_CMD  := 
LOCAL_PRE_STRIP_CMD  := 
LOCAL_POST_STRIP_CMD := 

#*********************************************************************************************************
# Depend target
#*********************************************************************************************************
LOCAL_DEPEND_TARGET := 

include $(KERNEL_LIBRARY_MK)

#*********************************************************************************************************
# End
#*********************************************************************************************************
