#
#
#  kernel/cpt/Makefile
#
#  Copyright (C) 2000-2005  SWsoft
#  All rights reserved.
#
#  Licensing governed by "linux/COPYING.SWsoft" file.

obj-$(CONFIG_VZ_CHECKPOINT) += vzcpt.o vzrst.o

vzcpt-objs := cpt_proc.o cpt_dump.o cpt_obj.o cpt_context.o cpt_process.o \
	cpt_mm.o cpt_files.o cpt_kernel.o \
	cpt_socket.o cpt_socket_in.o cpt_tty.o cpt_sysvipc.o cpt_net.o \
	cpt_conntrack.o cpt_epoll.o cpt_cgroup.o

vzrst-objs := rst_proc.o rst_undump.o rst_context.o rst_process.o \
	rst_mm.o rst_files.o \
	rst_socket.o rst_socket_in.o rst_tty.o rst_sysvipc.o rst_net.o \
	rst_conntrack.o rst_epoll.o rst_delayfs.o rst_cgroup.o

ifeq ($(CONFIG_BEANCOUNTERS), y)
vzcpt-objs += cpt_ubc.o
vzrst-objs += rst_ubc.o
endif

ifeq ($(CONFIG_INOTIFY_USER), y)
vzcpt-objs += cpt_inotify.o
vzrst-objs += rst_inotify.o
endif

vzrst-objs += cpt_exports.o

ifeq ($(CONFIG_VZ_CHECKPOINT), m)
vzrst-objs += cpt_obj.o cpt_kernel.o
endif

ifeq ($(CONFIG_VZ_CHECKPOINT_ITER), y)
vzcpt-objs += cpt_iterative.o
vzrst-objs += rst_iterative.o
endif

ifeq ($(CONFIG_X86_64), y)
vzcpt-objs += cpt_x8664.o
ifeq ($(CONFIG_VZ_CHECKPOINT), m)
vzrst-objs += cpt_x8664.o
endif
endif
