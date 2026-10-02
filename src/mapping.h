/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MAP_MAPPING_H
#define MAP_MAPPING_H

#include <linux/types.h>

struct map_session;
struct map_selector;

/* The caller holds map_mutex and uses the session's owner address space. */
int map_target_pid_into_current(struct map_session *session, pid_t target_pid, const struct map_selector *selector, bool ondemand);
int map_bound_addr_into_current(struct map_session *session, unsigned long addr, bool ondemand);

#endif
