/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MAP_ACCESS_H
#define MAP_ACCESS_H

#include <linux/types.h>

bool map_caller_allowed(void);
bool map_is_self_target(pid_t target_pid);

#endif
