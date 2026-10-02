// SPDX-License-Identifier: GPL-2.0
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include "access.h"

static unsigned int allowed_uid = 1000;
module_param(allowed_uid, uint, 0);
MODULE_PARM_DESC(allowed_uid, "Non-root UID allowed to access /dev/map (temporary testing)");

bool map_is_self_target(pid_t target_pid) {
	return target_pid == task_pid_nr(current);
}

bool map_caller_allowed(void) {
	if (capable(CAP_SYS_ADMIN)) return true;

	return __kuid_val(current_euid()) == allowed_uid;
}
