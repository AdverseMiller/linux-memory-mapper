// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/module.h>
#include "device.h"
#include "session.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Map a target process' anonymous VMAs into the caller");
MODULE_VERSION("0.2");

static int __init map_init(void)
{
	int ret;

	ret = map_sessions_init();
	if (ret)
		return ret;
	ret = map_device_register();
	if (ret) {
		map_sessions_exit();
		return ret;
	}
	pr_info("map: loaded, created /dev/map (mode 0666)\n");
	return 0;
}

static void __exit map_exit(void)
{
	map_device_unregister();
	map_sessions_exit();
	pr_info("map: unloaded\n");
}

module_init(map_init);
module_exit(map_exit);
