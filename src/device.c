// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include "access.h"
#include "device.h"
#include "mapping.h"
#include "request.h"
#include "session.h"

static int map_dev_open(struct inode *inode, struct file *file)
{
	struct map_session *s;

	if (!map_caller_allowed())
		return -EPERM;
	s = map_session_create(current->mm);
	if (IS_ERR(s))
		return PTR_ERR(s);
	file->private_data = s;
	return 0;
}

static ssize_t map_dev_write(struct file *file, const char __user *ubuf,
			     size_t len, loff_t *ppos)
{
	char kbuf[256];
	char *input;
	char *opts = NULL;
	char *sep;
	char sep_ch = '\0';
	size_t n;
	int pid;
	int ret;
	struct map_request req = {
		.ondemand = true,
	};
	struct map_bind_request breq = {};
	struct map_session *s = file->private_data;

	if (!map_caller_allowed())
		return -EPERM;
	if (!s || !s->owner_mm || current->mm != s->owner_mm)
		return -EPERM;

	n = min(len, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, ubuf, n))
		return -EFAULT;
	kbuf[n] = '\0';

	input = strim(kbuf);
	if (!*input)
		return -EINVAL;

	sep = strpbrk(input, " \t");
	if (sep) {
		sep_ch = *sep;
		*sep = '\0';
		opts = strim(sep + 1);
	}

	ret = kstrtoint(input, 10, &pid);
	if (!ret) {
		if (pid <= 0)
			return -EINVAL;

		if (opts && *opts) {
			ret = parse_map_request(opts, &req);
			if (ret)
				return ret;
		}

		mutex_lock(&map_mutex);
		ret = session_cleanup_current(s);
		if (!ret)
			ret = map_target_pid_into_current(s, (pid_t)pid, &req.selector,
						  req.ondemand);
		mutex_unlock(&map_mutex);
		map_selector_reset(&req.selector);

		if (ret)
			return ret;
		return len;
	}

	if (sep)
		*sep = sep_ch;

	ret = parse_bind_request(strim(kbuf), &breq);
	if (ret)
		return ret;

	mutex_lock(&map_mutex);
	if (breq.bind_set) {
		ret = session_bind_target(s, breq.bind_pid);
		if (ret)
			goto out_unlock;
		ret = session_cleanup_current(s);
		if (ret)
			goto out_unlock;
	}

	if (breq.map_addr_set) {
		ret = map_bound_addr_into_current(s, breq.map_addr, breq.ondemand);
		if (ret)
			goto out_unlock;
	}
out_unlock:
	mutex_unlock(&map_mutex);
	if (ret)
		return ret;
	return len;
}

static int map_dev_release(struct inode *inode, struct file *file)
{
	struct map_session *s = file->private_data;

	if (s)
		map_session_close(s);
	file->private_data = NULL;
	return 0;
}

static const struct file_operations map_fops = {
	.owner = THIS_MODULE,
	.open = map_dev_open,
	.write = map_dev_write,
	.release = map_dev_release,
	.llseek = noop_llseek,
};

static struct miscdevice map_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "map",
	.fops = &map_fops,
	/*
	 * Access is constrained in open/write by map_caller_allowed();
	 * mode is broad so the allowlisted non-root UID can open it.
	 */
	.mode = 0666,
};

int map_device_register(void)
{
	return misc_register(&map_miscdev);
}

void map_device_unregister(void)
{
	misc_deregister(&map_miscdev);
}
