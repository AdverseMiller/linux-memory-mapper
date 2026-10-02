// SPDX-License-Identifier: GPL-2.0
#include <linux/dcache.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/slab.h>
#include "diagnostics.h"

static bool log_failures = true;
module_param(log_failures, bool, 0);
MODULE_PARM_DESC(log_failures, "Log a line for each failed VMA mapping step");

void log_vma_failure(const char *stage, const struct vm_area_struct *vma, unsigned long start, unsigned long len, long err) {
	char *buf;
	char *path = NULL;

	if (!log_failures) return;

	if (vma->vm_file) {
		buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (buf) {
			path = d_path(&vma->vm_file->f_path, buf, PATH_MAX);
			if (IS_ERR(path)) path = NULL;
		} else {
			buf = NULL;
		}
	} else {
		buf = NULL;
	}

	pr_info("map: fail stage=%s err=%ld vma=%lx-%lx len=%lx flags=%lx pgoff=%lx file=%s\n", stage, err, start, start + len, len, (unsigned long)vma->vm_flags, (unsigned long)vma->vm_pgoff, path ? path : (vma->vm_file ? "<path?>" : "<anon>"));

	kfree(buf);
}
