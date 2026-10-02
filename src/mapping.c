// SPDX-License-Identifier: GPL-2.0
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>
#include "access.h"
#include "anon.h"
#include "diagnostics.h"
#include "mapping.h"
#include "request.h"
#include "session.h"

static bool live_anon = true;
module_param(live_anon, bool, 0);
MODULE_PARM_DESC(live_anon, "Map anonymous VMAs live by pinning and remapping PFNs (dangerous)");

static unsigned long vma_prot_from_flags(unsigned long vm_flags) {
	unsigned long prot = 0;

	if (vm_flags & VM_READ) prot |= PROT_READ;
	if (vm_flags & VM_WRITE) prot |= PROT_WRITE;
	if (vm_flags & VM_EXEC) prot |= PROT_EXEC;
	return prot;
}

static int map_target_mm_into_current(struct map_session *session, struct mm_struct *target_mm, const struct map_selector *selector, bool ondemand) {
	struct mm_struct *dest_mm = current->mm;
	struct vm_area_struct *vma;
	VMA_ITERATOR(iter, target_mm, 0);
	size_t mapped_vmas = 0, skipped_vmas = 0, failed_vmas = 0;
	unsigned long vma_idx = 1;

	if (!dest_mm) return -EINVAL;
	if (target_mm == dest_mm) return -EINVAL;

	mmap_read_lock(target_mm);
	for_each_vma(iter, vma) {
		unsigned long start, len, prot, flags, new_start;
		unsigned long offset;
		unsigned long npages;
		unsigned long curr_idx = vma_idx++;
		bool src_is_shared;
		struct vm_area_struct *dest_vma;
		struct page **pages = NULL;
		long pinned = 0;
		int err;

		start = vma->vm_start;
		len = vma->vm_end - vma->vm_start;
		if (!len) {
			skipped_vmas++;
			continue;
		}

		if (!map_selector_matches(selector, curr_idx, start, vma->vm_end)) {
			skipped_vmas++;
			continue;
		}

		src_is_shared = !!(vma->vm_flags & VM_SHARED);
		prot = vma_prot_from_flags(vma->vm_flags);
		flags = MAP_FIXED;
		offset = vma->vm_pgoff << PAGE_SHIFT;

		if (vma->vm_file) {
			flags |= src_is_shared ? MAP_SHARED : MAP_PRIVATE;
		} else {
			flags |= MAP_ANONYMOUS | (src_is_shared ? MAP_SHARED : MAP_PRIVATE);
			offset = 0;
		}

		/* Map in the *caller* (current) process. */
		new_start = vm_mmap(vma->vm_file, start, len, prot, flags, offset);
		if (IS_ERR_VALUE(new_start)) {
			failed_vmas++;
			log_vma_failure("vm_mmap", vma, start, len, (long)new_start);
			continue;
		}

		err = session_add_region(session, new_start, len);
		if (err) {
			(void)vm_munmap(new_start, len);
			mmap_read_unlock(target_mm);
			return err;
		}

		/* For file-backed mappings, vm_mmap() is sufficient. */
		if (vma->vm_file) {
			mapped_vmas++;
			continue;
		}

		if (ondemand) {
			mmap_write_lock(dest_mm);
			dest_vma = find_vma(dest_mm, new_start);
			if (!dest_vma || dest_vma->vm_start > new_start) {
				mmap_write_unlock(dest_mm);
				(void)vm_munmap(new_start, len);
				failed_vmas++;
				log_vma_failure("find_vma", vma, start, len, -ENOENT);
				continue;
			}

			err = map_attach_anon_region(session, target_mm, dest_vma, start, len, true);
			mmap_write_unlock(dest_mm);
			if (err) {
				(void)vm_munmap(new_start, len);
				mmap_read_unlock(target_mm);
				return err;
			}

			mapped_vmas++;
			continue;
		}

		npages = DIV_ROUND_UP(len, PAGE_SIZE);
		if (!live_anon) {
			(void)vm_munmap(new_start, len);
			failed_vmas++;
			log_vma_failure("anon_disabled", vma, start, len, -EOPNOTSUPP);
			continue;
		}

		pages = kvcalloc(npages, sizeof(*pages), GFP_KERNEL);
		if (!pages) {
			(void)vm_munmap(new_start, len);
			mmap_read_unlock(target_mm);
			return -ENOMEM;
		}

		pinned = get_user_pages_remote(target_mm, start, npages, FOLL_GET, pages, NULL);
		if (pinned != (long)npages) {
			if (pinned > 0) {
				for (long i = 0; i < pinned; i++) {
					put_page(pages[i]);
				}
			}
			kvfree(pages);
			(void)vm_munmap(new_start, len);
			failed_vmas++;
			log_vma_failure("get_user_pages_remote", vma, start, len, (pinned < 0) ? pinned : -EFAULT);
			continue;
		}

		mmap_write_lock(dest_mm);
		dest_vma = find_vma(dest_mm, new_start);
		if (!dest_vma || dest_vma->vm_start > new_start) {
			mmap_write_unlock(dest_mm);
			for (long i = 0; i < pinned; i++) {
				put_page(pages[i]);
			}
			kvfree(pages);
			(void)vm_munmap(new_start, len);
			failed_vmas++;
			log_vma_failure("find_vma", vma, start, len, -ENOENT);
			continue;
		}

		err = map_attach_anon_region(session, target_mm, dest_vma, start, len, false);
		if (err) {
			mmap_write_unlock(dest_mm);
			(void)vm_munmap(new_start, len);
			for (long i = 0; i < pinned; i++) {
				put_page(pages[i]);
			}
			kvfree(pages);
			mmap_read_unlock(target_mm);
			return err;
		}

		/* Transfer every reference before publishing any raw PFN PTEs. */
		mutex_lock(&session->lock);
		err = session_add_pinned_pages(session, pages, npages);
		mutex_unlock(&session->lock);
		if (err) {
			mmap_write_unlock(dest_mm);
			(void)vm_munmap(new_start, len);
			for (long i = 0; i < pinned; i++) {
				put_page(pages[i]);
			}
			kvfree(pages);
			mmap_read_unlock(target_mm);
			return err;
		}

		err = 0;
		for (unsigned long i = 0; i < npages; i++) {
			unsigned long pfn = page_to_pfn(pages[i]);

			err = remap_pfn_range(dest_vma, new_start + (i * PAGE_SIZE), pfn, PAGE_SIZE, dest_vma->vm_page_prot);
			if (err) break;
		}
		mmap_write_unlock(dest_mm);
		kvfree(pages);

		if (err) {
			(void)vm_munmap(new_start, len);
			failed_vmas++;
			log_vma_failure("remap_pfn_range", vma, start, len, err);
			continue;
		}

		mapped_vmas++;
	}
	mmap_read_unlock(target_mm);

	pr_info("map: mapped_vmas=%zu skipped_vmas=%zu failed_vmas=%zu target_mm=%p dest_pid=%d\n", mapped_vmas, skipped_vmas, failed_vmas, target_mm, task_pid_nr(current));

	return mapped_vmas ? 0 : -EINVAL;
}

int map_target_pid_into_current(struct map_session *session, pid_t target_pid, const struct map_selector *selector, bool ondemand) {
	struct task_struct *target_task;
	struct mm_struct *target_mm;
	int ret = 0;

	if (!map_caller_allowed()) return -EPERM;
	if (map_is_self_target(target_pid)) {
		pr_info("map: reject self-target map pid=%d\n", target_pid);
		return -EINVAL;
	}

	target_task = get_pid_task(find_vpid(target_pid), PIDTYPE_PID);
	if (!target_task) return -ESRCH;

	target_mm = get_task_mm(target_task);
	if (!target_mm) goto out_put_task;

	ret = map_target_mm_into_current(session, target_mm, selector, ondemand);
	mmput(target_mm);
	out_put_task:
	put_task_struct(target_task);
	return ret;
}

int map_bound_addr_into_current(struct map_session *session, unsigned long addr, bool ondemand) {
	struct map_selector selector = { .mode = MAP_SELECT_ADDR_RANGE, .addr_start = addr, .addr_end = addr + 1, };

	if (!session || !session->bound_mm) return -EINVAL;
	if (addr == ULONG_MAX) return -ERANGE;

	return map_target_mm_into_current(session, session->bound_mm, &selector, ondemand);
}
