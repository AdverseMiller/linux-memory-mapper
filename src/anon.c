// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include "anon.h"
#include "session.h"

struct map_ondemand_region {
	struct kref refcount;
	struct map_session *session;
	struct mm_struct *target_mm;
	unsigned long src_start;
	unsigned long src_len;
};

static void map_ondemand_region_release(struct kref *ref)
{
	struct map_ondemand_region *od =
		container_of(ref, struct map_ondemand_region, refcount);

	if (od->target_mm)
		mmdrop(od->target_mm);
	atomic_dec(&od->session->anon_regions);
	map_session_put(od->session);
	kfree(od);
	module_put(THIS_MODULE);
}

static void map_ondemand_vma_open(struct vm_area_struct *vma)
{
	struct map_ondemand_region *od = vma->vm_private_data;

	if (od)
		kref_get(&od->refcount);
}

static void map_ondemand_vma_close(struct vm_area_struct *vma)
{
	struct map_ondemand_region *od = vma->vm_private_data;

	if (!od)
		return;
	vma->vm_private_data = NULL;
	kref_put(&od->refcount, map_ondemand_region_release);
}

static vm_fault_t map_ondemand_vma_fault(struct vm_fault *vmf)
{
	struct map_ondemand_region *od = vmf->vma->vm_private_data;
	struct page *page;
	unsigned long fault_addr;
	unsigned long src_addr;
	long pinned;
	vm_fault_t ret;
	int err;

	if (!od || !od->session || !od->target_mm)
		return VM_FAULT_SIGBUS;

	fault_addr = vmf->address & PAGE_MASK;
	if (fault_addr < vmf->vma->vm_start || fault_addr >= vmf->vma->vm_end)
		return VM_FAULT_SIGBUS;

	mutex_lock(&od->session->lock);
	if (od->session->dying) {
		mutex_unlock(&od->session->lock);
		return VM_FAULT_SIGBUS;
	}
	/* vm_pgoff follows VMA splits and moves; vm_start does not. */
	src_addr = vmf->pgoff << PAGE_SHIFT;
	if (src_addr < od->src_start ||
	    src_addr - od->src_start >= od->src_len ||
	    !mmget_not_zero(od->target_mm)) {
		mutex_unlock(&od->session->lock);
		return VM_FAULT_SIGBUS;
	}

	mmap_read_lock(od->target_mm);
	pinned = get_user_pages_remote(od->target_mm, src_addr, 1, FOLL_GET,
				      &page, NULL);
	mmap_read_unlock(od->target_mm);
	/* A last mmput must not tear down another mm under this fault's lock. */
	mmput_async(od->target_mm);
	if (pinned != 1) {
		mutex_unlock(&od->session->lock);
		return VM_FAULT_SIGBUS;
	}

	/* Own the page before publishing its PFN, including allocation failures. */
	err = session_track_pinned_page(od->session, page);
	if (err) {
		put_page(page);
		mutex_unlock(&od->session->lock);
		return VM_FAULT_OOM;
	}

	ret = vmf_insert_pfn(vmf->vma, fault_addr, page_to_pfn(page));
	if (ret != VM_FAULT_NOPAGE && ret != 0) {
		od->session->pinned_count--;
		put_page(page);
	}
	mutex_unlock(&od->session->lock);
	return ret;
}

static const struct vm_operations_struct map_ondemand_vm_ops = {
	.open = map_ondemand_vma_open,
	.close = map_ondemand_vma_close,
	.fault = map_ondemand_vma_fault,
};

static const struct vm_operations_struct map_eager_vm_ops = {
	.open = map_ondemand_vma_open,
	.close = map_ondemand_vma_close,
};

/* Called with the destination mmap write lock held. */
int map_attach_anon_region(struct map_session *session,
				 struct mm_struct *target_mm,
				 struct vm_area_struct *vma,
				 unsigned long start, unsigned long len,
				 bool ondemand)
{
	struct map_ondemand_region *od;

	od = kzalloc_obj(*od);
	if (!od)
		return -ENOMEM;

	kref_init(&od->refcount);
	od->session = session;
	od->src_start = start;
	od->src_len = len;
	if (ondemand) {
		od->target_mm = target_mm;
		mmgrab(target_mm);
	}
	map_session_get(session);
	atomic_inc(&session->anon_regions);
	__module_get(THIS_MODULE);

	vm_flags_clear(vma, VM_MIXEDMAP);
	vm_flags_set(vma, VM_PFNMAP | VM_IO | VM_DONTEXPAND |
			 VM_DONTDUMP | VM_DONTCOPY | VM_SHARED | VM_MAYSHARE);
	vma->vm_pgoff = start >> PAGE_SHIFT;
	vma->vm_ops = ondemand ? &map_ondemand_vm_ops : &map_eager_vm_ops;
	vma->vm_private_data = od;
	return 0;
}

bool map_anon_vma_belongs_to(const struct vm_area_struct *vma,
			    const struct map_session *session)
{
	struct map_ondemand_region *od;

	if (vma->vm_ops != &map_ondemand_vm_ops &&
	    vma->vm_ops != &map_eager_vm_ops)
		return false;
	od = vma->vm_private_data;
	return od && od->session == session;
}
