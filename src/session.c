// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "access.h"
#include "anon.h"
#include "session.h"

DEFINE_MUTEX(map_mutex);
static struct kthread_worker *cleanup_worker;

struct map_region {
	unsigned long start;
	unsigned long len;
};

int session_add_region(struct map_session *s, unsigned long start,
			      unsigned long len)
{
	struct map_region *new_regions;

	if (s->region_count == s->region_cap) {
		size_t new_cap = s->region_cap ? (s->region_cap * 2) : 64;

		new_regions = krealloc(s->regions, new_cap * sizeof(*new_regions),
				       GFP_KERNEL);
		if (!new_regions)
			return -ENOMEM;
		s->regions = new_regions;
		s->region_cap = new_cap;
	}

	s->regions[s->region_count++] = (struct map_region){
		.start = start,
		.len = len,
	};
	return 0;
}

int session_add_pinned_pages(struct map_session *s, struct page **pages,
				    unsigned long npages)
{
	struct page **new_pages;

	if (npages == 0)
		return 0;

	if (s->pinned_count + npages > s->pinned_cap) {
		size_t new_cap = s->pinned_cap ? s->pinned_cap : 1024;

		while (new_cap < s->pinned_count + npages)
			new_cap *= 2;

		new_pages = krealloc(s->pinned_pages, new_cap * sizeof(*new_pages),
				     GFP_KERNEL);
		if (!new_pages)
			return -ENOMEM;
		s->pinned_pages = new_pages;
		s->pinned_cap = new_cap;
	}

	memcpy(&s->pinned_pages[s->pinned_count], pages,
	       npages * sizeof(*pages));
	s->pinned_count += npages;
	return 0;
}

int session_track_pinned_page(struct map_session *s, struct page *page)
{
	struct page *tmp[1];

	tmp[0] = page;
	return session_add_pinned_pages(s, tmp, 1);
}

static void session_clear_bound_target(struct map_session *s)
{
	if (!s)
		return;
	if (s->bound_mm) {
		mmput_async(s->bound_mm);
		s->bound_mm = NULL;
	}
	s->bound_pid = 0;
}

int session_bind_target(struct map_session *s, pid_t target_pid)
{
	struct task_struct *target_task;
	struct mm_struct *target_mm;
	struct mm_struct *old_mm;

	if (map_is_self_target(target_pid)) {
		pr_info("map: reject self-target bind pid=%d\n", target_pid);
		return -EINVAL;
	}

	target_task = get_pid_task(find_vpid(target_pid), PIDTYPE_PID);
	if (!target_task)
		return -ESRCH;

	target_mm = get_task_mm(target_task);
	put_task_struct(target_task);
	if (!target_mm)
		return -EINVAL;

	old_mm = s->bound_mm;
	s->bound_mm = target_mm;
	s->bound_pid = target_pid;
	if (old_mm)
		mmput_async(old_mm);

	return 0;
}

static void session_release_pages(struct map_session *s)
{
	for (size_t i = 0; i < s->pinned_count; i++)
		put_page(s->pinned_pages[i]);
	kfree(s->pinned_pages);
	s->pinned_pages = NULL;
	s->pinned_count = 0;
	s->pinned_cap = 0;
}

static void map_session_release(struct kref *ref)
{
	struct map_session *s = container_of(ref, struct map_session, refcount);

	/* The file and every anonymous VMA have gone; no PFN can remain live. */
	session_release_pages(s);
	kfree(s->regions);
	if (s->bound_mm)
		mmput_async(s->bound_mm);
	mmdrop(s->owner_mm);
	kfree(s);
}

int session_cleanup_current(struct map_session *s)
{
	int err;

	if (current->mm != s->owner_mm)
		return -EPERM;

	mutex_lock(&s->lock);
	s->dying = true;
	mutex_unlock(&s->lock);

	for (size_t i = 0; i < s->region_count; i++) {
		err = vm_munmap(s->regions[i].start, s->regions[i].len);
		if (err)
			return err;
	}

	/* mremap() may have moved or split a mapping since it was recorded. */
	while (atomic_read(&s->anon_regions)) {
		struct vm_area_struct *vma;
		unsigned long start = 0, len = 0;

		VMA_ITERATOR(iter, s->owner_mm, 0);

		mmap_read_lock(s->owner_mm);
		for_each_vma(iter, vma) {
			if (map_anon_vma_belongs_to(vma, s)) {
				start = vma->vm_start;
				len = vma->vm_end - start;
				break;
			}
		}
		mmap_read_unlock(s->owner_mm);
		if (!len)
			return -EBUSY;
		err = vm_munmap(start, len);
		if (err)
			return err;
	}

	mutex_lock(&s->lock);
	session_release_pages(s);

	kfree(s->regions);
	s->regions = NULL;
	s->region_count = 0;
	s->region_cap = 0;

	s->dying = false;
	mutex_unlock(&s->lock);
	return 0;
}

static void session_cleanup_work(struct kthread_work *work)
{
	struct map_session *s = container_of(work, struct map_session, cleanup_work);

	mutex_lock(&map_mutex);
	mutex_lock(&s->lock);
	s->dying = true;
	mutex_unlock(&s->lock);
	/* mmgrab keeps the structure, without preventing exit_mmap on exit/exec. */
	if (mmget_not_zero(s->owner_mm)) {
		kthread_use_mm(s->owner_mm);
		(void)session_cleanup_current(s);
		kthread_unuse_mm(s->owner_mm);
		mmput(s->owner_mm);
	}
	session_clear_bound_target(s);
	mutex_unlock(&map_mutex);
}

int map_sessions_init(void)
{
	cleanup_worker = kthread_create_worker(0, "map-cleanup");
	return PTR_ERR_OR_ZERO(cleanup_worker);
}

void map_sessions_exit(void)
{
	kthread_destroy_worker(cleanup_worker);
}

struct map_session *map_session_create(struct mm_struct *owner_mm)
{
	struct map_session *s;

	if (!owner_mm)
		return ERR_PTR(-EINVAL);
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return ERR_PTR(-ENOMEM);
	mutex_init(&s->lock);
	kref_init(&s->refcount);
	kthread_init_work(&s->cleanup_work, session_cleanup_work);
	atomic_set(&s->anon_regions, 0);
	s->owner_mm = owner_mm;
	mmgrab(s->owner_mm);
	return s;
}

void map_session_get(struct map_session *s)
{
	kref_get(&s->refcount);
}

void map_session_put(struct map_session *s)
{
	kref_put(&s->refcount, map_session_release);
}

void map_session_close(struct map_session *s)
{
	/* release may run after fork, SCM_RIGHTS, exec, or in a kernel task. */
	kthread_queue_work(cleanup_worker, &s->cleanup_work);
	kthread_flush_work(&s->cleanup_work);
	map_session_put(s);
}
