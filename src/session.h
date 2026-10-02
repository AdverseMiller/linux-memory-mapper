/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MAP_SESSION_H
#define MAP_SESSION_H

#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/types.h>

struct mm_struct;
struct page;
struct map_region;

struct map_session {
	struct kref refcount;
	struct kthread_work cleanup_work;
	struct mm_struct *owner_mm;
	struct mutex lock;
	atomic_t anon_regions;
	bool dying;
	pid_t bound_pid;
	struct mm_struct *bound_mm;
	struct map_region *regions;
	size_t region_count;
	size_t region_cap;
	struct page **pinned_pages;
	size_t pinned_count;
	size_t pinned_cap;
};

/* Serializes mapping requests and cleanup across all sessions. */
extern struct mutex map_mutex;

int map_sessions_init(void);
void map_sessions_exit(void);
struct map_session *map_session_create(struct mm_struct *owner_mm);
void map_session_close(struct map_session *s);
void map_session_get(struct map_session *s);
void map_session_put(struct map_session *s);
int session_cleanup_current(struct map_session *s);
int session_bind_target(struct map_session *s, pid_t target_pid);
int session_add_region(struct map_session *s, unsigned long start, unsigned long len);
/* The caller holds s->lock when transferring pinned page references. */
int session_add_pinned_pages(struct map_session *s, struct page **pages, unsigned long npages);
int session_track_pinned_page(struct map_session *s, struct page *page);

#endif
