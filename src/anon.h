/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MAP_ANON_H
#define MAP_ANON_H

#include <linux/types.h>

struct map_session;
struct mm_struct;
struct vm_area_struct;

/* The caller holds the destination mmap write lock. */
int map_attach_anon_region(struct map_session *session,
			   struct mm_struct *target_mm,
			   struct vm_area_struct *vma,
			   unsigned long start, unsigned long len, bool ondemand);
/* The caller holds the VMA's mmap lock. */
bool map_anon_vma_belongs_to(const struct vm_area_struct *vma,
			    const struct map_session *session);

#endif
