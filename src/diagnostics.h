/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MAP_DIAGNOSTICS_H
#define MAP_DIAGNOSTICS_H

struct vm_area_struct;

void log_vma_failure(const char *stage, const struct vm_area_struct *vma, unsigned long start, unsigned long len, long err);

#endif
