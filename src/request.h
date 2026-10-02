/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MAP_REQUEST_H
#define MAP_REQUEST_H

#include <linux/types.h>

enum map_select_mode {
	MAP_SELECT_ALL = 0,
	MAP_SELECT_ADDR_RANGE,
	MAP_SELECT_VMA_INDEX,
};

struct vma_index_range {
	unsigned long first;
	unsigned long last;
};

struct map_selector {
	enum map_select_mode mode;
	unsigned long addr_start;
	unsigned long addr_end;
	struct vma_index_range *idx_ranges;
	size_t idx_count;
	size_t idx_cap;
};

struct map_request {
	struct map_selector selector;
	bool ondemand;
};

struct map_bind_request {
	bool bind_set;
	pid_t bind_pid;
	bool map_addr_set;
	unsigned long map_addr;
	bool ondemand;
};

void map_selector_reset(struct map_selector *sel);
bool map_selector_matches(const struct map_selector *sel, unsigned long vma_idx,
			  unsigned long start, unsigned long end);
int parse_map_request(char *spec, struct map_request *req);
int parse_bind_request(char *spec, struct map_bind_request *req);

#endif
