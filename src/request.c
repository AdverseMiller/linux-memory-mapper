// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "request.h"

void map_selector_reset(struct map_selector *sel) {
	kfree(sel->idx_ranges);
	sel->idx_ranges = NULL;
	sel->idx_count = 0;
	sel->idx_cap = 0;
	sel->mode = MAP_SELECT_ALL;
	sel->addr_start = 0;
	sel->addr_end = 0;
}

static int map_selector_add_idx_range(struct map_selector *sel, unsigned long first, unsigned long last) {
	struct vma_index_range *new_ranges;

	if (first > last) return -EINVAL;

	if (sel->idx_count == sel->idx_cap) {
		size_t new_cap = sel->idx_cap ? (sel->idx_cap * 2) : 8;

		new_ranges = krealloc(sel->idx_ranges, new_cap * sizeof(*new_ranges), GFP_KERNEL);
		if (!new_ranges) return -ENOMEM;
		sel->idx_ranges = new_ranges;
		sel->idx_cap = new_cap;
	}

	sel->idx_ranges[sel->idx_count++] = (struct vma_index_range){ .first = first, .last = last, };
	return 0;
}

static int parse_addr_range(char *spec, unsigned long *start, unsigned long *end) {
	char *dash;
	int ret;

	dash = strchr(spec, '-');
	if (!dash) return -EINVAL;

	*dash = '\0';
	ret = kstrtoul(spec, 0, start);
	if (ret) return ret;
	ret = kstrtoul(dash + 1, 0, end);
	if (ret) return ret;
	if (*end <= *start) return -EINVAL;
	return 0;
}

static int parse_vma_index_spec(struct map_selector *sel, char *spec) {
	char *entry;
	int ret;

	sel->mode = MAP_SELECT_VMA_INDEX;
	while ((entry = strsep(&spec, ",")) != NULL) {
		unsigned long first, last;
		char *dash;

		entry = strim(entry);
		if (!*entry) continue;

		dash = strchr(entry, '-');
		if (!dash) {
			ret = kstrtoul(entry, 0, &first);
			if (ret) return ret;
			ret = map_selector_add_idx_range(sel, first, first);
			if (ret) return ret;
			continue;
		}

		*dash = '\0';
		ret = kstrtoul(entry, 0, &first);
		if (ret) return ret;
		ret = kstrtoul(dash + 1, 0, &last);
		if (ret) return ret;
		ret = map_selector_add_idx_range(sel, first, last);
		if (ret) return ret;
	}

	if (!sel->idx_count) return -EINVAL;

	return 0;
}

static int parse_map_selector(char *spec, struct map_selector *sel) {
	int ret;

	map_selector_reset(sel);
	if (!spec || !*spec) return 0;

	if (!strncmp(spec, "addr=", 5)) {
		sel->mode = MAP_SELECT_ADDR_RANGE;
		ret = parse_addr_range(spec + 5, &sel->addr_start, &sel->addr_end);
		if (ret) map_selector_reset(sel);
		return ret;
	}

	if (!strncmp(spec, "vma=", 4)) {
		ret = parse_vma_index_spec(sel, spec + 4);
		if (ret) map_selector_reset(sel);
		return ret;
	}

	return -EINVAL;
}

bool map_selector_matches(const struct map_selector *sel, unsigned long vma_idx, unsigned long start, unsigned long end) {
	if (!sel || sel->mode == MAP_SELECT_ALL) return true;

	if (sel->mode == MAP_SELECT_ADDR_RANGE) {
		return end > sel->addr_start && start < sel->addr_end;
	}

	if (sel->mode == MAP_SELECT_VMA_INDEX) {
		for (size_t i = 0; i < sel->idx_count; i++) {
			if (vma_idx >= sel->idx_ranges[i].first && vma_idx <= sel->idx_ranges[i].last) {
				return true;
			}
		}
		return false;
	}

	return true;
}

static int parse_map_option_token(char *token, struct map_request *req, bool *selector_seen) {
	int ret;

	if (!strncmp(token, "ondemand=", 9)) {
		unsigned int val;

		ret = kstrtouint(token + 9, 0, &val);
		if (ret) return ret;
		req->ondemand = !!val;
		return 0;
	}

	if (!strncmp(token, "addr=", 5) || !strncmp(token, "vma=", 4)) {
		if (*selector_seen) return -EINVAL;
		ret = parse_map_selector(token, &req->selector);
		if (ret) return ret;
		*selector_seen = true;
		return 0;
	}

	return -EINVAL;
}

int parse_map_request(char *spec, struct map_request *req) {
	char *token;
	bool selector_seen = false;
	int ret;

	req->ondemand = true;
	map_selector_reset(&req->selector);

	if (!spec || !*spec) return 0;

	while ((token = strsep(&spec, " \t")) != NULL) {
		token = strim(token);
		if (!*token) continue;
		ret = parse_map_option_token(token, req, &selector_seen);
		if (ret) {
			map_selector_reset(&req->selector);
			return ret;
		}
	}

	return 0;
}

static int parse_bind_option_token(char *token, struct map_bind_request *req) {
	int ret;

	if (!strncmp(token, "bind=", 5)) {
		int pid;

		ret = kstrtoint(token + 5, 10, &pid);
		if (ret) return ret;
		if (pid <= 0) return -EINVAL;
		req->bind_pid = (pid_t)pid;
		req->bind_set = true;
		return 0;
	}

	if (!strncmp(token, "map_addr=", 9)) {
		ret = kstrtoul(token + 9, 0, &req->map_addr);
		if (ret) return ret;
		req->map_addr_set = true;
		return 0;
	}

	if (!strncmp(token, "ondemand=", 9)) {
		unsigned int val;

		ret = kstrtouint(token + 9, 0, &val);
		if (ret) return ret;
		req->ondemand = !!val;
		return 0;
	}

	return -EINVAL;
}

int parse_bind_request(char *spec, struct map_bind_request *req) {
	char *token;
	int ret;

	memset(req, 0, sizeof(*req));
	req->ondemand = true;
	if (!spec || !*spec) return -EINVAL;

	while ((token = strsep(&spec, " \t")) != NULL) {
		token = strim(token);
		if (!*token) continue;
		ret = parse_bind_option_token(token, req);
		if (ret) return ret;
	}

	if (!req->bind_set && !req->map_addr_set) return -EINVAL;

	return 0;
}
