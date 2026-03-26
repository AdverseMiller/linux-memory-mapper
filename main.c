#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/capability.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/kref.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Map a target process' anonymous VMAs into the caller");
MODULE_VERSION("0.2");

static DEFINE_MUTEX(map_mutex);
static bool log_failures = true;
module_param(log_failures, bool, 0);
MODULE_PARM_DESC(log_failures, "Log a line for each failed VMA mapping step");
static bool live_anon = true;
module_param(live_anon, bool, 0);
MODULE_PARM_DESC(live_anon, "Map anonymous VMAs live by pinning and remapping PFNs (dangerous)");
static unsigned int allowed_uid = 1000;
module_param(allowed_uid, uint, 0);
MODULE_PARM_DESC(allowed_uid, "Non-root UID allowed to access /dev/map (temporary testing)");

struct map_region {
	unsigned long start;
	unsigned long len;
};

struct map_session {
	struct mm_struct *owner_mm;
	struct mutex lock;
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

struct map_ondemand_region {
	struct kref refcount;
	struct map_session *session;
	struct mm_struct *target_mm;
	unsigned long src_start;
	unsigned long src_len;
	bool src_is_shared;
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

static int session_track_pinned_page(struct map_session *s, struct page *page);

static bool map_is_self_target(pid_t target_pid)
{
	return target_pid == task_pid_nr(current);
}

static bool map_caller_allowed(void)
{
	if (capable(CAP_SYS_ADMIN))
		return true;

	return __kuid_val(current_euid()) == allowed_uid;
}

static unsigned long vma_prot_from_flags(unsigned long vm_flags)
{
	unsigned long prot = 0;

	if (vm_flags & VM_READ)
		prot |= PROT_READ;
	if (vm_flags & VM_WRITE)
		prot |= PROT_WRITE;
	if (vm_flags & VM_EXEC)
		prot |= PROT_EXEC;
	return prot;
}

static void log_vma_failure(const char *stage, const struct vm_area_struct *vma,
			    unsigned long start, unsigned long len, long err)
{
	char *buf;
	char *path = NULL;

	if (!log_failures)
		return;

	if (vma->vm_file) {
		buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (buf) {
			path = d_path(&vma->vm_file->f_path, buf, PATH_MAX);
			if (IS_ERR(path))
				path = NULL;
		} else {
			buf = NULL;
		}
	} else {
		buf = NULL;
	}

	pr_info("map: fail stage=%s err=%ld vma=%lx-%lx len=%lx flags=%lx pgoff=%lx file=%s\n",
		stage,
		err,
		start,
		start + len,
		len,
		(unsigned long)vma->vm_flags,
		(unsigned long)vma->vm_pgoff,
		path ? path : (vma->vm_file ? "<path?>" : "<anon>"));

	kfree(buf);
}

static void map_selector_reset(struct map_selector *sel)
{
	kfree(sel->idx_ranges);
	sel->idx_ranges = NULL;
	sel->idx_count = 0;
	sel->idx_cap = 0;
	sel->mode = MAP_SELECT_ALL;
	sel->addr_start = 0;
	sel->addr_end = 0;
}

static int map_selector_add_idx_range(struct map_selector *sel,
				      unsigned long first,
				      unsigned long last)
{
	struct vma_index_range *new_ranges;

	if (first > last)
		return -EINVAL;

	if (sel->idx_count == sel->idx_cap) {
		size_t new_cap = sel->idx_cap ? (sel->idx_cap * 2) : 8;

		new_ranges = krealloc(sel->idx_ranges,
				      new_cap * sizeof(*new_ranges),
				      GFP_KERNEL);
		if (!new_ranges)
			return -ENOMEM;
		sel->idx_ranges = new_ranges;
		sel->idx_cap = new_cap;
	}

	sel->idx_ranges[sel->idx_count++] = (struct vma_index_range) {
		.first = first,
		.last = last,
	};
	return 0;
}

static int parse_addr_range(char *spec, unsigned long *start,
			    unsigned long *end)
{
	char *dash;
	int ret;

	dash = strchr(spec, '-');
	if (!dash)
		return -EINVAL;

	*dash = '\0';
	ret = kstrtoul(spec, 0, start);
	if (ret)
		return ret;
	ret = kstrtoul(dash + 1, 0, end);
	if (ret)
		return ret;
	if (*end <= *start)
		return -EINVAL;
	return 0;
}

static int parse_vma_index_spec(struct map_selector *sel, char *spec)
{
	char *entry;
	int ret;

	sel->mode = MAP_SELECT_VMA_INDEX;
	while ((entry = strsep(&spec, ",")) != NULL) {
		unsigned long first, last;
		char *dash;

		entry = strim(entry);
		if (!*entry)
			continue;

		dash = strchr(entry, '-');
		if (!dash) {
			ret = kstrtoul(entry, 0, &first);
			if (ret)
				return ret;
			ret = map_selector_add_idx_range(sel, first, first);
			if (ret)
				return ret;
			continue;
		}

		*dash = '\0';
		ret = kstrtoul(entry, 0, &first);
		if (ret)
			return ret;
		ret = kstrtoul(dash + 1, 0, &last);
		if (ret)
			return ret;
		ret = map_selector_add_idx_range(sel, first, last);
		if (ret)
			return ret;
	}

	if (!sel->idx_count)
		return -EINVAL;

	return 0;
}

static int parse_map_selector(char *spec, struct map_selector *sel)
{
	int ret;

	map_selector_reset(sel);
	if (!spec || !*spec)
		return 0;

	if (!strncmp(spec, "addr=", 5)) {
		sel->mode = MAP_SELECT_ADDR_RANGE;
		ret = parse_addr_range(spec + 5, &sel->addr_start, &sel->addr_end);
		if (ret)
			map_selector_reset(sel);
		return ret;
	}

	if (!strncmp(spec, "vma=", 4)) {
		ret = parse_vma_index_spec(sel, spec + 4);
		if (ret)
			map_selector_reset(sel);
		return ret;
	}

	return -EINVAL;
}

static bool map_selector_matches(const struct map_selector *sel,
				 unsigned long vma_idx,
				 unsigned long start,
				 unsigned long end)
{
	if (!sel || sel->mode == MAP_SELECT_ALL)
		return true;

	if (sel->mode == MAP_SELECT_ADDR_RANGE)
		return end > sel->addr_start && start < sel->addr_end;

	if (sel->mode == MAP_SELECT_VMA_INDEX) {
		for (size_t i = 0; i < sel->idx_count; i++) {
			if (vma_idx >= sel->idx_ranges[i].first &&
			    vma_idx <= sel->idx_ranges[i].last)
				return true;
		}
		return false;
	}

	return true;
}

static int parse_map_option_token(char *token, struct map_request *req,
				  bool *selector_seen)
{
	int ret;

	if (!strncmp(token, "ondemand=", 9)) {
		unsigned int val;

		ret = kstrtouint(token + 9, 0, &val);
		if (ret)
			return ret;
		req->ondemand = !!val;
		return 0;
	}

	if (!strncmp(token, "addr=", 5) || !strncmp(token, "vma=", 4)) {
		if (*selector_seen)
			return -EINVAL;
		ret = parse_map_selector(token, &req->selector);
		if (ret)
			return ret;
		*selector_seen = true;
		return 0;
	}

	return -EINVAL;
}

static int parse_map_request(char *spec, struct map_request *req)
{
	char *token;
	bool selector_seen = false;
	int ret;

	req->ondemand = true;
	map_selector_reset(&req->selector);

	if (!spec || !*spec)
		return 0;

	while ((token = strsep(&spec, " \t")) != NULL) {
		token = strim(token);
		if (!*token)
			continue;
		ret = parse_map_option_token(token, req, &selector_seen);
		if (ret) {
			map_selector_reset(&req->selector);
			return ret;
		}
	}

	return 0;
}

static int parse_bind_option_token(char *token, struct map_bind_request *req)
{
	int ret;

	if (!strncmp(token, "bind=", 5)) {
		int pid;

		ret = kstrtoint(token + 5, 10, &pid);
		if (ret)
			return ret;
		if (pid <= 0)
			return -EINVAL;
		req->bind_pid = (pid_t)pid;
		req->bind_set = true;
		return 0;
	}

	if (!strncmp(token, "map_addr=", 9)) {
		ret = kstrtoul(token + 9, 0, &req->map_addr);
		if (ret)
			return ret;
		req->map_addr_set = true;
		return 0;
	}

	if (!strncmp(token, "ondemand=", 9)) {
		unsigned int val;

		ret = kstrtouint(token + 9, 0, &val);
		if (ret)
			return ret;
		req->ondemand = !!val;
		return 0;
	}

	return -EINVAL;
}

static int parse_bind_request(char *spec, struct map_bind_request *req)
{
	char *token;
	int ret;

	memset(req, 0, sizeof(*req));
	req->ondemand = true;
	if (!spec || !*spec)
		return -EINVAL;

	while ((token = strsep(&spec, " \t")) != NULL) {
		token = strim(token);
		if (!*token)
			continue;
		ret = parse_bind_option_token(token, req);
		if (ret)
			return ret;
	}

	if (!req->bind_set && !req->map_addr_set)
		return -EINVAL;

	return 0;
}

static void map_ondemand_region_release(struct kref *ref)
{
	struct map_ondemand_region *od =
		container_of(ref, struct map_ondemand_region, refcount);

	if (od->target_mm)
		mmput(od->target_mm);
	kfree(od);
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
	mutex_unlock(&od->session->lock);

	src_addr = od->src_start + (fault_addr - vmf->vma->vm_start);
	src_addr &= PAGE_MASK;

	mmap_read_lock(od->target_mm);
	pinned = get_user_pages_remote(od->target_mm, src_addr, 1, FOLL_GET,
				      &page, NULL);
	mmap_read_unlock(od->target_mm);
	if (pinned != 1)
		return VM_FAULT_SIGBUS;

	ret = vmf_insert_pfn(vmf->vma, fault_addr, page_to_pfn(page));
	if (ret != VM_FAULT_NOPAGE && ret != 0) {
		put_page(page);
		return ret;
	}

	mutex_lock(&od->session->lock);
	if (od->session->dying) {
		mutex_unlock(&od->session->lock);
		/*
		 * Keep the reference rather than risking UAF if this fault raced
		 * with teardown after we inserted the PTE.
		 */
		return VM_FAULT_NOPAGE;
	}
	err = session_track_pinned_page(od->session, page);
	mutex_unlock(&od->session->lock);
	if (err)
		return VM_FAULT_OOM;

	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct map_ondemand_vm_ops = {
	.open = map_ondemand_vma_open,
	.close = map_ondemand_vma_close,
	.fault = map_ondemand_vma_fault,
};

static int session_add_region(struct map_session *s, unsigned long start,
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

static int session_add_pinned_pages(struct map_session *s, struct page **pages,
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

static int session_track_pinned_page(struct map_session *s, struct page *page)
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
		mmput(s->bound_mm);
		s->bound_mm = NULL;
	}
	s->bound_pid = 0;
}

static int session_bind_target(struct map_session *s, pid_t target_pid)
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
		mmput(old_mm);

	return 0;
}

static void session_cleanup_current(struct map_session *s)
{
	if (!s)
		return;
	if (!s->owner_mm || current->mm != s->owner_mm)
		return;

	mutex_lock(&s->lock);
	s->dying = true;
	mutex_unlock(&s->lock);

	for (size_t i = 0; i < s->region_count; i++)
		(void)vm_munmap(s->regions[i].start, s->regions[i].len);

	mutex_lock(&s->lock);
	for (size_t i = 0; i < s->pinned_count; i++)
		put_page(s->pinned_pages[i]);

	kfree(s->regions);
	s->regions = NULL;
	s->region_count = 0;
	s->region_cap = 0;

	kfree(s->pinned_pages);
	s->pinned_pages = NULL;
	s->pinned_count = 0;
	s->pinned_cap = 0;
	s->dying = false;
	mutex_unlock(&s->lock);
}

static int map_target_mm_into_current(struct map_session *session,
				      struct mm_struct *target_mm,
				      const struct map_selector *selector,
				      bool ondemand)
{
	struct mm_struct *dest_mm = current->mm;
	struct vm_area_struct *vma;
	VMA_ITERATOR(iter, target_mm, 0);
	size_t mapped_vmas = 0, skipped_vmas = 0, failed_vmas = 0;
	unsigned long vma_idx = 1;

	if (!dest_mm)
		return -EINVAL;
	if (target_mm == dest_mm)
		return -EINVAL;

	mmap_read_lock(target_mm);
	for_each_vma(iter, vma) {
		unsigned long start, len, prot, flags, new_start;
		unsigned long offset;
		unsigned long npages;
		unsigned long curr_idx = vma_idx++;
		bool src_is_shared;
		struct vm_area_struct *dest_vma;
		struct map_ondemand_region *od;
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

			od = kzalloc(sizeof(*od), GFP_KERNEL);
			if (!od) {
				mmap_write_unlock(dest_mm);
				(void)vm_munmap(new_start, len);
				return -ENOMEM;
			}

			kref_init(&od->refcount);
			od->session = session;
			od->target_mm = target_mm;
			od->src_start = start;
			od->src_len = len;
			od->src_is_shared = src_is_shared;
			mmget(target_mm);

			vm_flags_clear(dest_vma, VM_MIXEDMAP);
			vm_flags_set(dest_vma, VM_PFNMAP | VM_IO |
					       VM_DONTEXPAND | VM_DONTDUMP |
					       VM_DONTCOPY);
			if (!src_is_shared)
				vm_flags_set(dest_vma, VM_SHARED | VM_MAYSHARE);
			dest_vma->vm_ops = &map_ondemand_vm_ops;
			dest_vma->vm_private_data = od;
			mmap_write_unlock(dest_mm);

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

		pinned = get_user_pages_remote(target_mm, start, npages, FOLL_GET,
					      pages, NULL);
		if (pinned != (long)npages) {
			if (pinned > 0) {
				for (long i = 0; i < pinned; i++)
					put_page(pages[i]);
			}
			kvfree(pages);
			(void)vm_munmap(new_start, len);
			failed_vmas++;
			log_vma_failure("get_user_pages_remote", vma, start, len,
					(pinned < 0) ? pinned : -EFAULT);
			continue;
		}

		mmap_write_lock(dest_mm);
		dest_vma = find_vma(dest_mm, new_start);
		if (!dest_vma || dest_vma->vm_start > new_start) {
			mmap_write_unlock(dest_mm);
			for (long i = 0; i < pinned; i++)
				put_page(pages[i]);
			kvfree(pages);
			(void)vm_munmap(new_start, len);
			failed_vmas++;
			log_vma_failure("find_vma", vma, start, len, -ENOENT);
			continue;
		}

		vm_flags_clear(dest_vma, VM_MIXEDMAP);
		vm_flags_set(dest_vma, VM_PFNMAP | VM_IO |
				       VM_DONTEXPAND | VM_DONTDUMP);
		if (!src_is_shared)
			vm_flags_set(dest_vma, VM_SHARED | VM_MAYSHARE);

		err = 0;
		for (unsigned long i = 0; i < npages; i++) {
			unsigned long pfn = page_to_pfn(pages[i]);

			err = remap_pfn_range(dest_vma,
				      new_start + (i * PAGE_SIZE),
				      pfn, PAGE_SIZE,
				      dest_vma->vm_page_prot);
			if (err)
				break;
		}
		mmap_write_unlock(dest_mm);

		if (err) {
			for (long i = 0; i < pinned; i++)
				put_page(pages[i]);
			kvfree(pages);
			(void)vm_munmap(new_start, len);
			failed_vmas++;
			log_vma_failure("remap_pfn_range", vma, start, len, err);
			continue;
		}

		err = session_add_pinned_pages(session, pages, npages);
		kvfree(pages);
		if (err) {
			(void)vm_munmap(new_start, len);
			mmap_read_unlock(target_mm);
			return err;
		}

		mapped_vmas++;
	}
	mmap_read_unlock(target_mm);

	pr_info("map: mapped_vmas=%zu skipped_vmas=%zu failed_vmas=%zu target_mm=%p dest_pid=%d\n",
		mapped_vmas, skipped_vmas, failed_vmas, target_mm, task_pid_nr(current));

	return mapped_vmas ? 0 : -EINVAL;
}

static int map_target_pid_into_current(struct map_session *session,
				       pid_t target_pid,
				       const struct map_selector *selector,
				       bool ondemand)
{
	struct task_struct *target_task;
	struct mm_struct *target_mm;
	int ret = 0;

	if (!map_caller_allowed())
		return -EPERM;
	if (map_is_self_target(target_pid)) {
		pr_info("map: reject self-target map pid=%d\n", target_pid);
		return -EINVAL;
	}

	target_task = get_pid_task(find_vpid(target_pid), PIDTYPE_PID);
	if (!target_task)
		return -ESRCH;

	target_mm = get_task_mm(target_task);
	if (!target_mm)
		goto out_put_task;

	ret = map_target_mm_into_current(session, target_mm, selector, ondemand);
	mmput(target_mm);
out_put_task:
	put_task_struct(target_task);
	return ret;
}

static int map_bound_addr_into_current(struct map_session *session,
				       unsigned long addr,
				       bool ondemand)
{
	struct map_selector selector = {
		.mode = MAP_SELECT_ADDR_RANGE,
		.addr_start = addr,
		.addr_end = addr + 1,
	};

	if (!session || !session->bound_mm)
		return -EINVAL;
	if (addr == ULONG_MAX)
		return -ERANGE;

	return map_target_mm_into_current(session, session->bound_mm, &selector,
					  ondemand);
}

static int map_dev_open(struct inode *inode, struct file *file)
{
	struct map_session *s;

	if (!map_caller_allowed())
		return -EPERM;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	mutex_init(&s->lock);
	s->dying = false;
	s->owner_mm = current->mm;
	if (s->owner_mm)
		mmget(s->owner_mm);
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
		session_cleanup_current(s);
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
		session_cleanup_current(s);
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

	mutex_lock(&map_mutex);
	session_cleanup_current(s);
	session_clear_bound_target(s);
	mutex_unlock(&map_mutex);

	if (s && s->owner_mm)
		mmput(s->owner_mm);
	kfree(s);
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

static int __init map_init(void)
{
	int ret;

	ret = misc_register(&map_miscdev);
	if (ret)
		return ret;

	pr_info("map: loaded, created /dev/%s (mode 0600)\n", map_miscdev.name);
	return 0;
}

static void __exit map_exit(void)
{
	misc_deregister(&map_miscdev);
	pr_info("map: unloaded\n");
}

module_init(map_init);
module_exit(map_exit);
