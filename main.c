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

struct map_region {
	unsigned long start;
	unsigned long len;
};

struct map_session {
	struct mm_struct *owner_mm;
	struct map_region *regions;
	size_t region_count;
	size_t region_cap;
	struct page **pinned_pages;
	size_t pinned_count;
	size_t pinned_cap;
};

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

static void session_cleanup_current(struct map_session *s)
{
	if (!s)
		return;
	if (!s->owner_mm || current->mm != s->owner_mm)
		return;

	for (size_t i = 0; i < s->region_count; i++)
		(void)vm_munmap(s->regions[i].start, s->regions[i].len);

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
}

static int map_target_mm_into_current(struct map_session *session,
				      struct task_struct *target_task,
				      struct mm_struct *target_mm)
{
	struct mm_struct *dest_mm = current->mm;
	struct vm_area_struct *vma;
	VMA_ITERATOR(iter, target_mm, 0);
	size_t mapped_vmas = 0, skipped_vmas = 0, failed_vmas = 0;

	if (!dest_mm)
		return -EINVAL;

	mmap_read_lock(target_mm);
	for_each_vma(iter, vma) {
		unsigned long start, len, prot, flags, new_start;
		unsigned long offset;
		unsigned long npages;
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

		prot = vma_prot_from_flags(vma->vm_flags);
		flags = MAP_FIXED;
		offset = vma->vm_pgoff << PAGE_SHIFT;

		if (vma->vm_file) {
			flags |= (vma->vm_flags & VM_SHARED) ? MAP_SHARED : MAP_PRIVATE;
		} else {
			flags |= MAP_ANONYMOUS | MAP_SHARED;
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

		vm_flags_set(dest_vma, VM_PFNMAP | VM_IO | VM_DONTEXPAND | VM_DONTDUMP);

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

static int map_target_pid_into_current(struct map_session *session, pid_t target_pid)
{
	struct task_struct *target_task;
	struct mm_struct *target_mm;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	target_task = get_pid_task(find_vpid(target_pid), PIDTYPE_PID);
	if (!target_task)
		return -ESRCH;

	target_mm = get_task_mm(target_task);
	if (!target_mm)
		goto out_put_task;

	ret = map_target_mm_into_current(session, target_task, target_mm);
	mmput(target_mm);
out_put_task:
	put_task_struct(target_task);
	return ret;
}

static int map_dev_open(struct inode *inode, struct file *file)
{
	struct map_session *s;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->owner_mm = current->mm;
	if (s->owner_mm)
		mmget(s->owner_mm);
	file->private_data = s;
	return 0;
}

static ssize_t map_dev_write(struct file *file, const char __user *ubuf,
			     size_t len, loff_t *ppos)
{
	char kbuf[32];
	size_t n;
	int pid;
	int ret;
	struct map_session *s = file->private_data;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!s || !s->owner_mm || current->mm != s->owner_mm)
		return -EPERM;

	n = min(len, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, ubuf, n))
		return -EFAULT;
	kbuf[n] = '\0';

	ret = kstrtoint(strim(kbuf), 10, &pid);
	if (ret)
		return ret;
	if (pid <= 0)
		return -EINVAL;

	mutex_lock(&map_mutex);
	session_cleanup_current(s);
	ret = map_target_pid_into_current(s, (pid_t)pid);
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
	.mode = 0600,
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
