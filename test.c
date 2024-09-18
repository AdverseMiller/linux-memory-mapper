#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mman.h>
#include <linux/kthread.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A kernel module to print VMAs of a target process");
MODULE_VERSION("0.1");

static int target_pid = 1234;  // Set the target PID here
module_param(target_pid, int, 0);
MODULE_PARM_DESC(target_pid, "Target process ID");
static int calling_pid = 1234;  // Set the target PID here
module_param(calling_pid, int, 0);
MODULE_PARM_DESC(calling_pid, "Target process ID");

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

static int (*orig_insert_vm_struct)(struct mm_struct *, struct vm_area_struct *);
//static struct vm_area_struct *(*orig_vm_area_alloc)(struct mm_struct *mm);
//static unsigned long (*orig_mmap_region)(struct file *file, unsigned long addr, unsigned long len, vm_flags_t vm_flags, unsigned long pgoff, struct list_head *uf);
static unsigned long (*orig_do_mmap)(struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, vm_flags_t vm_flags,
			unsigned long pgoff, unsigned long *populate,
			struct list_head *uf);

static int __init vma_printer_init(void)
{
    struct task_struct *task;
	struct mm_struct *mm, *cmm;
    printk(KERN_INFO "VMA Printer Module Loaded\n");
    printk(KERN_INFO "Looking for VMAs of process with PID: %d\n", target_pid);
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    orig_insert_vm_struct = (int (*)(struct mm_struct *, struct vm_area_struct *))kallsyms_lookup_name("insert_vm_struct");
    //orig_mmap_region = (unsigned long (*)(struct file *file, unsigned long addr, unsigned long len, vm_flags_t vm_flags, unsigned long pgoff, struct list_head *uf))kallsyms_lookup_name("mmap_region");
	//orig_vm_area_alloc = (struct vm_area_struct *(*)(struct mm_struct *))kallsyms_lookup_name("vm_area_alloc");
    orig_do_mmap = (unsigned long (*)(struct file *file, unsigned long addr,unsigned long len, unsigned long prot,unsigned long flags, vm_flags_t vm_flags,unsigned long pgoff, unsigned long *populate,struct list_head *uf))kallsyms_lookup_name("do_mmap");
    if (!orig_insert_vm_struct || !orig_do_mmap) {
        printk(KERN_ERR "Failed to find __x64_sys_ptrace\n");
        return -EFAULT;
    }
	for_each_process(task) {
		if(task->pid == target_pid)  mm = task->mm;
		if(task->pid == calling_pid) cmm = task->mm;
	}

	if(mm && cmm) {
        

        struct vm_area_struct *vma;
        unsigned long populate = 0;
        struct list_head uf;
        INIT_LIST_HEAD(&uf);
        VMA_ITERATOR(iter, mm, 0);  // Ini
        

        vma_iter_init(&iter, mm, 0);

        unsigned long start = 0x40000000;
        kthread_use_mm(cmm);
        if (mmap_write_lock_killable(cmm)) return -EINTR;
        for_each_vma(iter, vma) {
            unsigned long size = vma->vm_end - vma->vm_start;
            
            unsigned long ret = orig_do_mmap(NULL, start, size, 
                               PROT_READ | PROT_WRITE, 
                               MAP_ANONYMOUS | MAP_PRIVATE, 
                               vma->vm_flags,
                               0, &populate, &uf);
            if (IS_ERR_VALUE(ret)) {
                pr_err("do_mmap failed: %ld\n", ret);
            } else {
                    pr_info("Successfully allocated VMA at address: %lx\n", ret);
            }
        }
              
        mmap_write_unlock(cmm);
        kthread_unuse_mm(cmm);
    
    }

    return 0;
}

static void __exit vma_printer_exit(void)
{

    printk(KERN_INFO "VMA Printer Module Unloaded\n");
}

module_init(vma_printer_init);
module_exit(vma_printer_exit);