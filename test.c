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
#include <linux/pagemap.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VMA mapper");
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
static struct vm_area_struct *(*orig_vm_area_alloc)(struct mm_struct *mm);


static int __init vma_printer_init(void)
{
    struct task_struct *task;
    struct mm_struct *mm = NULL, *cmm = NULL;
    struct task_struct *target = NULL;  /* Pointer to the target process's task */
    struct page *page;
    unsigned long src_addr, target_addr;
    unsigned long pfn;
    int ret_pages, locked = 0;

    printk(KERN_INFO "VMA Printer Module Loaded\n");
    printk(KERN_INFO "Looking for VMAs of process with PID: %d\n", target_pid);

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    orig_insert_vm_struct = (int (*)(struct mm_struct *, struct vm_area_struct *))
        kallsyms_lookup_name("insert_vm_struct");
    orig_vm_area_alloc = (struct vm_area_struct *(*)(struct mm_struct *))
        kallsyms_lookup_name("vm_area_alloc");

    if (!orig_insert_vm_struct  ||  !orig_vm_area_alloc) {
        printk(KERN_ERR "Failed to resolve all functions\n");
        return -EFAULT;
    }

    /* Locate the target and calling processes */
    for_each_process(task) {
        if (task->pid == target_pid) {
            mm = task->mm;
            target = task;  /* Save pointer to target task */
        }
        if (task->pid == calling_pid) {
            cmm = task->mm;
        }
    }

    if (mm && cmm && target) {
        struct vm_area_struct *vma;
        struct vm_area_struct *new_vma;
        unsigned long size, start;
        VMA_ITERATOR(iter, mm, 0);

        vma_iter_init(&iter, mm, 0);

        /* For demonstration, take a fixed offset for the new mapping */
        down_write(&cmm->mmap_lock);
        for_each_vma(iter, vma) {
            new_vma = orig_vm_area_alloc(mm);
            size = vma->vm_end - vma->vm_start;
            start = vma->vm_start + 0x1000000;
            new_vma->vm_start = start;
            new_vma->vm_end = start + size;
            new_vma->vm_mm = cmm;
            new_vma->vm_pgoff = vma->vm_pgoff;
            new_vma->vm_ops = vma->vm_ops;

            if (vma->vm_file) { /* File-backed VMA */
                get_file(vma->vm_file);
                new_vma->vm_file = vma->vm_file;
                new_vma->vm_private_data = vma->vm_private_data;
            } else vma_set_anonymous(new_vma);

	   	unsigned long new_flags = vma->vm_flags;
                new_flags &= ~(VM_MAYWRITE);
                new_flags |= (VM_SHARED | VM_MIXEDMAP | VM_MAYREAD); /* to make remap_pfn_range happy */
		vm_flags_init(new_vma, new_flags);
		
		new_vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
		

            /* Remap the target's pages into the new VMA, one page at a time */
	    down_read(&mm->mmap_lock);
            for (src_addr = vma->vm_start, target_addr = start;
                 src_addr < vma->vm_end;
                 src_addr += PAGE_SIZE, target_addr += PAGE_SIZE) {


		ret_pages = get_user_pages_remote(mm, src_addr, 1, FOLL_GET, &page, &locked);


                if (ret_pages != 1) {
                    pr_err("Failed to get page at 0x%lx\n", src_addr);
                    break;
                }
                pfn = page_to_pfn(page);
                ret_pages = remap_pfn_range(new_vma, target_addr, pfn,
                                            PAGE_SIZE, vma->vm_page_prot);
                if (ret_pages) {
                    pr_err("remap_pfn_range failed at 0x%lx, bailing out of this VMA...\n", target_addr);
                    put_page(page);
                    break;
                }
                put_page(page);
            }
	    up_read(&mm->mmap_lock);
            printk(KERN_INFO "VMA: Old = 0x%lx, New = 0x%lx\n", vma->vm_start, new_vma->vm_start);

            if (orig_insert_vm_struct(cmm, new_vma)) {
                pr_err("Failed to insert the new VMA into the process memory map\n");
                kfree(new_vma);
            }
        }
        up_write(&cmm->mmap_lock);
    } else {
        pr_err("Could not find both target and calling processes or their mm_structs\n");
        return -ESRCH;
    }

    return 0;
}

static void __exit vma_printer_exit(void)
{

    printk(KERN_INFO "VMA Printer Module Unloaded\n");
}

module_init(vma_printer_init);
module_exit(vma_printer_exit);
