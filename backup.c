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
static struct vm_area_struct *(*orig_vm_area_alloc)(struct mm_struct *mm);
static struct page *(*orig_follow_page)(struct vm_area_struct *vma, unsigned long address, unsigned int foll_flags);




static int __init vma_printer_init(void)
{
    struct task_struct *task;
	struct mm_struct *mm, *cmm;
    struct page *page;
    long unsigned int src_addr, target_addr;

    printk(KERN_INFO "VMA Printer Module Loaded\n");
    printk(KERN_INFO "Looking for VMAs of process with PID: %d\n", target_pid);
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    orig_insert_vm_struct = (int (*)(struct mm_struct *, struct vm_area_struct *))kallsyms_lookup_name("insert_vm_struct");
	orig_vm_area_alloc = (struct vm_area_struct *(*)(struct mm_struct *))kallsyms_lookup_name("vm_area_alloc");
    orig_follow_page = (struct page *(*)(struct vm_area_struct *, unsigned long, unsigned int))kallsyms_lookup_name("follow_page");
    if (!orig_insert_vm_struct  || !orig_follow_page || !orig_vm_area_alloc) {
        printk(KERN_ERR "Failed to find __x64_sys_ptrace\n");
        return -EFAULT;
    }
	for_each_process(task) {
		if(task->pid == target_pid)  mm = task->mm;
		if(task->pid == calling_pid) cmm = task->mm;
	}

	if(mm && cmm) {
        struct vm_area_struct *vma;
        VMA_ITERATOR(iter, mm, 0);  

        vma_iter_init(&iter, mm, 0);

        unsigned long start = 0x40000000; //example base address, can be changed to pretty much anything
        down_write(&cmm->mmap_lock);
        for_each_vma(iter, vma) {
            struct vm_area_struct *new_vma = orig_vm_area_alloc(mm);
            unsigned long size = vma->vm_end - vma->vm_start;
            pr_info("0x%lx\n", vma->vm_start);
            new_vma->vm_start = start;
            new_vma->vm_end = start + size;
            new_vma->vm_mm = cmm;

            vma_set_anonymous(new_vma);
            vm_flags_init(new_vma, vma->vm_flags | VM_MIXEDMAP);
            new_vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

            // Remap new VMA to point to the existing physical memory
            
            for(src_addr = vma->vm_start, target_addr = start; src_addr < vma->vm_end; src_addr += PAGE_SIZE, target_addr += PAGE_SIZE) {
                page = orig_follow_page(vma, src_addr, FOLL_GET);
                
                if (IS_ERR(page)) {
                    pr_err("Failed to follow page at %lx\n", src_addr);
                    break;  
                } else
                if(page) {
                    int ret = vm_insert_page(new_vma, target_addr, page);
                    if(ret) pr_err("Failed to map page\n");
                    break;
                }
            }

            start+=size; //increase offset
            
            printk(KERN_INFO "VMA: Old = 0x%lx, New = 0x%lx\n", vma->vm_start, new_vma->vm_start);

            if (orig_insert_vm_struct(cmm, new_vma)) {
                pr_err("Failed to insert the new new_vma into the process memory map\n");
                kfree(new_vma);
            }
        }
        up_write(&cmm->mmap_lock);
    
    }

    return 0;
}

static void __exit vma_printer_exit(void)
{

    printk(KERN_INFO "VMA Printer Module Unloaded\n");
}

module_init(vma_printer_init);
module_exit(vma_printer_exit);