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
#include <linux/kthread.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VMA mapper");
MODULE_VERSION("0.1");

static int target_pid = 1234;  // Set the target PID here
module_param(target_pid, int, 0);
MODULE_PARM_DESC(target_pid, "Target process ID");
static int calling_pid = 1234;  // Set the target PID here
module_param(calling_pid, int, 0);
MODULE_PARM_DESC(calling_pid, "Target process ID");


static int __init vma_printer_init(void)
{
    	struct task_struct *task;
	struct mm_struct *mm, *cmm;
    	struct page *page;

    	printk(KERN_INFO "VMA Printer Module Loaded\n");
    	printk(KERN_INFO "Looking for VMAs of process with PID: %d\n", target_pid);
	for_each_process(task) {
		if(task->pid == target_pid)  mm = task->mm;
		if(task->pid == calling_pid) cmm = task->mm;
	}
	if (mm && cmm) {
	    	struct vm_area_struct *vma;
		struct mm_struct *old_mm;
	    	VMA_ITERATOR(iter, mm, 0);
	
	    
	    	down_read (&mm->mmap_lock);
	
		for_each_vma(iter, vma) {
		        unsigned long start  = vma->vm_start;
		        unsigned long len    = vma->vm_end   - start;
		        unsigned long prot   = 0;
		        unsigned long flags  = MAP_FIXED;
		        unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
		        unsigned long new_start;
		
		        if (vma->vm_flags & VM_READ)  prot |= PROT_READ;
		        if (vma->vm_flags & VM_WRITE) prot |= PROT_WRITE;
		        if (vma->vm_flags & VM_EXEC)  prot |= PROT_EXEC;
		
			if (vma->vm_file) {
		        	flags |= (vma->vm_flags & VM_SHARED) ? MAP_SHARED : MAP_PRIVATE;
			} else flags |= MAP_ANONYMOUS | MAP_SHARED;
		    	
		
		
		        //switch into calling process' address space and mmap a new VMA
			old_mm = current->mm;
		        current->mm   = cmm;
			new_start     = vm_mmap(vma->vm_file,  start, len, prot, flags, offset);
			current->mm = old_mm;
		        if (IS_ERR_VALUE(new_start)) pr_err("vma_printer: vm_mmap failed @%lx len=%lu: %ld\n", start, len, new_start);
		        else pr_info("vma_printer: mapped %lx–%lx\n", new_start, new_start + len);
			down_read(&cmm->mmap_lock);
			struct vm_area_struct *new_vma = find_vma(cmm, new_start);
			up_read(&cmm->mmap_lock);
		
		      	//do not remap file-backed regions
			if (!vma->vm_file && new_vma) {
				long got = get_user_pages_remote(mm, vma->vm_start, 1, FOLL_GET, &page, NULL);
		        	if (got <= 0) {
		        		pr_err("pin failed @%lx: %ld\n", vma->vm_start, got);
		        		continue;
		        	}
				down_write(&cmm->mmap_lock);
				got = remap_pfn_range(new_vma, new_vma->vm_start, page_to_pfn(page), vma->vm_end - vma->vm_start, new_vma->vm_page_prot);
		        	if(got < 0) pr_err("remap failed: %ld\n", got);
				put_page(page);
				up_write(&cmm->mmap_lock);
			}
		}
	
	    up_read(&mm->mmap_lock);
	}

    return 0;
}

static void __exit vma_printer_exit(void)
{

    printk(KERN_INFO "VMA Printer Module Unloaded\n");
}

module_init(vma_printer_init);
module_exit(vma_printer_exit);
