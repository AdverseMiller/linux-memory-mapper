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
MODULE_PARM_DESC(calling_pid, "Calling process ID");

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

static int (*orig_insert_vm_struct)(struct mm_struct *, struct vm_area_struct *);
static unsigned long (*orig_mmap_region)(struct file *file, unsigned long addr, unsigned long len, vm_flags_t vm_flags, unsigned long pgoff, struct list_head *uf);

unsigned long start = 0x40000000;
unsigned long size = 2 * PAGE_SIZE;

static int __init vma_printer_init(void)
{
    struct task_struct *task;
    //struct vm_area_struct *vma;
    struct mm_struct *cmm;
    
    printk(KERN_INFO "VMA Printer Module Loaded\n");
    printk(KERN_INFO "Looking for VMAs of process with PID: %d\n", target_pid);
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    orig_insert_vm_struct = (int (*)(struct mm_struct *, struct vm_area_struct *))kallsyms_lookup_name("insert_vm_struct");
    orig_mmap_region = (unsigned long (*)(struct file *file, unsigned long addr, unsigned long len, vm_flags_t vm_flags, unsigned long pgoff, struct list_head *uf))kallsyms_lookup_name("mmap_region");
    if (!orig_insert_vm_struct) {
        printk(KERN_ERR "Failed to find __x64_sys_ptrace\n");
        return -EFAULT;
    }

    for_each_process(task) {
        if(task->pid == calling_pid) {
            struct mm_struct *mm = current->mm;   
            down_write(&mm->mmap_lock);
            int ret = orig_mmap_region(NULL, start, 2* PAGE_SIZE, VM_READ | VM_WRITE | VM_EXEC | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0);
            
            if (IS_ERR((void *)ret)) {
                pr_err("Failed to map the new VMA\n");
                up_write(&mm->mmap_lock); // Release the semaphore on failure
                return PTR_ERR((void *)ret);
            }
            struct vm_area_struct * new_vma; 

            new_vma = find_vma(mm, start);
            if (!new_vma || new_vma->vm_start != start || new_vma->vm_end != start + size) {
                pr_err("VMA not found or incorrect range\n");
                up_write(&mm->mmap_lock); // Release the semaphore
                return -EINVAL;
            }

            cmm = task->mm;
            down_write(&cmm->mmap_lock);
            if (orig_insert_vm_struct(cmm, new_vma)) {
                pr_err("Failed to insert the new VMA into the process memory map\n");
                kfree(new_vma);
            }
            cmm->map_count++;
            up_write(&cmm->mmap_lock);
            up_write(&mm->mmap_lock);

        
        }
    }

    if (!task) {
        printk(KERN_INFO "Target process with PID %d not found.\n", target_pid);
    }

    return 0;
}

static void __exit vma_printer_exit(void)
{

    printk(KERN_INFO "VMA Printer Module Unloaded\n");
}

module_init(vma_printer_init);
module_exit(vma_printer_exit);
