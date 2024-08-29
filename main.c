#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/mm_types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A kernel module to print VMAs of a target process");
MODULE_VERSION("0.1");

static int target_pid = 1234;  // Set the target PID here
module_param(target_pid, int, 0);
MODULE_PARM_DESC(target_pid, "Target process ID");

static int __init vma_printer_init(void)
{
    struct task_struct *task;
    struct vm_area_struct *vma;
    struct mm_struct *mm;

    printk(KERN_INFO "VMA Printer Module Loaded\n");
    printk(KERN_INFO "Looking for VMAs of process with PID: %d\n", target_pid);

    // Find the task_struct of the target process
    for_each_process(task) {
        if (task->pid == target_pid) {
            printk(KERN_INFO "Found target process: %s (PID: %d)\n", task->comm, task->pid);

            mm = task->mm;
	    VMA_ITERATOR(iter, mm, 0);  // Ini
            // Lock the memory map
            down_read(&mm->mmap_lock);

            // Initialize the iterator with the mm_struct and start address
            vma_iter_init(&iter, mm, 0);

            // Iterate through each VMA using for_each_vma
            for_each_vma(iter, vma) {
                printk(KERN_INFO "VMA: Start = 0x%lx, End = 0x%lx\n",
                       vma->vm_start, vma->vm_end);
            }

            // Unlock the memory map
            up_read(&mm->mmap_lock);
            break;
        }
    }

    if (!task || task->pid != target_pid) {
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
