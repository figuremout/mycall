/*
 * Tested on Linux x86-64 v5.15.0
 */
#include <linux/list.h>
#include <linux/kprobes.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/version.h>
#include "mycall.h"

static int MYCALL_NUM;
static long (*anything_saved)(void); // preserve the original syscall
unsigned long *sys_call_table_addr;

// Find the address of sys_call_table address through kprobes
static struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_my;

/*
 * Retrieve process info
 */
void dfs_procs(struct task_struct *p_task, struct process *procs,
	       int *procs_num)
{
	struct task_struct *child;

	// check if reach max
	if (*procs_num >= MAX_PROCS)
		return;

	procs[*procs_num].pid = p_task->pid;
	procs[*procs_num].ppid = p_task->parent->pid;
	strncpy(procs[*procs_num].cmd, p_task->comm,
		sizeof(procs[*procs_num].cmd));

	*procs_num += 1;

	// iterate over children
	list_for_each_entry(child, &p_task->children, sibling) {
		dfs_procs(child, procs, procs_num);
	}
	return;
}

/*
 * Define a new syscall
 * Return number of procs
 */
asmlinkage long sys_mycall(struct pt_regs *regs)
{
	char __user *buf;
	unsigned long not_copied;
	struct process *procs;
	int procs_num;

	pr_info("Called mysyscall\n");

	buf = (char __user *)regs->di;

	procs_num = 0;
	procs = (struct process *)kmalloc(MAX_PROCS * sizeof(struct process),
					  GFP_KERNEL);
	if (!procs) {
		pr_err("Failed to allocate memory.\n");
		return -ENOMEM;
	}
	dfs_procs(&init_task, procs, &procs_num);

	not_copied = copy_to_user((struct process *)buf, procs,
				  procs_num * sizeof(struct process));
	if (not_copied != 0) {
		pr_err("Failed to copy %lu bytes to user space.\n", not_copied);
		return -EFAULT; // Bad address
	}
	kfree(procs);

	return procs_num;
}

/*
 * Disable cr0 WP, return origin value of cr0
 */
static unsigned long clear_cr0(void)
{
	unsigned long cr0 = 0;
	unsigned long ret;
	asm volatile(
		"movq %%cr0, %%rax"
		: "=a"(cr0)); // move reg cr0 to reg rax, and store into variable cr0
	ret = cr0;
	cr0 &= ~X86_CR0_WP; // clear WP of variable cr0
	asm volatile("movq %%rax, %%cr0" ::"a"(
		cr0)); // store variable cr0 into reg rax, and move reg rax to reg cr0
	return ret;
}

/*
 * restore cr0
 */
static void setback_cr0(unsigned long val)
{
	asm volatile("movq %%rax, %%cr0" ::"a"(
		val)); // store variable val into reg rax, and move reg rax to reg cr0
}

void insert_syscall(void)
{
	unsigned long origin_cr0;
	origin_cr0 = read_cr0();
	sys_call_table_addr =
		(unsigned long *)kallsyms_lookup_name_my("sys_call_table");
	anything_saved = (long (*)(void))(sys_call_table_addr[MYCALL_NUM]);
	origin_cr0 = clear_cr0();
	sys_call_table_addr[MYCALL_NUM] = (unsigned long)&sys_mycall;
	setback_cr0(origin_cr0);
}

void remove_syscall(void)
{
	unsigned long origin_cr0;
	origin_cr0 = clear_cr0();
	sys_call_table_addr[MYCALL_NUM] = (unsigned long)anything_saved;
	setback_cr0(origin_cr0);
}

static int __init mymod_init(void)
{
	if (MYCALL_NUM == 0) {
		pr_err("Invalid MYCALL_NUM.\nUsage: `sudo insmod MYCALL_NUM=<num>`\n");
		return -EINVAL; // Invalid argument
	}

	pr_info("Module loaded, MYCALL_NUM=%d\n", MYCALL_NUM);

	register_kprobe(&kp);
	kallsyms_lookup_name_my = (kallsyms_lookup_name_t)kp.addr;

	insert_syscall();
	pr_info("Syscall %d inserted.\n", MYCALL_NUM);

	return 0;
}

static void __exit mymod_exit(void)
{
	remove_syscall();

	unregister_kprobe(&kp);
	pr_info("Goodbye!\n");
}

module_param(MYCALL_NUM, int, S_IRUGO); // perm: 0444 readable
module_init(mymod_init);
module_exit(mymod_exit);

MODULE_PARM_DESC(MYCALL_NUM, "Number of my syscall");
MODULE_LICENSE("GPL");
