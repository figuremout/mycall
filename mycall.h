#define MAX_PROCS 1024
#define TASK_COMM_LEN 16
#define PROC_NAME "mycall_num"

struct process {
	int pid;
	int ppid;
	char cmd[TASK_COMM_LEN];
};
