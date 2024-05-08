#define MAX_PROCS 1024
#define TASK_COMM_LEN 16

struct process {
	int pid;
	int ppid;
	char cmd[TASK_COMM_LEN];
};
