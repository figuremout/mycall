#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mycall.h"

int num_procs = 0;
struct process procs[MAX_PROCS];
int specific_pid = -1;
int MYCALL_NUM = -1;

#ifdef PSTREE
void print_child(int ppid, int level)
{
	for (int i = 0; i < num_procs; i++) {
		if (procs[i].ppid == ppid && procs[i].pid != 0) {
			for (int j = 0; j < level; j++) {
				if (j != 0)
					printf("|");
				printf("\t");
			}
			printf("|-%s(%d)\n", procs[i].cmd, procs[i].pid);
			print_child(procs[i].pid, level + 1);
		}
	}
}

void print_tree(int root)
{
	for (int i = 0; i < num_procs; i++) {
		if (procs[i].pid == root) {
			printf("%s(%d)\n", procs[i].cmd, procs[i].pid);
			print_child(root, 1);
			break;
		}
	}
}
#endif

void usage()
{
	printf("ps/pstree - Minimal version of ps command relying on self-defined syscall.\n");
	printf("Usage:\n");
	printf("\tps/pstree [-h] [-p pid] [-n MYCALL_NUM]\n");
	printf("Options:\n");
	printf("\t-h Print help and exit.\n");
	printf("\t-p Select by pid.\n");
	printf("\t-n Specify the syscall number.\n");

	return;
}

int main(int argc, char *argv[])
{
	// read flags
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) { // -p flag
			specific_pid = atoi(argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-n") == 0 &&
			   i + 1 < argc) { // -n flag
			MYCALL_NUM = atoi(argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-h") == 0) { // -h flag
			usage();
			exit(0);
		}
	}

	// read MYCALL_NUM from module param
	if (MYCALL_NUM == -1) {
		FILE *fp;
		char buf[10];

		fp = fopen("/sys/module/mymod/parameters/MYCALL_NUM", "r");
		if (fp == NULL) {
			perror("open");
			exit(1);
		}

		if (fgets(buf, sizeof(buf), fp) == NULL) {
			perror("read");
			fclose(fp);
			exit(1);
		}

		fclose(fp);

		MYCALL_NUM = atoi(buf);
	}

	if (MYCALL_NUM <= 0) {
		fprintf(stderr, "Invalid or no MYCALL_NUM provided.\n");
		usage();
		exit(EXIT_FAILURE);
	}

	int ret = syscall(MYCALL_NUM, procs);
	if (ret < 0) {
		perror("Error: "); // print error
		usage();
		exit(EXIT_FAILURE);
	}
	num_procs = ret;

#ifdef PSTREE
	print_tree(specific_pid < 0 ? 0 : specific_pid);
#else
	printf("PID\tPPID\tCMD\n");
	if (specific_pid >= 0) {
		for (int i = 0; i < num_procs; i++) {
			if (procs[i].pid == specific_pid) {
				printf("%d\t%d\t%s\n", procs[i].pid,
				       procs[i].ppid, procs[i].cmd);
				break;
			}
		}
	} else {
		for (int i = 0; i < ret; i++) {
			printf("%d\t%d\t%s\n", procs[i].pid, procs[i].ppid,
			       procs[i].cmd);
		}
	}
#endif

	return 0;
}
